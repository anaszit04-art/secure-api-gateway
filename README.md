# Secure API Gateway

API Gateway sécurisée développée avec FastAPI, JWT, Redis,
PostgreSQL, SQLAlchemy, Alembic et Docker.

Le projet centralise l'authentification, la persistance des
utilisateurs, la limitation de débit, la protection
anti-brute-force et le routage vers des microservices internes.

## État du projet

Phase 4 terminée :

- authentification JWT ;
- persistance PostgreSQL des utilisateurs ;
- accès asynchrone SQLAlchemy + asyncpg ;
- migrations Alembic ;
- reverse proxy authentifié ;
- rate limiting Redis distribué ;
- protection anti-brute-force ;
- verrouillage temporaire des comptes ;
- limitation des connexions par adresse IP ;
- stratégie fail-closed Redis et PostgreSQL ;
- persistance validée après reconstruction des conteneurs ;
- durcissement Docker ;
- 298 tests automatisés réussis.

## Architecture

    Client HTTP
         |
         | 127.0.0.1:8000
         v
    FastAPI Gateway
      |
      +-- JWT
      |
      +-- AuthenticationService async
      |       |
      |       v
      |   UserRepository
      |       |
      |       v
      |   PostgreSQLUserRepository
      |       |
      |       v
      |   SQLAlchemy AsyncSession
      |       |
      |       v
      |     asyncpg
      |       |
      |       v
      |   PostgreSQL
      |
      +-- Redis
      |    |
      |    +-- Rate limiting
      |    |
      |    +-- Anti-brute-force
      |
      +-- Reverse proxy
           |
           +-- Service A
           |
           +-- Service B

Seule la Gateway est publiée sur la machine hôte :

    127.0.0.1:8000

PostgreSQL, Redis et les microservices restent uniquement
accessibles depuis le réseau Docker interne.

Les migrations SQL sont gérées par Alembic :

    Alembic
       |
       v
    1cc279e452ed
       |
       v
    users

## Structure du projet

    gateway/
    └── app/
        ├── auth/
        ├── database/
        ├── proxy/
        ├── rate_limit/
        └── main.py

    migrations/
    └── versions/

    microservices/
    ├── service_a/
    └── service_b/

    tests/

    alembic.ini
    compose.yaml
    Dockerfile
    requirements.txt
    requirements-runtime.txt

## Fonctionnalités

### Authentification

- inscription locale ;
- normalisation des noms d'utilisateur ;
- hachage Argon2 des mots de passe ;
- stockage persistant des hashes dans PostgreSQL ;
- jetons JWT HS256 ;
- validation de l'émetteur et de l'audience ;
- durée configurable des jetons ;
- message générique pour les identifiants incorrects ;
- vérification Argon2 factice pour les utilisateurs inconnus ;
- renouvellement automatique d'un hash devenu obsolète ;
- aucune exposition du mot de passe ou du hash dans les réponses API.

### Persistance PostgreSQL

Les utilisateurs sont stockés dans PostgreSQL via :

    AuthenticationService
        |
        v
    UserRepository async
        |
        v
    PostgreSQLUserRepository
        |
        v
    SQLAlchemy AsyncSession
        |
        v
    asyncpg
        |
        v
    PostgreSQL

Le modèle `users` contient notamment :

- UUID ;
- username normalisé ;
- hash du mot de passe ;
- état actif/inactif ;
- date de création ;
- date de mise à jour.

La contrainte d'unicité du nom d'utilisateur est également
garantie au niveau PostgreSQL.

Les inscriptions concurrentes d'un même utilisateur ont été
validées :

    1 x HTTP 201
    9 x HTTP 409
    1 seule ligne PostgreSQL

### Migrations Alembic

La migration initiale est :

    1cc279e452ed

Elle crée la table `users`.

Appliquer les migrations :

    docker compose \
      --profile tools \
      run \
      --rm \
      migrate \
      alembic upgrade head

Afficher la migration courante :

    docker compose \
      --profile tools \
      run \
      --rm \
      migrate \
      alembic current

Afficher les heads :

    docker compose \
      --profile tools \
      run \
      --rm \
      migrate \
      alembic heads

Détecter une dérive ORM / migration :

    docker compose \
      --profile tools \
      run \
      --rm \
      migrate \
      alembic check

État validé :

    1cc279e452ed (head)

    No new upgrade operations detected.

### Résilience PostgreSQL

Les erreurs SQLAlchemy ou asyncpg sont interceptées à la
frontière du repository.

Une panne PostgreSQL n'est jamais interprétée comme un mauvais
mot de passe.

Lorsque PostgreSQL devient indisponible :

    /auth/register      -> HTTP 503
    /auth/token         -> HTTP 503
    /auth/me            -> HTTP 503
    /api/* protégé      -> HTTP 503

La réponse utilise :

    Retry-After: 1

Le message retourné reste générique et ne révèle aucune
information SQL interne.

La route :

    GET /health

reste disponible avec HTTP 200 car elle représente actuellement
la liveness de la Gateway.

Après redémarrage de PostgreSQL, le pool SQLAlchemy récupère
automatiquement les connexions grâce notamment à
`pool_pre_ping`.

### Persistance après redémarrage

La persistance a été testée avec la procédure suivante :

    création utilisateur
          |
          v
    PostgreSQL
          |
          v
    destruction Gateway
          |
          v
    recréation Gateway
          |
          v
    même utilisateur disponible

Un test plus strict a également détruit tout le stack Docker
sans supprimer le volume :

    docker compose down

Le volume :

    secure-api-gateway_postgres-data

a été conservé.

Après reconstruction complète du stack :

- le même UUID utilisateur était présent ;
- l'ancien JWT restait valide ;
- une nouvelle authentification réussissait ;
- le reverse proxy authentifié fonctionnait toujours.

### Reverse proxy

Les routes `/api/*` nécessitent un JWT valide et un utilisateur
actif chargé depuis PostgreSQL.

La Gateway transfère les requêtes vers les services enregistrés
tout en filtrant les headers sensibles.

Services disponibles :

- `service-a` ;
- `service-b`.

Les routes génériques du proxy sont volontairement exclues du
schéma OpenAPI.

### Rate limiting Redis

Le rate limiting utilise un Token Bucket atomique exécuté avec
un script Lua Redis.

Politique du proxy authentifié :

- capacité : 60 requêtes ;
- recharge : 1 jeton par seconde ;
- coût : 1 jeton par requête ;
- identité : UUID utilisateur haché en SHA-256.

Headers retournés :

- `X-RateLimit-Limit` ;
- `X-RateLimit-Remaining` ;
- `X-RateLimit-Reset` ;
- `Retry-After` en cas de blocage.

### Protection anti-brute-force

Politique par adresse IP :

- capacité : 10 tentatives ;
- recharge : 0,2 tentative par seconde ;
- utilisation de l'adresse réseau directe ;
- `X-Forwarded-For` ignoré tant qu'aucun proxy fiable
  n'est configuré.

Politique par compte :

- seuil : 5 échecs ;
- fenêtre : 900 secondes ;
- verrouillage : 300 secondes ;
- suppression du compteur après connexion réussie ;
- identifiant normalisé puis haché en SHA-256.

Validation observée :

    tentative 1 -> 401
    tentative 2 -> 401
    tentative 3 -> 401
    tentative 4 -> 401
    tentative 5 -> 429
    tentative 6 -> 429

Les noms d'utilisateur ne sont pas stockés en clair dans les
clés Redis.

Lorsque Redis est indisponible, les routes protégées utilisent
également une stratégie fail-closed et retournent HTTP 503.

## Séparation PostgreSQL / Redis

PostgreSQL conserve les données durables :

- utilisateurs ;
- hashes de mots de passe ;
- états de compte ;
- timestamps.

Redis conserve uniquement les états temporaires de sécurité :

- Token Bucket ;
- compteurs d'échecs ;
- verrouillages temporaires ;
- rate limiting.

Un `FLUSHDB` Redis ne supprime donc aucun utilisateur.

## Durcissement Docker

### Gateway et microservices Python

Les conteneurs Python utilisent notamment :

- utilisateur non-root ;
- système de fichiers en lecture seule ;
- `no-new-privileges:true` ;
- `cap_drop: ALL` ;
- `/tmp` en `tmpfs` ;
- réseau Docker interne.

### Redis

Redis utilise notamment :

- utilisateur `redis` ;
- système de fichiers en lecture seule ;
- `no-new-privileges:true` ;
- `cap_drop: ALL` ;
- `/data` en `tmpfs` ;
- aucun port publié sur l'hôte.

Redis ne conserve volontairement aucune donnée métier durable.

### PostgreSQL

PostgreSQL utilise :

- l'image `postgres:18.4-alpine` ;
- `no-new-privileges:true` ;
- un réseau Docker interne ;
- aucun port publié sur l'hôte ;
- un volume Docker nommé persistant ;
- une authentification SCRAM pour les connexions réseau.

Le port `5432` est uniquement exposé à l'intérieur du réseau
Docker.

### Exposition réseau

Seule la Gateway est publiée :

    127.0.0.1:8000 -> 8000

PostgreSQL :

    5432/tcp

sans publication hôte.

Redis :

    6379/tcp

sans publication hôte.

## Prérequis

- Python 3.13 ;
- Docker ;
- Docker Compose ;
- Git.

## Configuration

Créer le fichier local :

    cp .env.example .env

Le fichier `.env` :

- contient des secrets locaux ;
- ne doit jamais être versionné ;
- est ignoré par Git.

Ne jamais afficher son contenu dans des logs ou des captures.

Variables JWT :

| Variable | Description | Défaut |
|---|---|---|
| `JWT_SECRET_KEY` | Secret de signature, minimum 32 caractères | obligatoire |
| `JWT_ALGORITHM` | Algorithme JWT | `HS256` |
| `JWT_ACCESS_TOKEN_MINUTES` | Durée du jeton | `15` |
| `JWT_ISSUER` | Émetteur | `secure-api-gateway` |
| `JWT_AUDIENCE` | Audience | `secure-api-clients` |

Variables Redis :

| Variable | Description | Défaut |
|---|---|---|
| `REDIS_URL` | URL Redis | `redis://redis:6379/0` |
| `REDIS_KEY_PREFIX` | Préfixe des clés | `secure-api-gateway` |
| `REDIS_CONNECT_TIMEOUT_SECONDS` | Timeout connexion | `2` |
| `REDIS_SOCKET_TIMEOUT_SECONDS` | Timeout opérations | `2` |
| `REDIS_MAX_CONNECTIONS` | Taille maximale du pool | `20` |
| `REDIS_VERIFY_ON_STARTUP` | Vérification au démarrage Docker | `true` |

Variables PostgreSQL :

| Variable | Description | Défaut |
|---|---|---|
| `POSTGRES_DB` | Base PostgreSQL | `gateway` |
| `POSTGRES_USER` | Utilisateur PostgreSQL | `gateway` |
| `POSTGRES_PASSWORD` | Mot de passe PostgreSQL | obligatoire |
| `DATABASE_POOL_SIZE` | Taille du pool SQLAlchemy | `5` |
| `DATABASE_MAX_OVERFLOW` | Connexions supplémentaires | `10` |
| `DATABASE_POOL_TIMEOUT_SECONDS` | Timeout du pool | `5` |
| `DATABASE_CONNECT_TIMEOUT_SECONDS` | Timeout de connexion | `5` |
| `DATABASE_VERIFY_ON_STARTUP` | Test DB au démarrage | Docker : `true` |
| `DATABASE_APPLICATION_NAME` | Nom PostgreSQL de l'application | `secure-api-gateway` |

## Démarrage

Démarrer le stack :

    docker compose up --build -d

Vérifier :

    docker compose ps

Les cinq services doivent être healthy :

- `gateway` ;
- `postgres` ;
- `redis` ;
- `service-a` ;
- `service-b`.

Consulter les logs :

    docker compose logs \
      --tail=100 \
      gateway postgres redis

Arrêter l'environnement sans supprimer les données PostgreSQL :

    docker compose down

Attention :

    docker compose down -v

supprime également le volume PostgreSQL et ne doit être utilisé
que lorsqu'une suppression volontaire des données est souhaitée.

## Endpoints

### Santé

    GET /health

### Inscription

    POST /auth/register
    Content-Type: application/json

### Authentification

    POST /auth/token
    Content-Type: application/x-www-form-urlencoded

### Profil courant

    GET /auth/me
    Authorization: Bearer <token>

### Reverse proxy

    ANY /api/{service_name}
    ANY /api/{service_name}/{path}
    Authorization: Bearer <token>

## Documentation interactive

Lorsque la Gateway fonctionne :

- Swagger UI : `http://127.0.0.1:8000/docs`
- ReDoc : `http://127.0.0.1:8000/redoc`
- OpenAPI : `http://127.0.0.1:8000/openapi.json`

Le schéma OpenAPI expose les routes explicites
d'authentification et de santé.

Les routes proxy génériques sont exclues volontairement.

## Tests

Créer l'environnement Python :

    python -m venv venv
    source venv/bin/activate

Installer :

    python -m pip install \
      --requirement requirements.txt

Exécuter :

    python -m pytest -q

État validé de la Phase 4 :

    298 passed, 1 warning

Le warning restant provient de l'intégration actuelle entre
Starlette TestClient et httpx et n'indique pas un échec
fonctionnel du projet.

## Contrôles utiles

Validation Docker Compose sans révéler les secrets :

    docker compose config --quiet

Ne pas utiliser `docker compose config` dans des captures ou
logs publics car les variables peuvent être résolues.

Contrôle Git :

    git diff --check
    git status --short

Vérifier que `.env` est ignoré :

    git check-ignore -v .env

Contrôler les migrations :

    docker compose \
      --profile tools \
      run \
      --rm \
      migrate \
      alembic check

Inspection des clés Redis :

    docker compose exec -T redis \
      redis-cli --scan \
      --pattern 'secure-api-gateway:*'

Les noms d'utilisateur, UUID et adresses IP ne doivent pas
apparaître en clair dans les clés Redis.

## Limites actuelles

- `/health` représente actuellement uniquement la liveness ;
- aucune route de readiness complète n'est encore exposée ;
- Redis ne possède volontairement aucune persistance disque ;
- le contrôle d'accès fin RBAC n'est pas encore implémenté ;
- les événements d'audit persistants feront partie d'une phase
  ultérieure ;
- le déploiement CI/CD n'est pas encore finalisé.

## Licence

Projet pédagogique de démonstration d'une API Gateway sécurisée.
