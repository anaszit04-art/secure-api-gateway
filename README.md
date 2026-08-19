# Secure API Gateway

API Gateway sécurisée développée avec FastAPI, JWT, Redis,
PostgreSQL, SQLAlchemy, Alembic et Docker.

Le projet centralise l'authentification, l'autorisation RBAC,
la persistance des utilisateurs, la limitation de débit, la
protection anti-brute-force et le routage Zero Trust vers des
microservices internes.

Version applicative validée :

    0.5.0

Image applicative Docker :

    secure-api-gateway:phase5

## État du projet

Phase 5 terminée techniquement :

- authentification JWT ;
- persistance PostgreSQL des utilisateurs ;
- accès asynchrone SQLAlchemy + asyncpg ;
- migrations Alembic ;
- autorisation RBAC persistante PostgreSQL ;
- rôles `user`, `operator` et `admin` ;
- permissions fines par service et méthode HTTP ;
- stratégie Zero Trust sur le reverse proxy ;
- administration sécurisée des rôles ;
- révocation de privilège effective avec le même JWT ;
- protection contre le spoofing de rôles et permissions ;
- rate limiting Redis distribué ;
- protection anti-brute-force ;
- verrouillage temporaire des comptes ;
- limitation des connexions par adresse IP ;
- stratégie fail-closed Redis et PostgreSQL ;
- persistance validée après redémarrage des conteneurs ;
- récupération PostgreSQL validée sans renouveler le JWT ;
- durcissement Docker ;
- uniquement la Gateway publiée sur l'hôte ;
- 377 tests automatisés réussis.

État de validation :

    377 passed, 1 warning

## Architecture

Architecture de confiance Phase 5 :

    Client HTTP
         |
         | 127.0.0.1:8000
         v
    FastAPI Gateway
         |
         +-------------------------------+
         |                               |
         v                               v
    Authentification                 Redis
         |                               |
         |                               +-- Rate limiting
         |                               |
         |                               +-- Anti-brute-force
         |
         v
    JWT signé et validé
         |
         v
    Rechargement utilisateur
    depuis PostgreSQL
         |
         v
    AuthorizationService
         |
         v
    RBAC PostgreSQL
         |
         +-- users
         +-- roles
         +-- permissions
         +-- user_roles
         +-- role_permissions
         |
         v
    Policy Zero Trust
         |
         +-- service-a read/write
         |
         +-- service-b read/write
         |
         +-- administration des rôles
         |
         v
    Reverse Proxy
         |
         +-- Service A
         |
         +-- Service B

Principe de sécurité :

    JWT valide
        ≠
    autorisation suffisante

L'identité est rechargée depuis PostgreSQL à chaque requête
protégée et les permissions courantes sont également évaluées
depuis PostgreSQL.

Les claims client tels que `role` ou `permissions` ne constituent
jamais une source d'autorité.

Seule la Gateway est publiée sur la machine hôte :

    127.0.0.1:8000

PostgreSQL, Redis et les microservices restent uniquement
accessibles depuis le réseau Docker interne.

Chaîne de migrations :

    Alembic
       |
       v
    1cc279e452ed
       |
       | create users
       v
    b04e170d1c97
       |
       | add RBAC authorization schema
       v
    HEAD

Tables persistantes principales :

    users
    roles
    permissions
    user_roles
    role_permissions

## Structure du projet

    gateway/
    └── app/
        ├── auth/
        ├── authorization/
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

La première migration est :

    1cc279e452ed

Elle crée la table :

    users

La migration RBAC Phase 5 est :

    b04e170d1c97

Elle crée :

    roles
    permissions
    user_roles
    role_permissions

Elle initialise également les rôles système et leurs permissions,
puis attribue le rôle `user` aux utilisateurs existants lors de
l'upgrade.

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

    b04e170d1c97 (head)

    No new upgrade operations detected.

La migration downgrade/upgrade a également été testée avec
conservation des utilisateurs existants et réattribution du rôle
par défaut.

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

Les routes `/api/*` nécessitent :

1. un JWT valide ;
2. un utilisateur actif rechargé depuis PostgreSQL ;
3. une permission RBAC courante chargée depuis PostgreSQL.

Services disponibles :

- `service-a` ;
- `service-b`.

La politique d'autorisation est dérivée exclusivement des
informations de routage fiables de la Gateway.

Méthodes de lecture :

    GET
    HEAD
    OPTIONS

requièrent :

    proxy:<service>:read

Méthodes de modification :

    POST
    PUT
    PATCH
    DELETE

requièrent :

    proxy:<service>:write

Toute méthode non classifiée est refusée par défaut.

Un service inconnu est également rejeté avant tout appel
upstream.

Les routes génériques du proxy restent volontairement exclues
du schéma OpenAPI.

La Gateway filtre les headers réseau spoofables ainsi que les
headers de privilège tels que :

    X-Role
    X-User-Role
    X-Permission
    X-Authorization-Role

### Autorisation RBAC et Zero Trust

Le modèle RBAC persistant utilise :

    users
      |
      +-- user_roles
              |
              v
            roles
              |
              +-- role_permissions
                       |
                       v
                  permissions

Rôles système :

| Rôle | Service A | Service B | Administration RBAC |
|---|---|---|---|
| `user` | lecture | lecture | aucune |
| `operator` | lecture + écriture | lecture + écriture | aucune |
| `admin` | lecture + écriture | lecture + écriture | lecture + gestion |

Permissions persistantes :

    proxy:service-a:read
    proxy:service-a:write
    proxy:service-b:read
    proxy:service-b:write
    authorization:roles:read
    authorization:roles:manage

Un utilisateur créé via `/auth/register` reçoit automatiquement
le rôle minimal `user`.

Le payload d'inscription interdit les champs supplémentaires :
un client ne peut donc pas demander lui-même `role=admin`.

L'administration des rôles nécessite les permissions
`authorization:roles:read` ou
`authorization:roles:manage`.

La base PostgreSQL est la source d'autorité.

Conséquence :

    même JWT
       |
       +-- ajout operator
       |       |
       |       v
       |    écriture autorisée
       |
       +-- suppression operator
               |
               v
            écriture immédiatement refusée

Aucune réémission du JWT n'est nécessaire pour appliquer une
révocation.

Tests de sécurité validés :

- self-promotion d'un utilisateur normal : HTTP 403 ;
- injection de rôle à l'inscription : rejetée ;
- claims JWT `role` / `permissions` forgés : sans effet ;
- headers RBAC spoofés : sans effet ;
- headers RBAC spoofés non transmis aux services internes ;
- autorisation refusée : aucun appel upstream ;
- backend d'autorisation indisponible : HTTP 503 fail-closed ;
- méthode HTTP non reconnue : refus par défaut.

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

Un utilisateur nouvellement inscrit reçoit le rôle `user`.

### Authentification

    POST /auth/token
    Content-Type: application/x-www-form-urlencoded

### Profil courant

    GET /auth/me
    Authorization: Bearer <token>

### Administration RBAC

Lecture des rôles d'un utilisateur :

    GET /authorization/users/{username}/roles
    Authorization: Bearer <token>

Attribution d'un rôle :

    PUT /authorization/users/{username}/roles/{role_name}
    Authorization: Bearer <token>

Suppression d'un rôle :

    DELETE /authorization/users/{username}/roles/{role_name}
    Authorization: Bearer <token>

Ces routes sont protégées par les permissions
`authorization:roles:read` et
`authorization:roles:manage`.

### Reverse proxy

    /api/{service_name}
    /api/{service_name}/{path}

Méthodes explicitement supportées :

    GET
    HEAD
    OPTIONS
    POST
    PUT
    PATCH
    DELETE

Chaque requête nécessite :

    Authorization: Bearer <token>

puis une permission RBAC adaptée au service et à la méthode.

## Documentation interactive

Lorsque la Gateway fonctionne :

- Swagger UI : `http://127.0.0.1:8000/docs`
- ReDoc : `http://127.0.0.1:8000/redoc`
- OpenAPI : `http://127.0.0.1:8000/openapi.json`

Le schéma OpenAPI expose les routes explicites :

- `/health` ;
- `/auth/register` ;
- `/auth/token` ;
- `/auth/me` ;
- `/authorization/users/{username}/roles` ;
- `/authorization/users/{username}/roles/{role_name}`.

Les routes proxy génériques `/api/*` sont volontairement
exclues du schéma.

## Tests

Créer l'environnement Python :

    python -m venv venv
    source venv/bin/activate

Installer :

    python -m pip install \
      --requirement requirements.txt

Exécuter :

    python -m pytest -q

État validé de la Phase 5 :

    377 passed, 1 warning

La couverture inclut notamment :

- JWT valides, expirés, altérés et malformés ;
- persistance PostgreSQL ;
- migrations Alembic ;
- rate limiting Redis ;
- anti-brute-force ;
- repositories RBAC ;
- services d'autorisation ;
- administration des rôles ;
- proxy Zero Trust ;
- spoofing de privilèges ;
- claims JWT de privilège forgés ;
- fail-closed PostgreSQL ;
- fail-closed du backend d'autorisation ;
- absence d'appel upstream lorsqu'une permission est refusée.

Le warning restant provient de l'intégration actuelle entre
Starlette `TestClient` et `httpx` et ne représente pas un échec
fonctionnel.

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
- le bootstrap du tout premier administrateur reste une opération
  contrôlée côté infrastructure/base de données ;
- PostgreSQL conserve un root filesystem writable afin de rester
  compatible avec le fonctionnement de l'image officielle ;
- les événements d'audit persistants seront ajoutés lors de la
  phase d'observabilité ;
- le déploiement CI/CD n'est pas encore finalisé.

## Licence

Projet pédagogique de démonstration d'une API Gateway sécurisée.
