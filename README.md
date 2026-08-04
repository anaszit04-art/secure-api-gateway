# Secure API Gateway

API Gateway sécurisée développée avec FastAPI, JWT, Redis et Docker.

Le projet centralise l'authentification, la limitation de débit,
la protection anti-brute-force et le routage vers des microservices
internes.

## État du projet

Phase 3 terminée :

- authentification JWT ;
- reverse proxy authentifié ;
- rate limiting Redis distribué ;
- protection anti-brute-force ;
- verrouillage temporaire des comptes ;
- limitation des connexions par adresse IP ;
- durcissement des conteneurs Docker ;
- 221 tests automatisés réussis.

## Architecture

    Client HTTP
         |
         | 127.0.0.1:8000
         v
    FastAPI Gateway
      - JWT
      - Rate limiting
      - Anti-brute-force
      - Reverse proxy
         |
         +------ Redis interne
         |
         +------ Service A
         |
         +------ Service B

Seule la Gateway est publiée sur la machine hôte.

Redis et les microservices sont uniquement accessibles depuis le
réseau Docker interne.

## Structure du projet

    gateway/
    └── app/
        ├── auth/
        ├── proxy/
        ├── rate_limit/
        └── main.py

    microservices/
    ├── service_a/
    └── service_b/

    tests/
    compose.yaml
    Dockerfile
    requirements.txt
    requirements-runtime.txt

## Fonctionnalités

### Authentification

- inscription locale ;
- normalisation des noms d'utilisateur ;
- hachage Argon2 des mots de passe ;
- jetons JWT HS256 ;
- validation de l'émetteur et de l'audience ;
- durée configurable des jetons ;
- message générique pour les identifiants incorrects ;
- vérification Argon2 factice pour les utilisateurs inconnus.

### Reverse proxy

Les routes `/api/*` nécessitent un JWT valide.

La Gateway transfère les requêtes vers les services enregistrés
tout en filtrant les headers sensibles.

Services disponibles :

- `service-a` ;
- `service-b`.

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
- une nouvelle tentative toutes les cinq secondes après épuisement ;
- utilisation de l'adresse réseau directe ;
- `X-Forwarded-For` ignoré tant qu'aucun proxy fiable n'est configuré.

Politique par compte :

- seuil : 5 échecs ;
- fenêtre : 900 secondes ;
- verrouillage : 300 secondes ;
- suppression du compteur après une connexion réussie ;
- identifiant normalisé puis haché en SHA-256.

Lorsque Redis est indisponible, les routes protégées appliquent
une stratégie fail-closed et retournent une réponse HTTP 503.

## Durcissement Docker

Les conteneurs utilisent :

- un utilisateur non-root ;
- un système de fichiers en lecture seule ;
- `no-new-privileges:true` ;
- `cap_drop: ALL` ;
- des répertoires temporaires en `tmpfs` ;
- un réseau Docker interne ;
- aucun port hôte pour Redis ;
- aucun port hôte pour les microservices ;
- une exposition de la Gateway limitée à `127.0.0.1:8000`.

## Prérequis

- Python 3.13 ;
- Docker ;
- Docker Compose ;
- Git.

## Configuration

Créer le fichier local :

    cp .env.example .env

Le fichier `.env` ne doit jamais être versionné.

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
| `REDIS_CONNECT_TIMEOUT_SECONDS` | Timeout de connexion | `2` |
| `REDIS_SOCKET_TIMEOUT_SECONDS` | Timeout des opérations | `2` |
| `REDIS_MAX_CONNECTIONS` | Taille maximale du pool | `20` |
| `REDIS_HEALTH_CHECK_INTERVAL_SECONDS` | Intervalle de contrôle | `30` |
| `REDIS_VERIFY_ON_STARTUP` | Vérification au démarrage | `false` |

Docker Compose force la vérification Redis au démarrage de la
Gateway.

## Démarrage

    docker compose up --build -d

Vérifier les services :

    docker compose ps

Les quatre services doivent être `healthy` :

- `gateway` ;
- `redis` ;
- `service-a` ;
- `service-b`.

Consulter les logs :

    docker compose logs --tail=100 gateway redis

Arrêter l'environnement :

    docker compose down

## Endpoints

### Santé

    GET /health

### Inscription

    POST /auth/register
    Content-Type: application/json

Exemple :

    curl -X POST \
      http://127.0.0.1:8000/auth/register \
      -H 'Content-Type: application/json' \
      -d '{
        "username": "anas",
        "password": "correct-horse-battery-staple"
      }'

### Authentification

    POST /auth/token
    Content-Type: application/x-www-form-urlencoded

Exemple :

    curl -X POST \
      http://127.0.0.1:8000/auth/token \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode 'username=anas' \
      --data-urlencode 'password=correct-horse-battery-staple'

### Profil courant

    GET /auth/me
    Authorization: Bearer <token>

### Reverse proxy

    ANY /api/{service_name}
    ANY /api/{service_name}/{path}
    Authorization: Bearer <token>

Exemple :

    curl \
      http://127.0.0.1:8000/api/service-a/ping \
      -H 'Authorization: Bearer <token>'

Les routes proxy génériques sont volontairement exclues du schéma
OpenAPI, car elles acceptent plusieurs méthodes et leurs contrats
dépendent du microservice ciblé.

## Documentation interactive

Lorsque la Gateway fonctionne :

- Swagger UI : `http://127.0.0.1:8000/docs`
- ReDoc : `http://127.0.0.1:8000/redoc`
- OpenAPI : `http://127.0.0.1:8000/openapi.json`

## Tests

Créer l'environnement Python :

    python -m venv venv
    source venv/bin/activate

Installer les dépendances :

    python -m pip install --requirement requirements.txt

Exécuter toute la suite :

    python -m pytest -q

État validé de la Phase 3 :

    221 passed, 1 warning

L'avertissement restant vient de l'intégration Starlette TestClient
et n'indique pas un échec fonctionnel.

## Contrôles utiles

Validation Compose :

    docker compose config --quiet

Contrôle Git :

    git diff --check
    git status --short

Inspection des clés Redis :

    docker compose exec -T redis \
      redis-cli --scan \
      --pattern 'secure-api-gateway:*'

Les noms d'utilisateur, UUID et adresses IP ne doivent pas apparaître
en clair dans les clés Redis.

## Limites actuelles

- les utilisateurs sont conservés en mémoire ;
- les utilisateurs sont perdus au redémarrage de la Gateway ;
- Redis n'utilise pas de persistance disque ;
- Redis conserve uniquement des états temporaires de sécurité ;
- la prochaine évolution prévue est PostgreSQL pour les utilisateurs
  et les événements d'audit.

## Licence

Projet pédagogique de démonstration d'une API Gateway sécurisée.
