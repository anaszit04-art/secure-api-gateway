# Secure API Gateway — Operations Runbook

Ce document fournit les procédures d'exploitation et de
diagnostic de la Secure API Gateway.

Toutes les commandes sont exécutées depuis la racine du
repository.

## Règles de sécurité

Ne jamais afficher le contenu de `.env`.

Ne jamais afficher ou copier dans les logs :

- JWT ;
- clé de signature ;
- mot de passe PostgreSQL ;
- header Authorization ;
- chaîne de connexion complète.

Pour vérifier Docker Compose, utiliser uniquement :

    docker compose config --quiet

Ne pas utiliser `docker compose config` sans `--quiet`, car
les variables d'environnement peuvent être résolues.

## État général

Vérifier les services :

    docker compose ps

État nominal :

    gateway      healthy
    postgres     healthy
    redis        healthy
    service-a    healthy
    service-b    healthy

## Liveness

Tester :

    curl -sS \
      http://127.0.0.1:8000/health

Réponse nominale :

    {"status":"ok"}

`/health` représente uniquement la liveness du processus
Gateway.

Une panne Redis, PostgreSQL ou upstream ne doit donc pas
nécessairement faire échouer `/health`.

## Readiness

Tester :

    curl -sS \
      http://127.0.0.1:8000/ready

Réponse nominale :

    {
      "status": "ready",
      "checks": {
        "database": "ok",
        "redis": "ok"
      }
    }

PostgreSQL ou Redis indisponible entraîne HTTP 503.

Les services upstream sont volontairement exclus de la
readiness. Leur indisponibilité est gérée par les circuit
breakers.

## Logs opérationnels

Consulter les logs :

    docker compose logs \
      --no-color \
      --tail 100 \
      gateway

La Gateway produit ses propres événements JSON structurés.

Les access logs HTTP standards Uvicorn sont désactivés afin
d'éviter :

- les doublons ;
- les chemins HTTP bruts ;
- les query strings dans les logs d'accès.

Les champs structurés autorisés incluent notamment :

    timestamp
    level
    logger
    event
    request_id
    method
    route
    status_code
    duration_ms
    dependency
    dependency_status

Les logs opérationnels ne doivent jamais contenir un JWT,
Authorization, un body de requête, une query string brute ou
une URL de base de données.

## Corrélation Request ID

Chaque requête reçoit un UUID créé par la Gateway.

Capturer un request ID :

    request_id="$(
      curl \
        -sS \
        -D - \
        -o /dev/null \
        http://127.0.0.1:8000/health \
      | awk '
          BEGIN {
            IGNORECASE=1
          }

          /^x-request-id:/ {
            gsub("\r", "", $2)
            print $2
          }
        '
    )"

    printf '%s\n' "$request_id"

Rechercher la requête correspondante :

    docker compose logs \
      --no-color \
      --since 5m \
      gateway \
      | grep -F "$request_id"

Les valeurs `X-Request-ID` fournies par un client ne sont pas
considérées comme fiables. La Gateway génère son propre UUID.

## Diagnostic readiness

Une dépendance critique indisponible produit un événement :

    readiness_dependency_unavailable

Recherche :

    docker compose logs \
      --no-color \
      --since 10m \
      gateway \
      | grep \
        'readiness_dependency_unavailable'

Les seules dépendances autorisées dans cet événement sont :

    database
    redis

Exemple logique :

    event=readiness_dependency_unavailable
    dependency=redis
    dependency_status=unavailable
    status_code=503

Aucune exception brute, URL d'infrastructure ou credential
n'est incluse.

## Prometheus

Le serveur Prometheus écoute sur le port interne 9100.

Ce port ne doit pas être publié sur l'hôte.

Vérifier :

    docker compose port \
      gateway \
      9100 \
      || true

Inspecter les ports :

    docker inspect \
      "$(docker compose ps -q gateway)" \
      --format \
      '{{json .NetworkSettings.Ports}}'

Lire les métriques depuis le conteneur :

    docker compose exec \
      -T gateway \
      python -c \
      'import urllib.request; print(
          urllib.request.urlopen(
              "http://127.0.0.1:9100/metrics",
              timeout=5,
          ).read().decode()
      )'

Principales familles :

    gateway_http_requests_total
    gateway_http_request_duration_seconds
    gateway_security_events_total
    gateway_rate_limit_decisions_total
    gateway_upstream_requests_total
    gateway_upstream_resilience_events_total
    gateway_upstream_request_duration_seconds

Les labels Prometheus sont volontairement bornés.

Ne jamais utiliser comme labels :

    username
    user_id
    request_id
    raw URL
    query string
    adresse IP

## Audit de sécurité

Les événements de sécurité importants sont persistés dans
PostgreSQL.

Le schéma d'audit ne stocke pas :

    password
    JWT
    Authorization
    request body
    query string
    raw client path

Le `request_id` permet de rapprocher les événements d'audit
et les logs opérationnels.

L'audit applicatif est append-oriented.

## Incident Redis

Vérifier :

    docker compose ps redis

Probe direct :

    docker compose exec \
      -T redis \
      redis-cli ping

Consulter les logs :

    docker compose logs \
      --no-color \
      --tail 100 \
      redis

Redis indisponible doit provoquer un comportement fail-closed
pour les opérations dépendantes du rate limiting ou de la
protection de connexion.

La readiness doit passer HTTP 503.

Redémarrer :

    docker compose restart redis

Attendre ensuite son statut `healthy`, puis vérifier :

    curl -sS \
      http://127.0.0.1:8000/ready

La Gateway ne doit pas nécessiter de redémarrage.

## Incident PostgreSQL

Vérifier :

    docker compose ps postgres

Probe direct :

    docker compose exec \
      -T postgres \
      sh -lc '
        PGPASSWORD="$POSTGRES_PASSWORD" \
        pg_isready \
          -U "$POSTGRES_USER" \
          -d "$POSTGRES_DB" \
          -h 127.0.0.1
      '

Consulter :

    docker compose logs \
      --no-color \
      --tail 100 \
      postgres

PostgreSQL indisponible entraîne notamment :

    /ready   -> HTTP 503

Les opérations nécessitant la source de vérité d'identité ou
d'autorisation doivent également échouer en mode fail-closed.

Un JWT valide ne constitue pas à lui seul une autorisation
suffisante.

Redémarrer :

    docker compose restart postgres

Attendre `healthy`, puis revérifier `/ready`.

## Incident upstream

État :

    docker compose ps \
      service-a \
      service-b

Les erreurs de connexion initiales peuvent produire HTTP 502.

Un timeout upstream produit HTTP 504.

Un circuit OPEN rejette ensuite localement avec HTTP 503.

Rechercher les événements :

    docker compose logs \
      --no-color \
      --since 10m \
      gateway \
      | grep -E \
        'circuit|upstream'

Les circuit breakers sont isolés par service.

Une panne de Service A ne doit pas ouvrir le circuit de
Service B.

## Rotation des logs Docker

Les conteneurs utilisent :

    driver = json-file
    max-size = 10m
    max-file = 3

Contrôle :

    docker inspect \
      "$(docker compose ps -q gateway)" \
      --format \
      'Driver={{.HostConfig.LogConfig.Type}} Config={{json .HostConfig.LogConfig.Config}}'

Cette politique empêche la croissance sans limite des fichiers
de logs Docker.

## Recovery après incident

Vérifier d'abord :

    docker compose ps

Puis :

    curl -sS \
      http://127.0.0.1:8000/health

    curl -sS \
      http://127.0.0.1:8000/ready

État nominal :

    5 services healthy
    /health HTTP 200
    /ready HTTP 200
    database=ok
    redis=ok

PostgreSQL et Redis doivent pouvoir revenir à l'état nominal
sans redémarrer la Gateway.

## Validation configuration

Contrôle Docker Compose sûr :

    docker compose config --quiet

Contrôle Python :

    ruff check \
      gateway \
      tests \
      migrations \
      tools

    python -m pytest -q

    python -m pip check
