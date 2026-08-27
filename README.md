# GuardPay AI

Système de détection d'attaques sur APK Android, multi-couches, avec analyse de menaces
assistée par IA locale.

L'application Flutter audite l'appareil et les fichiers APK sur trois niveaux — détecteurs
natifs Kotlin, scoring comportemental embarqué, et enrichissement par un LLM local (Qwen 2.5
via Ollama) exécuté côté backend. La détection locale reste fonctionnelle hors ligne : le
backend n'est qu'une couche d'enrichissement.

---

## Sommaire

- [Architecture](#architecture)
- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Démarrage rapide](#démarrage-rapide)
- [Configuration](#configuration)
- [API backend](#api-backend)
- [Modèle de scoring](#modèle-de-scoring)
- [Structure du projet](#structure-du-projet)
- [Avant une mise en production](#avant-une-mise-en-production)
- [Dépannage](#dépannage)

---

## Architecture

```
┌──────────────────────── Application Flutter ────────────────────────┐
│                                                                     │
│   Splash ──▶ SecurityGate ──▶ Dashboard ──┬──▶ APK Analysis (self)  │
│                (scan bloquant)            └──▶ APK Report (externe) │
│                                                                     │
│   Couche sécurité                                                   │
│   SecurityManager · SecurityService · TFLiteAnalyzer                │
│   NativeBridge · ApkInfoCollector · SecureHttpClient                │
└────────────┬───────────────────────────────────────┬────────────────┘
             │ MethodChannel                         │ HTTP
             ▼                                       ▼
┌────────────────────────────┐        ┌──────────────────────────────┐
│  Kotlin (Android natif)    │        │      Backend FastAPI         │
│  SecurityDetectors         │        │  ThreatAnalyzer (statique)   │
│  9 vecteurs de détection   │        │  AnomalyDetector (ML)        │
│  Hash APK · permissions    │        │  OllamaAnalyzer (LLM)        │
│  composants du manifeste   │        │  AlertService (Slack/SIEM)   │
└────────────────────────────┘        └────┬────────────┬────────────┘
                                           │            │
                                  PostgreSQL 16    Ollama (Qwen 2.5)
                                     + Redis 7
```

| Couche | Technologie |
|---|---|
| Frontend | Flutter 3.2+ / Dart |
| Détection native | Kotlin, via MethodChannel `com.example.security/native` |
| Backend | Python 3 / FastAPI |
| IA | Qwen 2.5 1.5B servi par Ollama |
| ML | scikit-learn — Isolation Forest |
| Base de données | PostgreSQL 16 (SQLAlchemy async) |
| Cache | Redis 7 |
| Déploiement | Docker Compose |

---

## Fonctionnalités

### Détection native — 9 vecteurs indépendants

Chaque détecteur est autonome, afin qu'un hook posé sur l'un d'eux ne neutralise pas les
autres. Les poids ci-dessous alimentent le score statique.

| # | Vecteur | Poids | Méthode |
|---|---|---|---|
| 1 | Frida | 0.95 | Ports 27042-27043, `/proc/self/maps`, processus `frida-server` |
| 2 | Hooks runtime | 0.90 | Méthodes natives inattendues, bibliothèques de hooking chargées |
| 3 | Bypass de cert pinning | 0.85 | Apps proxy connues, proxy HTTP configuré |
| 4 | Signature APK | 0.80 | SHA-256 du certificat de signature |
| 5 | Intégrité DEX | 0.80 | SHA-256 de `classes.dex` |
| 6 | Xposed | 0.70 | Fichiers, pile d'appels, application installée |
| 7 | Debugger | 0.60 | API `Debug`, `TracerPid`, mesure de temps d'exécution |
| 8 | Root | 0.40 | Binaires `su`, apps de gestion root, propriétés système |
| 9 | Émulateur | 0.20 | Empreinte de build, propriétés QEMU, fichiers spécifiques |

### Analyse APK

Audit statique de l'APK installé ou d'un fichier APK sélectionné : hash, version,
source d'installation, flag `debuggable`, sideloading, permissions (dont les sensibles),
activities, services, receivers et providers. Chaque permission ou composant peut être
soumis individuellement au LLM pour obtenir une explication de risque.

### Analyse comportementale embarquée

`SecurityManager` bufferise les 50 derniers événements (appels réseau, accès fichiers,
appels d'API, pics CPU, anomalies mémoire) et en extrait un vecteur de 6 dimensions :

`network_calls_count`, `file_access_count`, `timing_entropy`, `api_call_sequence_hash`,
`memory_anomaly_score`, `cpu_spike_count`

Ce vecteur est scoré localement par heuristiques calibrées, puis envoyé au backend où
l'Isolation Forest le rescore.

> **Note** — Le modèle TFLite embarqué n'est pas encore livré. `TFLiteAnalyzer` s'appuie
> sur les heuristiques de `_heuristicScore`, qui reproduisent les signatures d'attaque de
> l'Isolation Forest côté backend.

### Enrichissement IA

Pour toute menace `medium` ou supérieure, le backend interroge Qwen 2.5 et produit une
explication en français, un niveau de risque, une probabilité de faux positif et des
recommandations concrètes. L'appel est asynchrone par défaut, ou bloquant avec
`?wait_for_llm=true`.

---

## Prérequis

| Outil | Version |
|---|---|
| Docker Desktop | 4.x (Compose V2) |
| Flutter SDK | 3.2+ |
| Android Studio | émulateur API 26+ |

Le modèle Qwen tourne sur CPU et réserve 4 Go de RAM dans `docker-compose.yml`.

---

## Démarrage rapide

### 1. Backend

```bash
docker compose up -d --build
```

Quatre services démarrent : `api` (8000), `ollama` (11434), `db` (5432), `redis` (6379).

### 2. Modèle Qwen

Le service `ollama-pull` tente le téléchargement automatiquement, mais échoue souvent.
Lancez-le manuellement (~1 Go) :

```bash
docker exec -it mobile_project_v2-ollama-1 ollama pull qwen2.5:1.5b
docker exec -it mobile_project_v2-ollama-1 ollama list
```

Si le nom du conteneur diffère : `docker ps --format "{{.Names}}" | grep ollama`

### 3. Vérification

```bash
curl http://localhost:8000/api/security/health
```

La réponse doit contenir `"llm_status": "connected"` et `"llm_model": "qwen2.5:1.5b"`.
Documentation interactive de l'API : <http://localhost:8000/docs>

### 4. Application Flutter

```bash
flutter pub get
flutter run
```

Sur émulateur Android, le backend est joint via `10.0.2.2:8000` — aucune configuration
supplémentaire n'est requise.

---

## Configuration

Copiez `.env.example` vers `backend/.env` et ajustez les valeurs. Toutes les clés sont
lues par `app/core/config.py`.

| Variable | Défaut | Rôle |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://postgres:postgres@localhost:5432/security_db` | Connexion PostgreSQL |
| `REDIS_URL` | `redis://localhost:6379` | Connexion Redis |
| `SECRET_KEY` | placeholder | Clé de signature JWT (32 caractères minimum) |
| `JWT_EXPIRATION_MINUTES` | `60` | Durée de vie des tokens |
| `OLLAMA_URL` | `http://localhost:11434` | Endpoint Ollama |
| `OLLAMA_MODEL` | `qwen2.5:1.5b` | Modèle utilisé |
| `OLLAMA_TIMEOUT` | `180` | Timeout de lecture LLM (secondes) |
| `SLACK_WEBHOOK_URL` | vide | Alertes critiques Slack (désactivé si vide) |
| `SIEM_WEBHOOK_URL` | vide | Alertes critiques SIEM (désactivé si vide) |
| `ML_CONTAMINATION` | `0.05` | Taux d'anomalie de l'Isolation Forest |
| `ML_N_ESTIMATORS` | `200` | Nombre d'arbres |
| `STATIC_WEIGHT` / `ML_WEIGHT` | `0.60` / `0.40` | Pondération du score combiné |
| `THRESHOLD_LOW…CRITICAL` | `0.20` / `0.40` / `0.65` / `0.85` | Seuils de niveaux de menace |
| `DEBUG` | `true` | Echo SQL et mode debug |

---

## API backend

### Sécurité — `/api/security`

| Méthode | Route | Description |
|---|---|---|
| `GET` | `/health` | État du backend et connectivité Ollama |
| `POST` | `/report` | Rapport de sécurité complet. `?wait_for_llm=true` pour une analyse LLM synchrone |
| `POST` | `/apk-analysis` | Audit d'un APK (scoring statique + verdict IA) |
| `POST` | `/explain-risk` | Explication IA d'une permission ou d'un composant |

### Authentification — `/api/auth`

| Méthode | Route | Description |
|---|---|---|
| `POST` | `/token` | Émet un JWT à partir d'une clé d'API et d'un `device_id` |
| `DELETE` | `/revoke` | Révoque un token (force logout) |
| `GET` | `/verify` | Valide le token courant |

### Dashboard — `/api/dashboard`

| Méthode | Route | Description |
|---|---|---|
| `GET` | `/incidents` | Incidents récents, filtrables par niveau et appareil |
| `GET` | `/stats` | Agrégats : total, distribution, score moyen, critiques sur 24 h |
| `WS` | `/ws/incidents` | Flux temps réel (écho ; à brancher sur Redis pub/sub) |

### Santé

`GET /` et `GET /api/health` — état de l'API, de la base et d'Ollama.

---

## Modèle de scoring

```
score_statique   = poids le plus élevé parmi les contrôles déclenchés
score_ml         = Isolation Forest sur le vecteur comportemental à 6 dimensions
score_combiné    = 0.60 × score_statique + 0.40 × score_ml
```

L'approche « poids maximum » est délibérée : elle empêche des contrôles de faible sévérité
de diluer une détection critique.

| Score combiné | Niveau | Action |
|---|---|---|
| > 0.85 | `critical` | `force_logout` + révocation du token + alerte Slack/SIEM |
| > 0.65 | `high` | Surveillance renforcée |
| > 0.40 | `medium` | Enrichissement LLM |
| > 0.20 | `low` | Journalisation |
| ≤ 0.20 | `clean` | — |

Types d'attaques classifiés : `frida_injection`, `runtime_hooking`, `mitm_attempt`,
`apk_repackage`, `xposed_framework`, `rooted_device`, `debugging_attempt`,
`emulator_environment`, `root_exploit`, `unknown_anomaly`.

Entraînement du modèle ML sur données synthétiques :

```bash
docker compose exec api python -m app.ml.trainer
```

---

## Structure du projet

```
lib/
├── main.dart                     Point d'entrée, thème
├── app_theme.dart                Palettes claire et sombre
├── theme_provider.dart           Préférence de thème persistée
├── screens/
│   ├── splash_screen.dart
│   ├── dashboard_screen.dart     Menace temps réel, vecteurs, graphe d'anomalie
│   ├── apk_analysis_screen.dart  Audit de l'APK installé
│   └── apk_report_screen.dart    Rapport d'APK externe, explications IA par item
└── security/
    ├── security_manager.dart     Orchestrateur singleton du pipeline
    ├── security_gate.dart        Scan bloquant au démarrage
    ├── security_service.dart     Rapports backend, identité appareil, JWT
    ├── secure_http_client.dart   Dio avec certificate pinning
    ├── native_bridge.dart        MethodChannel vers Kotlin
    ├── apk_info_collector.dart   Métadonnées APK natives
    ├── external_apk_scanner.dart Sélection et audit d'un APK externe
    ├── tflite_analyzer.dart      Scoring comportemental embarqué
    └── models/                   ThreatLevel, BehaviorEvent, SecurityReport

android/app/src/main/kotlin/com/example/anti_tampering_apk/
├── MainActivity.kt
├── NativeSecurityPlugin.kt       Gestionnaire du MethodChannel
└── SecurityDetectors.kt          Les 9 vecteurs de détection

backend/app/
├── main.py                       Application FastAPI, lifespan, CORS
├── api/routes/                   security · auth · dashboard
├── core/                         config · database · security (JWT)
├── ml/                           anomaly_detector · feature_extractor · trainer
├── models/                       ORM : device · security_report
└── services/                     threat_analyzer · llm_analyzer · alert_service
```

Documentation complémentaire : [DOCUMENTATION_APP.md](DOCUMENTATION_APP.md) (technique
détaillée) et [STARTUP_GUIDE.md](STARTUP_GUIDE.md) (guide de démarrage pas à pas).

---

## Avant une mise en production

Le dépôt est configuré pour le développement. Les points suivants doivent être traités
avant tout déploiement réel :

- **Empreintes natives** — `SecurityDetectors.kt` contient `EXPECTED_CERT_FINGERPRINT` et
  `EXPECTED_DEX_HASH` en placeholder. Tant qu'ils ne sont pas renseignés, la vérification
  de signature et l'intégrité DEX sont ignorées.
- **Certificate pinning** — `secure_http_client.dart` accepte tous les certificats tant que
  `_certFingerprint` reste à sa valeur par défaut.
- **Transport** — l'application communique en HTTP clair vers `10.0.2.2:8000`.
- **Secret JWT** — `SECRET_KEY` doit être régénérée ; la liste de révocation des tokens est
  en mémoire et doit passer sur Redis.
- **Clés d'API** — `VALID_API_KEYS` est codée en dur dans `api/routes/auth.py`.
- **CORS** — `allow_origins=["*"]` dans `main.py` doit être restreint.
- **Fichiers versionnés** — `app-release.apk` (69 Mo) et `backend/.env` sont suivis par Git.
  Le `.env` ne contient que des placeholders, mais les deux devraient être retirés du suivi
  et ajoutés au `.gitignore`.

---

## Dépannage

**`model not found`**
```bash
docker exec -it mobile_project_v2-ollama-1 ollama pull qwen2.5:1.5b
```

**L'application ne joint pas le backend**
Vérifiez `docker ps`, puis `curl http://localhost:8000/api/security/health`. Sur émulateur,
`localhost` de l'hôte est accessible via `10.0.2.2`.

**L'analyse IA est lente**
Qwen 2.5 1.5B tourne sur CPU : comptez 30 à 90 s pour une analyse APK complète et 10 à 20 s
pour une explication unitaire. Un runtime GPU (configuration NVIDIA dans Compose) réduit
nettement ces temps.

**Les vérifications natives échouent sur émulateur**
`MissingPluginException` est traitée comme un état sain et l'application continue. Le
`SecurityGate` laisse toujours passer en cas d'erreur — la conception est offline-first.

**Commandes utiles**

| Action | Commande |
|---|---|
| Logs backend | `docker compose logs -f api` |
| Rebuild backend | `docker compose up -d --build api` |
| Tout arrêter | `docker compose down` |
| Reset complet (perte de données) | `docker compose down -v` |
| Analyse statique Flutter | `flutter analyze` |
