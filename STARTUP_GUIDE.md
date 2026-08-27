# 🚀 Guide de Démarrage — GuardPay AI

## Prérequis

| Outil | Version minimale |
|---|---|
| **Docker Desktop** | 4.x (avec Docker Compose V2) |
| **Flutter SDK** | 3.x |
| **Android Studio** | avec émulateur API 26+ |
| **Git** | 2.x |

---

## 1. Backend (Docker)

### 1.1 Premier lancement

```bash
cd c:\Users\OMEN\Documents\Projects\Mobile_Project_V2

# Construire et démarrer tous les services
docker compose up -d --build
```

Cela démarre **4 services** :

| Service | Port | Rôle |
|---|---|---|
| `api` | `8000` | Backend FastAPI (Python) |
| `ollama` | `11434` | Serveur LLM local |
| `db` | `5432` | PostgreSQL 16 |
| `redis` | `6379` | Redis 7 (cache/sessions) |

### 1.2 ⚠️ Télécharger le modèle Qwen (OBLIGATOIRE)

Le service `ollama-pull` tente de télécharger le modèle automatiquement, mais **il échoue souvent**.
Vous **devez** exécuter cette commande manuellement :

```bash
docker exec -it mobile_project_v2-ollama-1 ollama pull qwen2.5:1.5b
```

> **Note** : Le téléchargement fait ~1 Go. Attendez que la commande se termine complètement.

Pour vérifier que le modèle est bien installé :

```bash
docker exec -it mobile_project_v2-ollama-1 ollama list
```

Vous devez voir `qwen2.5:1.5b` dans la liste.

### 1.3 Vérifier que tout fonctionne

```bash
# Vérifier l'état des conteneurs
docker ps

# Tester le health check du backend
curl http://localhost:8000/api/security/health
```

La réponse doit contenir `"llm_status": "connected"` et `"llm_model": "qwen2.5:1.5b"`.

### 1.4 Voir les logs

```bash
# Tous les services
docker compose logs -f

# Seulement le backend
docker compose logs -f api

# Seulement Ollama
docker compose logs -f ollama
```

---

## 2. Frontend (Flutter)

### 2.1 Installer les dépendances

```bash
cd c:\Users\OMEN\Documents\Projects\Mobile_Project_V2

flutter pub get
```

### 2.2 Lancer l'émulateur Android

```bash
# Lister les émulateurs disponibles
flutter emulators

# Lancer un émulateur (remplacer <nom> par celui listé)
flutter emulators --launch <nom>
```

Ou ouvrir Android Studio → Device Manager → Démarrer un émulateur API 26+.

### 2.3 Lancer l'application

```bash
flutter run
```

> **Important** : L'app Flutter sur l'émulateur Android utilise `10.0.2.2:8000` pour accéder au backend Docker sur `localhost:8000`. Aucune configuration supplémentaire n'est nécessaire.

---

## 3. Ordre de démarrage recommandé

```
1. docker compose up -d --build          ← Backend + BDD + Redis + Ollama
2. docker exec -it mobile_project_v2-ollama-1 ollama pull qwen2.5:1.5b  ← Modèle IA
3. curl http://localhost:8000/api/security/health   ← Vérification
4. flutter pub get                        ← Dépendances Flutter
5. flutter run                            ← Lancer l'app
```

---

## 4. Commandes utiles

| Action | Commande |
|---|---|
| Arrêter tout | `docker compose down` |
| Redémarrer le backend | `docker compose restart api` |
| Rebuild après changement backend | `docker compose up -d --build api` |
| Reset complet (⚠️ perd les données) | `docker compose down -v` |
| Hot reload Flutter | Appuyer sur `r` dans le terminal |
| Hot restart Flutter | Appuyer sur `R` dans le terminal |

---

## 5. Dépannage

### Le modèle Qwen n'est pas trouvé (`model not found`)
```bash
docker exec -it mobile_project_v2-ollama-1 ollama pull qwen2.5:1.5b
```

### Le nom du conteneur Ollama est différent
```bash
docker ps --format "{{.Names}}" | findstr ollama
```
Puis utilisez le nom retourné dans la commande `docker exec`.

### L'app Flutter ne se connecte pas au backend
- Vérifiez que Docker tourne : `docker ps`
- Vérifiez le health check : `curl http://localhost:8000/api/security/health`
- Sur émulateur Android, le backend est accessible via `10.0.2.2:8000` (configuré automatiquement)

### L'analyse IA est lente
Le modèle Qwen 2.5 1.5B tourne sur **CPU** dans Docker. Les temps attendus :
- Analyse complète APK : **30-90 secondes**
- Explication par item : **10-20 secondes**

Pour accélérer : utiliser un GPU avec `docker compose` + configuration NVIDIA.
