# GuardPay AI — Documentation Technique de l'Application

---

## 1. Présentation Générale

**GuardPay AI** est une application mobile Flutter de sécurité conçue pour :

- Détecter les menaces en temps réel sur un appareil Android (root, hooks, Frida, etc.)
- Analyser des fichiers APK externes pour identifier les risques de sécurité
- Exploiter un modèle d'IA local (Qwen 2.5 via Ollama) pour générer des rapports de sécurité détaillés

### Stack Technique

| Couche         | Technologie                        |
|----------------|------------------------------------|
| Frontend       | Flutter 3.x / Dart                 |
| Backend        | Python FastAPI                     |
| IA / LLM       | Qwen 2.5 1.5B via Ollama          |
| Base de données| PostgreSQL 16                      |
| Cache          | Redis 7                            |
| Conteneurisation| Docker Compose                    |
| Analyse native | Kotlin (Android MethodChannel)     |
| ML embarqué    | TFLite (stubbé — fallback heuristique) |

---

## 2. Architecture Globale

```
┌─────────────────────────────────────────────────┐
│                  Flutter App                     │
│  ┌───────────┐ ┌───────────┐ ┌───────────────┐  │
│  │  Splash   │→│ Security  │→│  Dashboard    │  │
│  │  Screen   │ │   Gate    │ │   Screen      │  │
│  └───────────┘ └───────────┘ └──────┬────────┘  │
│                                     │            │
│                    ┌────────────────┼──────┐     │
│                    ▼                ▼      ▼     │
│            ┌─────────────┐  ┌──────────┐         │
│            │APK Analysis │  │APK Report│         │
│            │  (self)     │  │(external)│         │
│            └─────────────┘  └──────────┘         │
│                                                  │
│  ┌──────────────── Security Layer ─────────────┐ │
│  │ SecurityManager │ SecurityService │ TFLite   │ │
│  │ NativeBridge    │ ApkInfoCollector│ HttpClient│ │
│  └──────────────────────────────────────────────│ │
└────────────────────────┬────────────────────────┘
                         │ HTTP (10.0.2.2:8000)
                         ▼
┌─────────────────────────────────────────────────┐
│              Docker Backend                      │
│  ┌─────────┐ ┌─────────┐ ┌──────┐ ┌─────────┐  │
│  │ FastAPI  │ │ Ollama  │ │Postgre│ │  Redis  │  │
│  │ :8000   │ │ :11434  │ │ :5432 │ │  :6379  │  │
│  └─────────┘ └─────────┘ └──────┘ └─────────┘  │
└─────────────────────────────────────────────────┘
```

---

## 3. Parcours Utilisateur — Page par Page

### 3.1 Splash Screen

**Fichier** : `lib/screens/splash_screen.dart`
**Durée** : ~2.7 secondes

Écran d'introduction purement visuel :
- Animation scale + glow du logo bouclier
- Fade-in du texte "GuardPay AI"
- Navigation automatique vers le Security Gate

**Fonction réelle** : Aucune logique métier, seulement du branding visuel.

---

### 3.2 Security Gate

**Fichier** : `lib/security/security_gate.dart`
**Durée** : ~2-3 secondes

Écran de vérification de sécurité au démarrage. Il :

1. Initialise le SecurityManager (TFLite + HTTP client)
2. Lance un scan complet de sécurité (`runFullSecurityScan()`)
3. Affiche une barre de progression animée
4. Décide du comportement selon le résultat :

| Niveau de menace | Action                              |
|------------------|-------------------------------------|
| CLEAN / LOW      | Passage automatique au Dashboard    |
| MEDIUM           | Avertissement + bouton "Continuer"  |
| HIGH / CRITICAL  | Blocage de l'application            |

**Sur émulateur** : Score toujours = 0 → passe directement au Dashboard.

---

### 3.3 Dashboard (Page Principale)

**Fichier** : `lib/screens/dashboard_screen.dart`
**Rôle** : Tableau de bord de sécurité en temps réel

#### Zones d'affichage :

**A) Carte de Menace (en haut)**
- Cercle animé avec le niveau de menace (CLEAN → CRITICAL)
- Score combiné affiché au centre
- Effet radar rotatif
- Code couleur : vert (safe), jaune (moyen), rouge (critique)

**B) Grille de Détection (9 cases)**
Affiche l'état de 9 vecteurs de détection de sécurité :

| Vecteur            | Ce qu'il détecte                                       |
|--------------------|--------------------------------------------------------|
| Frida              | Injection dynamique Frida (ports 27042, libs en mémoire)|
| Root               | Accès superutilisateur (su, Magisk, SuperSU)           |
| Signature APK      | Certificat de signature modifié (APK repackagé)        |
| DEX Hash           | Code compilé modifié (injection de code malveillant)   |
| Xposed             | Framework de hooking persistant Xposed                 |
| Debugger           | Débogueur attaché au processus (IDA, GDB, Android Studio)|
| Émulateur          | Environnement émulé (pas un vrai téléphone)            |
| Hooks              | Fonctions interceptées/remplacées (hooking générique)  |
| Certificate Pinning| Bypass du pinning SSL (attaque MITM possible)          |

**C) Graphe d'Anomalie**
- Historique du score d'anomalie comportementale
- Basé sur l'analyse TFLite (réseau, fichiers, CPU, mémoire)

**D) System Status**
- État du backend, du moteur d'analyse, dernière analyse

#### Boutons :

| Icône    | Action                                                    |
|----------|-----------------------------------------------------------|
| 🔍       | Ouvre l'APK Analysis Screen (analyse de l'app elle-même)  |
| 📤       | File picker → analyse d'un APK externe → rapport Qwen    |
| 🌙/☀️    | Bascule thème sombre / clair                              |
| 🔄       | Relance le scan de sécurité manuellement                  |

---

### 3.4 APK Analysis Screen (Auto-Analyse)

**Fichier** : `lib/screens/apk_analysis_screen.dart`
**Accès** : Bouton 🔍 du Dashboard

Analyse l'APK de l'application **elle-même** (l'app installée sur le téléphone).

#### Ce qu'elle affiche (7 cartes) :

| Carte              | Contenu                                              |
|--------------------|------------------------------------------------------|
| Classification     | SAIN / SUSPECT / COMPROMIS + score circulaire animé  |
| Intégrité APK      | Hash SHA-256, signature, vérification DEX            |
| Permissions        | Liste complète avec niveau de risque pour chacune    |
| Security Checks    | Résultat des 9 détecteurs natifs                     |
| Corrélation Score  | Décomposition Static Score vs ML Score               |
| Rapport IA Qwen    | Analyse textuelle générée par l'IA                   |
| Métadonnées        | Package name, version, installeur, taille APK        |

**Source des données** : Plugin natif Kotlin via MethodChannel (`getApkInfo`).
Utilise l'API Android `PackageManager` pour lire les métadonnées de l'app installée.

---

### 3.5 APK Report Screen (Analyse Externe)

**Fichier** : `lib/screens/apk_report_screen.dart`
**Accès** : Bouton 📤 du Dashboard → sélection d'un APK → dialogue Qwen → rapport

Affiche le rapport complet d'un APK **externe** choisi par l'utilisateur.

#### Ce qu'elle affiche (6 sections) :

| Section            | Contenu                                                |
|--------------------|--------------------------------------------------------|
| Score Animé        | Cercle 0-100 avec verdict local (Sain/Suspect/Compromis)|
| Rapport IA Qwen    | Analyse textuelle complète générée par le LLM          |
| Détails APK        | Hash, signature, installeur, version                   |
| Grille de Risques  | 4 indicateurs : Debuggable, Sideloaded, Permissions, Vérifié|
| Permissions        | Liste avec explications FR + badge sensible + bouton IA|
| Composants         | Activities, Services, Receivers, Providers             |

#### Fonctionnalités avancées :

- **Détection de combinaisons dangereuses** :
  - INTERNET + READ_SMS + READ_CONTACTS → "Exfiltration de données"
  - INTERNET + CAMERA + RECORD_AUDIO → "Espionnage potentiel"
  - SYSTEM_ALERT_WINDOW + ACCESSIBILITY → "Attaque par overlay"

- **Détection de noms suspects** dans les composants :
  - "Backdoor", "Hidden", "Debug", "Admin" → alerte visuelle

- **IA par item** : Bouton sur chaque permission pour demander à Qwen une explication de risque spécifique

---

## 4. Extraction des Données APK

### Comment les permissions, activités et composants sont extraits

Le processus utilise le **MethodChannel** Flutter → Kotlin natif :

```
Flutter (Dart)                          Android (Kotlin)
     │                                       │
  pickAndAnalyzeApk()                        │
     │                                       │
  getExternalApkInfo(path)                   │
     │── MethodChannel ──────────────────►   │
     │   "getApkFileDetails"                 │
     │                                       │
     │                          PackageManager.getPackageArchiveInfo(path, flags)
     │                                       │
     │                          flags = GET_PERMISSIONS
     │                                | GET_ACTIVITIES
     │                                | GET_SERVICES
     │                                | GET_RECEIVERS
     │                                | GET_PROVIDERS
     │                                       │
     │◄── Résultat Map ─────────────────────│
     │                                       │
  ApkInfo.fromJson(result)                   │
  ApkAudit(...)                              │
```

L'API Android `getPackageArchiveInfo()` parse le fichier `AndroidManifest.xml` compressé dans l'APK sans l'installer.

### Données extraites :

| Donnée               | Source dans l'APK                            |
|----------------------|----------------------------------------------|
| Package name         | `<manifest package="...">`                   |
| Version              | `<manifest versionName="..." versionCode="">` |
| Permissions          | `<uses-permission android:name="..."/>`      |
| Activities           | `<activity android:name="..."/>`             |
| Services             | `<service android:name="..."/>`              |
| Receivers            | `<receiver android:name="..."/>`             |
| Providers            | `<provider android:name="..."/>`             |
| Debuggable           | `<application android:debuggable="true">`    |
| Hash SHA-256         | Calculé sur le fichier APK complet           |

---

## 5. Analyse IA avec Qwen

### Flux d'analyse cloud

```
APK sélectionné
     │
     ▼
ApkAudit (données locales : permissions, composants, hash...)
     │
     ▼
Backend FastAPI (/api/security/apk-analysis)
     │
     ▼
LLM Analyzer → Prompt structuré envoyé à Ollama
     │
     ▼
Qwen 2.5 1.5B génère l'analyse en français
     │
     ▼
Réponse : threat_level + score + llm_analysis (texte)
     │
     ▼
Affiché dans ApkReportScreen
```

### Ce que l'IA analyse :
- Le package name (est-il connu ? suspect ?)
- Les permissions déclarées (combinaisons dangereuses)
- Les composants exposés (activities, services)
- Le flag debuggable
- La source d'installation (sideloaded ou Play Store)

---

## 6. Les 9 Vecteurs de Détection RASP

RASP = Runtime Application Self-Protection

| # | Vecteur          | Menace détectée                    | Méthode de détection                    |
|---|------------------|------------------------------------|-----------------------------------------|
| 1 | Frida            | Injection dynamique                | Scan ports 27042, libs frida en mémoire |
| 2 | Root             | Accès superutilisateur             | Présence de su, Magisk, SuperSU         |
| 3 | Signature APK    | APK repackagé                      | Comparaison certificat de signature     |
| 4 | DEX Hash         | Code modifié                       | Hash SHA-256 des fichiers .dex          |
| 5 | Xposed           | Hooking persistant                 | Classes Xposed en mémoire              |
| 6 | Debugger         | Débogueur attaché                  | Debug.isDebuggerConnected()             |
| 7 | Émulateur        | Environnement virtuel              | Propriétés système, capteurs absents    |
| 8 | Hooks            | Interception de fonctions          | Intégrité des méthodes natives          |
| 9 | Cert Pinning     | MITM (Man-in-the-Middle)           | Vérification du certificat SSL          |

---

## 7. Score de Menace

Le score combiné est calculé comme suit :

```
Score Combiné = (Score Statique × 0.6) + (Score ML × 0.4)
```

- **Score Statique** : basé sur les résultats des 9 détecteurs natifs
- **Score ML** : basé sur l'analyse comportementale TFLite (réseau, fichiers, CPU, mémoire)

### Classification :

| Score        | Niveau    | Couleur | Action                  |
|-------------|-----------|---------|-------------------------|
| 0.0 - 0.2   | CLEAN     | Vert    | Accès normal            |
| 0.2 - 0.4   | LOW       | Bleu    | Accès normal            |
| 0.4 - 0.6   | MEDIUM    | Jaune   | Avertissement           |
| 0.6 - 0.8   | HIGH      | Orange  | Blocage recommandé      |
| 0.8 - 1.0   | CRITICAL  | Rouge   | Blocage obligatoire     |

---

## 8. Infrastructure Docker

### Services :

| Service   | Image              | Port  | Rôle                           |
|-----------|--------------------|-------|--------------------------------|
| api       | Python FastAPI     | 8000  | Backend REST API               |
| ollama    | ollama/ollama      | 11434 | Serveur LLM local              |
| db        | postgres:16-alpine | 5432  | Base de données                |
| redis     | redis:7-alpine     | 6379  | Cache et sessions              |

### Commande obligatoire après le premier démarrage :

```bash
docker exec -it mobile_project_v2-ollama-1 ollama pull qwen2.5:1.5b
```

---

## 9. Fichiers Clés du Projet

### Frontend (Flutter/Dart)

| Fichier                         | Rôle                                    |
|---------------------------------|-----------------------------------------|
| `lib/main.dart`                 | Point d'entrée, initialisation thème    |
| `lib/screens/splash_screen.dart`| Animation de démarrage                  |
| `lib/security/security_gate.dart`| Scan de sécurité au démarrage          |
| `lib/screens/dashboard_screen.dart`| Tableau de bord principal             |
| `lib/screens/apk_analysis_screen.dart`| Analyse de l'app installée        |
| `lib/screens/apk_report_screen.dart`| Rapport APK externe avec IA         |

### Couche de Sécurité

| Fichier                               | Rôle                                |
|---------------------------------------|-------------------------------------|
| `lib/security/security_manager.dart`  | Orchestrateur principal des scans   |
| `lib/security/security_service.dart`  | Communication avec le backend       |
| `lib/security/apk_info_collector.dart`| Collecte métadonnées APK via natif  |
| `lib/security/native_bridge.dart`     | Bridge vers les détecteurs Kotlin   |
| `lib/security/tflite_analyzer.dart`   | Analyse comportementale ML          |
| `lib/security/external_apk_scanner.dart`| Scan APK externes (file picker)   |
| `lib/security/secure_http_client.dart`| Client HTTP avec SSL pinning        |

### Backend (Python)

| Fichier                                  | Rôle                              |
|------------------------------------------|-----------------------------------|
| `backend/app/api/routes/security.py`     | Endpoints API de sécurité         |
| `backend/app/services/llm_analyzer.py`   | Interface avec Ollama/Qwen        |
| `backend/app/core/config.py`             | Configuration (modèle, URLs)      |

### Natif Android (Kotlin)

| Fichier                                    | Rôle                              |
|--------------------------------------------|-----------------------------------|
| `android/.../NativeSecurityPlugin.kt`      | Plugin MethodChannel Flutter      |
| `android/.../SecurityDetectors.kt`         | Implémentation des 9 détecteurs   |
