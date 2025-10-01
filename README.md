# Système de Détection de Keyloggers

## Description
Un agent de sécurité qui surveille et détecte les keyloggers en temps réel basé sur des règles comportementales.

## Architecture

```
keylogger_detector/
├── core/
│   ├── agent.py              # Agent principal de surveillance
│   ├── process_monitor.py    # Surveillance des processus
│   ├── api_detector.py       # Détection d'API suspectes
│   ├── file_monitor.py       # Surveillance fichiers/réseau
│   ├── persistence_check.py  # Vérification de persistance
│   └── rules_engine.py       # Moteur de règles et scoring
├── rules/
│   ├── __init__.py
│   ├── base_rule.py          # Classe de base pour les règles
│   ├── api_rules.py          # Règles pour API suspectes
│   ├── behavior_rules.py     # Règles comportementales
│   └── persistence_rules.py  # Règles de persistance
├── alerts/
│   ├── __init__.py
│   ├── alert_manager.py      # Gestionnaire d'alertes
│   └── logger.py             # Système de logs
├── gui/
│   └── main_window.py        # Interface graphique
├── config/
│   └── settings.py           # Configuration
├── tests/
│   └── test_rules.py         # Tests unitaires
├── main.py                   # Point d'entrée principal
└── requirements.txt          # Dépendances
```

## Fonctionnalités

### 1. Surveillance des Processus
- Liste des processus en cours
- Détection de nouveaux processus
- Analyse des chemins d'exécution

### 2. Détection d'API Suspectes
- SetWindowsHookEx (hooks clavier/souris)
- GetAsyncKeyState (lecture clavier)
- ReadProcessMemory (lecture mémoire)
- SetWindowsHookExA/W (hooks Unicode/ANSI)

### 3. Surveillance Fichiers/Réseau
- Détection d'écriture de frappes dans fichiers
- Surveillance des connexions réseau suspectes
- Analyse des patterns de communication

### 4. Vérification de Persistance
- Autostart (registre Windows)
- Services cachés
- Exécution depuis %TEMP%
- DLL injection

### 5. Moteur de Règles
- Système de scoring basé sur des règles
- Seuils d'alerte configurables
- Règles modulaires et extensibles

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

```bash
# Mode console
python main.py

# Mode GUI
python main.py --gui
```

## Règles de Détection

Le système utilise des règles prédéfinies pour détecter les comportements suspects :

- **Score API** : +10 points par API suspecte utilisée
- **Score Fichier** : +15 points si écriture de frappes détectée
- **Score Réseau** : +20 points si communication suspecte
- **Score Persistance** : +25 points si tentative de persistance

**Seuil d'alerte** : 30 points (configurable)
