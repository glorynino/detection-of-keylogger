# Exemples de Règles et Utilisation

## Règles Prêtes à l'Emploi

### 1. Règles d'API Suspectes

#### SuspiciousAPIRule
```python
# Détecte l'utilisation d'API suspectes
from rules.api_rules import SuspiciousAPIRule

rule = SuspiciousAPIRule()
# Score: 10 points par API suspecte
# APIs surveillées: SetWindowsHookEx, GetAsyncKeyState, ReadProcessMemory, etc.
```

#### HookInstallationRule
```python
# Détecte l'installation de hooks système
from rules.api_rules import HookInstallationRule

rule = HookInstallationRule()
# Score: 15 points
# Détecte: SetWindowsHookEx, SetWindowsHookExA, SetWindowsHookExW
```

#### MemoryAccessRule
```python
# Détecte l'accès suspect à la mémoire
from rules.api_rules import MemoryAccessRule

rule = MemoryAccessRule()
# Score: 20 points
# Détecte: ReadProcessMemory, WriteProcessMemory, VirtualAllocEx
```

### 2. Règles Comportementales

#### SuspiciousProcessNameRule
```python
# Détecte les processus avec des noms suspects
from rules.behavior_rules import SuspiciousProcessNameRule

rule = SuspiciousProcessNameRule()
# Score: 15 points
# Mots-clés: keylog, logger, spy, monitor, hook, capture, etc.
```

#### SuspiciousPathRule
```python
# Détecte les processus exécutés depuis des chemins suspects
from rules.behavior_rules import SuspiciousPathRule

rule = SuspiciousPathRule()
# Score: 20 points
# Chemins: %TEMP%, %APPDATA%, %LOCALAPPDATA%, temp, tmp, etc.
```

#### HighCPUUsageRule
```python
# Détecte les processus avec utilisation CPU élevée
from rules.behavior_rules import HighCPUUsageRule

rule = HighCPUUsageRule()
# Score: 10 points
# Seuil: > 50% CPU
```

### 3. Règles de Persistance

#### RegistryPersistenceRule
```python
# Détecte la persistance via le registre
from rules.persistence_rules import RegistryPersistenceRule

rule = RegistryPersistenceRule()
# Score: 25 points
# Surveille: Run, RunOnce, RunServices, Winlogon
```

#### ServicePersistenceRule
```python
# Détecte les services de persistance
from rules.persistence_rules import ServicePersistenceRule

rule = ServicePersistenceRule()
# Score: 30 points
# Surveille: Services Windows suspects
```

## Configuration des Seuils

### Seuils de Scoring
```python
# Dans config/settings.py
SCORE_THRESHOLDS = {
    'LOW': 10,      # Alerte faible
    'MEDIUM': 20,   # Alerte moyenne
    'HIGH': 30,     # Alerte élevée
    'CRITICAL': 50  # Alerte critique
}
```

### Scores par Comportement
```python
BEHAVIOR_SCORES = {
    'SUSPICIOUS_API': 10,      # API suspecte
    'FILE_WRITE': 15,          # Écriture de fichier suspecte
    'NETWORK_COMM': 20,        # Communication réseau suspecte
    'PERSISTENCE': 25,         # Méthode de persistance
    'DLL_INJECTION': 30,       # Injection de DLL
    'HOOK_INSTALLATION': 15    # Installation de hook
}
```

## Exemples d'Utilisation

### 1. Utilisation Basique
```python
from core.agent import KeyloggerDetectorAgent

# Créer l'agent
agent = KeyloggerDetectorAgent()

# Démarrer la surveillance
agent.start()

# Obtenir un résumé
summary = agent.get_detection_summary()
print(f"Processus suspects: {summary['rules_summary']['suspicious_processes']}")

# Arrêter la surveillance
agent.stop()
```

### 2. Mode Console
```bash
# Lancer en mode console
python main.py

# Lancer en mode test (30 secondes)
python main.py --test
```

### 3. Mode Interface Graphique
```bash
# Lancer l'interface graphique
python main.py --gui
```

### 4. Ajout de Règles Personnalisées
```python
from rules.base_rule import BaseRule, RuleResult, RuleSeverity

class CustomRule(BaseRule):
    def __init__(self):
        super().__init__(
            name="CustomRule",
            description="Règle personnalisée",
            score=20,
            severity=RuleSeverity.HIGH
        )
    
    def check(self, data):
        # Logique de détection personnalisée
        if self._is_suspicious(data):
            return RuleResult(
                rule_name=self.name,
                triggered=True,
                score=self.score,
                severity=self.severity,
                details="Comportement suspect détecté"
            )
        return RuleResult(self.name, False, 0, self.severity)
    
    def _is_suspicious(self, data):
        # Implémentation de la logique
        return False

# Ajouter la règle au moteur
agent = KeyloggerDetectorAgent()
agent.get_rules_engine().add_rule(CustomRule())
```

## Exemples de Détection

### 1. Keylogger Simple
```
Processus: keylogger.exe (PID: 1234)
Score: 45 points
Déclenchements:
- SuspiciousProcessName: 15 points (nom suspect)
- SuspiciousPath: 20 points (exécution depuis %TEMP%)
- SuspiciousAPI: 10 points (GetAsyncKeyState)
Risque: HIGH
```

### 2. Keylogger Avancé
```
Processus: system_monitor.exe (PID: 5678)
Score: 75 points
Déclenchements:
- HookInstallation: 15 points (SetWindowsHookEx)
- MemoryAccess: 20 points (ReadProcessMemory)
- RegistryPersistence: 25 points (Run key)
- ServicePersistence: 30 points (service caché)
Risque: CRITICAL
```

### 3. Faux Positif
```
Processus: notepad.exe (PID: 9012)
Score: 0 points
Déclenchements: Aucun
Risque: LOW
```

## Configuration Avancée

### 1. Personnalisation des Chemins Surveillés
```python
# Dans core/file_monitor.py
self.watch_paths = [
    os.path.expandvars('%TEMP%'),
    os.path.expandvars('%APPDATA%'),
    'C:\\Custom\\Suspicious\\Path'  # Ajouter un chemin personnalisé
]
```

### 2. Personnalisation des APIs Surveillées
```python
# Dans config/settings.py
SUSPICIOUS_APIS = [
    'SetWindowsHookEx',
    'GetAsyncKeyState',
    'CustomAPI',  # Ajouter une API personnalisée
    # ...
]
```

### 3. Personnalisation des Ports Suspects
```python
# Dans config/settings.py
SUSPICIOUS_PORTS = [
    80, 443, 8080, 8443,
    1234,  # Ajouter un port personnalisé
    # ...
]
```

## Tests et Validation

### 1. Exécution des Tests
```bash
# Lancer tous les tests
python -m pytest tests/

# Lancer un test spécifique
python tests/test_rules.py
```

### 2. Test d'une Règle
```python
from tests.test_rules import TestAPIRules
import unittest

# Créer et exécuter un test
test = TestAPIRules()
test.setUp()
test.test_rule_initialization()
```

## Surveillance en Production

### 1. Logs
```python
from alerts.logger import security_logger

# Logs automatiques dans keylogger_detector.log
# Rotation automatique (10MB, 5 fichiers de sauvegarde)
```

### 2. Alertes
```python
from alerts.alert_manager import AlertManager

alert_manager = AlertManager()

# Alertes automatiques selon les seuils
# Export possible en JSON
```

### 3. Interface Graphique
- Surveillance en temps réel
- Filtrage des alertes
- Statistiques détaillées
- Export des données
