"""
Moteur de règles et système de scoring pour la détection de keyloggers
"""

import time
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
from rules.base_rule import BaseRule, RuleResult, RuleSeverity
from rules.api_rules import SuspiciousAPIRule, HookInstallationRule, MemoryAccessRule
from config.settings import SCORE_THRESHOLDS, BEHAVIOR_SCORES


class DetectionEvent:
    """Représente un événement de détection"""
    
    def __init__(self, event_type: str, data: Any, timestamp: float = None):
        self.event_type = event_type
        self.data = data
        self.timestamp = timestamp or time.time()
        self.processed = False
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            'event_type': self.event_type,
            'data': self.data,
            'timestamp': self.timestamp,
            'processed': self.processed
        }


class ProcessScore:
    """Score de risque pour un processus"""
    
    def __init__(self, process_name: str, process_pid: int):
        self.process_name = process_name
        self.process_pid = process_pid
        self.total_score = 0
        self.rule_results: List[RuleResult] = []
        self.events: List[DetectionEvent] = []
        self.first_seen = time.time()
        self.last_updated = time.time()
        self.risk_level = 'LOW'
    
    def add_rule_result(self, result: RuleResult):
        """Ajoute un résultat de règle"""
        if result.triggered:
            self.rule_results.append(result)
            self.total_score += result.score
            self.last_updated = time.time()
            self._update_risk_level()
    
    def add_event(self, event: DetectionEvent):
        """Ajoute un événement de détection"""
        self.events.append(event)
        self.last_updated = time.time()
    
    def _update_risk_level(self):
        """Met à jour le niveau de risque basé sur le score total"""
        if self.total_score >= SCORE_THRESHOLDS['CRITICAL']:
            self.risk_level = 'CRITICAL'
        elif self.total_score >= SCORE_THRESHOLDS['HIGH']:
            self.risk_level = 'HIGH'
        elif self.total_score >= SCORE_THRESHOLDS['MEDIUM']:
            self.risk_level = 'MEDIUM'
        else:
            self.risk_level = 'LOW'
    
    def is_suspicious(self) -> bool:
        """Détermine si le processus est suspect"""
        return self.total_score >= SCORE_THRESHOLDS['MEDIUM']
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            'process_name': self.process_name,
            'process_pid': self.process_pid,
            'total_score': self.total_score,
            'risk_level': self.risk_level,
            'rule_count': len(self.rule_results),
            'event_count': len(self.events),
            'first_seen': self.first_seen,
            'last_updated': self.last_updated,
            'is_suspicious': self.is_suspicious()
        }


class RulesEngine:
    """Moteur de règles pour la détection de keyloggers"""
    
    def __init__(self):
        self.rules: List[BaseRule] = []
        self.process_scores: Dict[int, ProcessScore] = {}
        self.detection_history: deque = deque(maxlen=1000)
        self.alert_threshold = SCORE_THRESHOLDS['HIGH']
        self.callbacks: List[callable] = []
        
        # Initialiser les règles par défaut
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialise les règles par défaut"""
        self.add_rule(SuspiciousAPIRule())
        self.add_rule(HookInstallationRule())
        self.add_rule(MemoryAccessRule())
    
    def add_rule(self, rule: BaseRule):
        """Ajoute une règle au moteur"""
        self.rules.append(rule)
        print(f"[RulesEngine] Règle ajoutée: {rule.name}")
    
    def remove_rule(self, rule_name: str):
        """Supprime une règle par nom"""
        self.rules = [rule for rule in self.rules if rule.name != rule_name]
        print(f"[RulesEngine] Règle supprimée: {rule_name}")
    
    def enable_rule(self, rule_name: str):
        """Active une règle"""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enable()
                print(f"[RulesEngine] Règle activée: {rule_name}")
                break
    
    def disable_rule(self, rule_name: str):
        """Désactive une règle"""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.disable()
                print(f"[RulesEngine] Règle désactivée: {rule_name}")
                break
    
    def add_callback(self, callback: callable):
        """Ajoute un callback pour les alertes"""
        self.callbacks.append(callback)
    
    def process_event(self, event: DetectionEvent):
        """Traite un événement de détection"""
        try:
            # Ajouter l'événement à l'historique
            self.detection_history.append(event)
            
            # Traiter selon le type d'événement
            if event.event_type == 'new_process':
                self._process_new_process(event.data)
            elif event.event_type == 'api_scan':
                self._process_api_scan(event.data)
            elif event.event_type == 'file_activity':
                self._process_file_activity(event.data)
            elif event.event_type == 'network_connection':
                self._process_network_connection(event.data)
            elif event.event_type == 'persistence_method':
                self._process_persistence_method(event.data)
            
            event.processed = True
            
        except Exception as e:
            print(f"[RulesEngine] Erreur lors du traitement de l'événement: {e}")
    
    def _process_new_process(self, process_data):
        """Traite un nouveau processus"""
        process_name = process_data.get('name', 'Unknown')
        process_pid = process_data.get('pid', 0)
        
        # Créer ou mettre à jour le score du processus
        if process_pid not in self.process_scores:
            self.process_scores[process_pid] = ProcessScore(process_name, process_pid)
        
        process_score = self.process_scores[process_pid]
        process_score.add_event(DetectionEvent('new_process', process_data))
        
        # Vérifier si le processus est suspect dès le départ
        if self._is_suspicious_process_name(process_name):
            result = RuleResult(
                rule_name="SuspiciousProcessName",
                triggered=True,
                score=BEHAVIOR_SCORES['SUSPICIOUS_API'],
                severity=RuleSeverity.MEDIUM,
                details=f"Nom de processus suspect: {process_name}",
                evidence={'process_name': process_name, 'process_pid': process_pid}
            )
            process_score.add_rule_result(result)
    
    def _process_api_scan(self, api_data):
        """Traite les résultats d'un scan d'API"""
        process_pid = api_data.get('process_pid', 0)
        if process_pid not in self.process_scores:
            return
        
        process_score = self.process_scores[process_pid]
        process_score.add_event(DetectionEvent('api_scan', api_data))
        
        # Appliquer les règles d'API
        for rule in self.rules:
            if isinstance(rule, (SuspiciousAPIRule, HookInstallationRule, MemoryAccessRule)):
                result = rule.check({'process': api_data})
                if result.triggered:
                    process_score.add_rule_result(result)
    
    def _process_file_activity(self, file_activity):
        """Traite une activité de fichier"""
        process_pid = file_activity.process_pid
        if process_pid not in self.process_scores:
            return
        
        process_score = self.process_scores[process_pid]
        process_score.add_event(DetectionEvent('file_activity', file_activity))
        
        # Si l'activité est suspecte, ajouter des points
        if file_activity.is_suspicious():
            result = RuleResult(
                rule_name="SuspiciousFileActivity",
                triggered=True,
                score=BEHAVIOR_SCORES['FILE_WRITE'],
                severity=RuleSeverity.HIGH,
                details=f"Activité de fichier suspecte: {file_activity.file_path}",
                evidence=file_activity.to_dict()
            )
            process_score.add_rule_result(result)
    
    def _process_network_connection(self, network_connection):
        """Traite une connexion réseau"""
        process_pid = network_connection.pid
        if process_pid not in self.process_scores:
            return
        
        process_score = self.process_scores[process_pid]
        process_score.add_event(DetectionEvent('network_connection', network_connection))
        
        # Si la connexion est suspecte, ajouter des points
        if network_connection.is_suspicious():
            result = RuleResult(
                rule_name="SuspiciousNetworkConnection",
                triggered=True,
                score=BEHAVIOR_SCORES['NETWORK_COMM'],
                severity=RuleSeverity.HIGH,
                details=f"Connexion réseau suspecte: {network_connection.raddr}",
                evidence=network_connection.to_dict()
            )
            process_score.add_rule_result(result)
    
    def _process_persistence_method(self, persistence_method):
        """Traite une méthode de persistance"""
        # Créer un événement global pour la persistance
        event = DetectionEvent('persistence_method', persistence_method)
        
        # Si la méthode est suspecte, créer une alerte
        if persistence_method.is_suspicious():
            result = RuleResult(
                rule_name="PersistenceMethod",
                triggered=True,
                score=BEHAVIOR_SCORES['PERSISTENCE'],
                severity=RuleSeverity.CRITICAL,
                details=f"Méthode de persistance détectée: {persistence_method.method_type}",
                evidence=persistence_method.to_dict()
            )
            
            # Créer un score global pour la persistance
            global_pid = -1  # PID spécial pour les événements globaux
            if global_pid not in self.process_scores:
                self.process_scores[global_pid] = ProcessScore("System", global_pid)
            
            self.process_scores[global_pid].add_rule_result(result)
    
    def _is_suspicious_process_name(self, process_name: str) -> bool:
        """Détermine si un nom de processus est suspect"""
        suspicious_names = [
            'keylog', 'logger', 'spy', 'monitor', 'hook', 'capture',
            'record', 'track', 'steal', 'grab', 'sniff'
        ]
        
        process_name_lower = process_name.lower()
        return any(name in process_name_lower for name in suspicious_names)
    
    def get_suspicious_processes(self) -> List[ProcessScore]:
        """Retourne la liste des processus suspects"""
        return [score for score in self.process_scores.values() 
                if score.is_suspicious()]
    
    def get_process_score(self, process_pid: int) -> Optional[ProcessScore]:
        """Retourne le score d'un processus spécifique"""
        return self.process_scores.get(process_pid)
    
    def get_high_risk_processes(self) -> List[ProcessScore]:
        """Retourne les processus à haut risque"""
        return [score for score in self.process_scores.values() 
                if score.risk_level in ['HIGH', 'CRITICAL']]
    
    def get_detection_summary(self) -> Dict:
        """Retourne un résumé des détections"""
        total_processes = len(self.process_scores)
        suspicious_processes = len(self.get_suspicious_processes())
        high_risk_processes = len(self.get_high_risk_processes())
        
        risk_distribution = defaultdict(int)
        for score in self.process_scores.values():
            risk_distribution[score.risk_level] += 1
        
        return {
            'total_processes': total_processes,
            'suspicious_processes': suspicious_processes,
            'high_risk_processes': high_risk_processes,
            'risk_distribution': dict(risk_distribution),
            'total_events': len(self.detection_history),
            'active_rules': len([rule for rule in self.rules if rule.enabled])
        }
    
    def check_alerts(self):
        """Vérifie s'il y a des alertes à déclencher"""
        high_risk_processes = self.get_high_risk_processes()
        
        for process_score in high_risk_processes:
            if process_score.total_score >= self.alert_threshold:
                self._trigger_alert(process_score)
    
    def _trigger_alert(self, process_score: ProcessScore):
        """Déclenche une alerte pour un processus"""
        alert_data = {
            'type': 'HIGH_RISK_PROCESS',
            'process_name': process_score.process_name,
            'process_pid': process_score.process_pid,
            'total_score': process_score.total_score,
            'risk_level': process_score.risk_level,
            'rule_results': [result.__dict__ for result in process_score.rule_results],
            'timestamp': time.time()
        }
        
        # Notifier tous les callbacks
        for callback in self.callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                print(f"[RulesEngine] Erreur dans callback d'alerte: {e}")
    
    def cleanup_old_processes(self, max_age: float = 3600):
        """Nettoie les anciens processus (plus de max_age secondes)"""
        current_time = time.time()
        old_pids = []
        
        for pid, score in self.process_scores.items():
            if current_time - score.last_updated > max_age:
                old_pids.append(pid)
        
        for pid in old_pids:
            del self.process_scores[pid]
        
        if old_pids:
            print(f"[RulesEngine] {len(old_pids)} anciens processus nettoyés")
