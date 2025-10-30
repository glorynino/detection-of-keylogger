"""
Gestionnaire d'alertes pour le système de détection de keyloggers
"""

import time
import json
from typing import Dict, List, Any, Optional
from enum import Enum
from collections import deque

# Notification Windows (optionnelle)
try:
    from win10toast import ToastNotifier
    _toaster = ToastNotifier()
except Exception:
    _toaster = None


class AlertSeverity(Enum):
    """Niveaux de sévérité des alertes"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Alert:
    """Représente une alerte de sécurité"""
    
    def __init__(self, alert_type: str, title: str, description: str, 
                 severity: AlertSeverity, process_name: str = "", 
                 process_pid: int = 0, evidence: Dict = None):
        self.alert_id = self._generate_alert_id()
        self.alert_type = alert_type
        self.title = title
        self.description = description
        self.severity = severity
        self.process_name = process_name
        self.process_pid = process_pid
        self.evidence = evidence or {}
        self.timestamp = time.time()
        self.acknowledged = False
        self.resolved = False
    
    def _generate_alert_id(self) -> str:
        """Génère un ID unique pour l'alerte"""
        return f"ALERT_{int(time.time() * 1000)}"
    
    def acknowledge(self):
        """Marque l'alerte comme acquittée"""
        self.acknowledged = True
    
    def resolve(self):
        """Marque l'alerte comme résolue"""
        self.resolved = True
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            'alert_id': self.alert_id,
            'alert_type': self.alert_type,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.name,
            'process_name': self.process_name,
            'process_pid': self.process_pid,
            'evidence': self.evidence,
            'timestamp': self.timestamp,
            'acknowledged': self.acknowledged,
            'resolved': self.resolved
        }
    
    def __str__(self):
        return f"[{self.severity.name}] {self.title} - {self.process_name} (PID: {self.process_pid})"


class AlertManager:
    """Gestionnaire central des alertes"""
    
    def __init__(self, max_alerts: int = 1000):
        self.alerts: deque = deque(maxlen=max_alerts)
        self.alert_callbacks: List[callable] = []
        self.alert_counters = {
            'total': 0,
            'low': 0,
            'medium': 0,
            'high': 0,
            'critical': 0
        }
    
    def add_callback(self, callback: callable):
        """Ajoute un callback pour les nouvelles alertes"""
        self.alert_callbacks.append(callback)
    
    def create_alert(self, alert_type: str, title: str, description: str,
                    severity: AlertSeverity, process_name: str = "",
                    process_pid: int = 0, evidence: Dict = None) -> Alert:
        """Crée une nouvelle alerte"""
        alert = Alert(
            alert_type=alert_type,
            title=title,
            description=description,
            severity=severity,
            process_name=process_name,
            process_pid=process_pid,
            evidence=evidence
        )
        
        self.alerts.append(alert)
        self._update_counters(severity)
        self._notify_callbacks(alert)
        
        return alert
    
    def create_keylogger_alert(self, process_name: str, process_pid: int, 
                              score: int, evidence: Dict) -> Alert:
        """Crée une alerte spécifique pour un keylogger détecté"""
        severity = self._determine_severity(score)
        
        title = f"Keylogger suspect détecté: {process_name}"
        description = f"Le processus {process_name} (PID: {process_pid}) présente des " \
                     f"comportements suspects de keylogger. Score de risque: {score}"
        
        alert = self.create_alert(
            alert_type="KEYLOGGER_DETECTED",
            title=title,
            description=description,
            severity=severity,
            process_name=process_name,
            process_pid=process_pid,
            evidence=evidence
        )

        # Afficher une notification Windows si possible (win10toast)
        if _toaster:
            try:
                # titre court + description
                _toaster.show_toast(title, description, duration=6, threaded=True)
            except Exception:
                # ne pas faire planter l'agent si la notification échoue
                pass

        return alert
    
    def create_api_alert(self, process_name: str, process_pid: int, 
                        suspicious_apis: List[str]) -> Alert:
        """Crée une alerte pour l'utilisation d'API suspectes"""
        title = f"API suspectes détectées: {process_name}"
        description = f"Le processus {process_name} (PID: {process_pid}) utilise " \
                     f"des API suspectes: {', '.join(suspicious_apis)}"
        
        evidence = {
            'suspicious_apis': suspicious_apis,
            'process_name': process_name,
            'process_pid': process_pid
        }
        
        return self.create_alert(
            alert_type="SUSPICIOUS_API",
            title=title,
            description=description,
            severity=AlertSeverity.HIGH,
            process_name=process_name,
            process_pid=process_pid,
            evidence=evidence
        )
    
    def create_file_alert(self, file_path: str, process_name: str, 
                         process_pid: int, activity_type: str) -> Alert:
        """Crée une alerte pour une activité de fichier suspecte"""
        title = f"Activité de fichier suspecte: {process_name}"
        description = f"Le processus {process_name} (PID: {process_pid}) a effectué " \
                     f"une activité suspecte sur le fichier: {file_path}"
        
        evidence = {
            'file_path': file_path,
            'activity_type': activity_type,
            'process_name': process_name,
            'process_pid': process_pid
        }
        
        return self.create_alert(
            alert_type="SUSPICIOUS_FILE_ACTIVITY",
            title=title,
            description=description,
            severity=AlertSeverity.MEDIUM,
            process_name=process_name,
            process_pid=process_pid,
            evidence=evidence
        )
    
    def create_persistence_alert(self, method_type: str, location: str, 
                               value: str) -> Alert:
        """Crée une alerte pour une méthode de persistance"""
        title = f"Méthode de persistance détectée: {method_type}"
        description = f"Une méthode de persistance de type {method_type} a été " \
                     f"détectée à l'emplacement: {location}"
        
        evidence = {
            'method_type': method_type,
            'location': location,
            'value': value
        }
        
        return self.create_alert(
            alert_type="PERSISTENCE_METHOD",
            title=title,
            description=description,
            severity=AlertSeverity.CRITICAL,
            evidence=evidence
        )
    
    def create_network_alert(self, process_name: str, process_pid: int, 
                           remote_address: str, port: int) -> Alert:
        """Crée une alerte pour une connexion réseau suspecte"""
        title = f"Connexion réseau suspecte: {process_name}"
        description = f"Le processus {process_name} (PID: {process_pid}) a établi " \
                     f"une connexion suspecte vers {remote_address}:{port}"
        
        evidence = {
            'remote_address': remote_address,
            'port': port,
            'process_name': process_name,
            'process_pid': process_pid
        }
        
        return self.create_alert(
            alert_type="SUSPICIOUS_NETWORK",
            title=title,
            description=description,
            severity=AlertSeverity.HIGH,
            process_name=process_name,
            process_pid=process_pid,
            evidence=evidence
        )
    
    def _determine_severity(self, score: int) -> AlertSeverity:
        """Détermine la sévérité basée sur le score"""
        if score >= 50:
            return AlertSeverity.CRITICAL
        elif score >= 30:
            return AlertSeverity.HIGH
        elif score >= 15:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    def _update_counters(self, severity: AlertSeverity):
        """Met à jour les compteurs d'alertes"""
        self.alert_counters['total'] += 1
        self.alert_counters[severity.name.lower()] += 1
    
    def _notify_callbacks(self, alert: Alert):
        """Notifie tous les callbacks d'une nouvelle alerte"""
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"[AlertManager] Erreur dans callback d'alerte: {e}")
    
    def get_alerts(self, severity: Optional[AlertSeverity] = None, 
                  acknowledged: Optional[bool] = None,
                  resolved: Optional[bool] = None) -> List[Alert]:
        """Retourne les alertes selon les critères"""
        filtered_alerts = []
        
        for alert in self.alerts:
            if severity and alert.severity != severity:
                continue
            if acknowledged is not None and alert.acknowledged != acknowledged:
                continue
            if resolved is not None and alert.resolved != resolved:
                continue
            
            filtered_alerts.append(alert)
        
        return filtered_alerts
    
    def get_unacknowledged_alerts(self) -> List[Alert]:
        """Retourne les alertes non acquittées"""
        return self.get_alerts(acknowledged=False)
    
    def get_critical_alerts(self) -> List[Alert]:
        """Retourne les alertes critiques"""
        return self.get_alerts(severity=AlertSeverity.CRITICAL)
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acquitte une alerte par son ID"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.acknowledge()
                return True
        return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Résout une alerte par son ID"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.resolve()
                return True
        return False
    
    def get_alert_summary(self) -> Dict:
        """Retourne un résumé des alertes"""
        total_alerts = len(self.alerts)
        unacknowledged = len(self.get_unacknowledged_alerts())
        critical = len(self.get_critical_alerts())
        
        return {
            'total_alerts': total_alerts,
            'unacknowledged_alerts': unacknowledged,
            'critical_alerts': critical,
            'alert_counters': self.alert_counters.copy(),
            'recent_alerts': [alert.to_dict() for alert in list(self.alerts)[-10:]]
        }
    
    def export_alerts(self, filepath: str):
        """Exporte les alertes vers un fichier JSON"""
        alerts_data = [alert.to_dict() for alert in self.alerts]
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(alerts_data, f, indent=2, ensure_ascii=False)
        
        print(f"[AlertManager] {len(alerts_data)} alertes exportées vers {filepath}")
    
    def clear_old_alerts(self, max_age_hours: int = 24):
        """Supprime les anciennes alertes"""
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        
        old_alerts = []
        for alert in self.alerts:
            if current_time - alert.timestamp > max_age_seconds:
                old_alerts.append(alert)
        
        for alert in old_alerts:
            self.alerts.remove(alert)
        
        if old_alerts:
            print(f"[AlertManager] {len(old_alerts)} anciennes alertes supprimées")
