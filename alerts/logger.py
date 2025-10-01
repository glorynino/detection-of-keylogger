"""
Système de logs pour le détecteur de keyloggers
"""

import logging
import os
import time
from logging.handlers import RotatingFileHandler
from typing import Dict, Any
from config.settings import LOG_CONFIG


class SecurityLogger:
    """Logger spécialisé pour les événements de sécurité"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file or LOG_CONFIG['file']
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """Configure le logger"""
        logger = logging.getLogger('KeyloggerDetector')
        logger.setLevel(getattr(logging, LOG_CONFIG['level']))
        
        # Éviter les doublons de handlers
        if logger.handlers:
            return logger
        
        # Handler pour fichier avec rotation
        file_handler = RotatingFileHandler(
            self.log_file,
            maxBytes=LOG_CONFIG['max_size'],
            backupCount=LOG_CONFIG['backup_count'],
            encoding='utf-8'
        )
        
        # Handler pour console
        console_handler = logging.StreamHandler()
        
        # Format des logs
        formatter = logging.Formatter(LOG_CONFIG['format'])
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Ajouter les handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def log_detection(self, detection_type: str, process_name: str, 
                     process_pid: int, details: str, evidence: Dict = None):
        """Log une détection de keylogger"""
        message = f"DETECTION [{detection_type}] Process: {process_name} (PID: {process_pid}) - {details}"
        
        if evidence:
            message += f" | Evidence: {evidence}"
        
        self.logger.warning(message)
    
    def log_alert(self, alert_type: str, title: str, severity: str, 
                 process_name: str = "", process_pid: int = 0):
        """Log une alerte"""
        message = f"ALERT [{alert_type}] {severity} - {title}"
        
        if process_name:
            message += f" | Process: {process_name} (PID: {process_pid})"
        
        if severity == 'CRITICAL':
            self.logger.critical(message)
        elif severity == 'HIGH':
            self.logger.error(message)
        elif severity == 'MEDIUM':
            self.logger.warning(message)
        else:
            self.logger.info(message)
    
    def log_process_activity(self, activity_type: str, process_name: str, 
                           process_pid: int, details: str = ""):
        """Log une activité de processus"""
        message = f"PROCESS [{activity_type}] {process_name} (PID: {process_pid})"
        
        if details:
            message += f" - {details}"
        
        self.logger.info(message)
    
    def log_file_activity(self, file_path: str, activity_type: str, 
                         process_name: str, process_pid: int):
        """Log une activité de fichier"""
        message = f"FILE [{activity_type}] {file_path} | Process: {process_name} (PID: {process_pid})"
        self.logger.info(message)
    
    def log_network_activity(self, connection_type: str, remote_address: str, 
                           process_name: str, process_pid: int):
        """Log une activité réseau"""
        message = f"NETWORK [{connection_type}] {remote_address} | Process: {process_name} (PID: {process_pid})"
        self.logger.info(message)
    
    def log_persistence_detection(self, method_type: str, location: str, 
                                value: str, risk_score: int):
        """Log une détection de persistance"""
        message = f"PERSISTENCE [{method_type}] Location: {location} | Value: {value} | Risk: {risk_score}"
        self.logger.warning(message)
    
    def log_api_usage(self, api_name: str, process_name: str, 
                     process_pid: int, module_path: str = ""):
        """Log l'utilisation d'une API suspecte"""
        message = f"API [{api_name}] Process: {process_name} (PID: {process_pid})"
        
        if module_path:
            message += f" | Module: {module_path}"
        
        self.logger.warning(message)
    
    def log_system_event(self, event_type: str, message: str, level: str = "INFO"):
        """Log un événement système"""
        log_message = f"SYSTEM [{event_type}] {message}"
        
        if level == "ERROR":
            self.logger.error(log_message)
        elif level == "WARNING":
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def log_rule_triggered(self, rule_name: str, process_name: str, 
                          process_pid: int, score: int, details: str = ""):
        """Log le déclenchement d'une règle"""
        message = f"RULE [{rule_name}] Process: {process_name} (PID: {process_pid}) | Score: {score}"
        
        if details:
            message += f" | Details: {details}"
        
        self.logger.warning(message)
    
    def log_summary(self, summary_data: Dict[str, Any]):
        """Log un résumé des activités"""
        message = f"SUMMARY | Processes: {summary_data.get('total_processes', 0)} | " \
                 f"Suspicious: {summary_data.get('suspicious_processes', 0)} | " \
                 f"High Risk: {summary_data.get('high_risk_processes', 0)} | " \
                 f"Alerts: {summary_data.get('total_alerts', 0)}"
        
        self.logger.info(message)
    
    def get_log_file_path(self) -> str:
        """Retourne le chemin du fichier de log"""
        return os.path.abspath(self.log_file)
    
    def clear_logs(self):
        """Efface les logs actuels"""
        try:
            with open(self.log_file, 'w') as f:
                f.write("")
            self.logger.info("Logs effacés")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'effacement des logs: {e}")


# Instance globale du logger
security_logger = SecurityLogger()
