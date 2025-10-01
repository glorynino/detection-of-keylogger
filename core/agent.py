"""
Agent principal de surveillance et détection de keyloggers
"""

import time
import threading
from typing import Dict, List, Any, Optional
from core.process_monitor import ProcessMonitor, ProcessInfo
from core.api_detector import APIDetector
from core.file_monitor import FileMonitor, FileActivity, NetworkConnection
from core.persistence_check import PersistenceChecker, PersistenceMethod
from core.rules_engine import RulesEngine, DetectionEvent
from alerts.alert_manager import AlertManager, AlertSeverity
from alerts.logger import security_logger
from config.settings import MONITOR_CONFIG


class KeyloggerDetectorAgent:
    """Agent principal de détection de keyloggers"""
    
    def __init__(self):
        # Composants du système
        self.process_monitor = ProcessMonitor(MONITOR_CONFIG['process_check_interval'])
        self.api_detector = APIDetector()
        self.file_monitor = FileMonitor(MONITOR_CONFIG['file_check_interval'])
        self.persistence_checker = PersistenceChecker()
        self.rules_engine = RulesEngine()
        self.alert_manager = AlertManager()
        
        # État de l'agent
        self.running = False
        self.scan_thread = None
        self.api_scan_thread = None
        self.persistence_scan_thread = None
        
        # Configuration
        self.scan_interval = MONITOR_CONFIG['scan_interval']
        self.api_scan_interval = 30  # secondes
        self.persistence_scan_interval = 300  # 5 minutes
        
        # Statistiques
        self.stats = {
            'start_time': None,
            'total_scans': 0,
            'processes_scanned': 0,
            'alerts_generated': 0,
            'keyloggers_detected': 0
        }
        
        # Configurer les callbacks
        self._setup_callbacks()
    
    def _setup_callbacks(self):
        """Configure les callbacks entre les composants"""
        # Callback pour les nouveaux processus
        self.process_monitor.add_callback(self._on_process_change)
        
        # Callback pour les activités de fichiers
        self.file_monitor.add_callback(self._on_file_activity)
        
        # Callback pour les alertes du moteur de règles
        self.rules_engine.add_callback(self._on_rules_alert)
        
        # Callback pour les nouvelles alertes
        self.alert_manager.add_callback(self._on_new_alert)
    
    def start(self):
        """Démarre l'agent de surveillance"""
        if self.running:
            return
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Démarrer les composants
        self.process_monitor.start()
        self.file_monitor.start()
        
        # Démarrer les threads de scan
        self.scan_thread = threading.Thread(target=self._main_scan_loop, daemon=True)
        self.scan_thread.start()
        
        self.api_scan_thread = threading.Thread(target=self._api_scan_loop, daemon=True)
        self.api_scan_thread.start()
        
        self.persistence_scan_thread = threading.Thread(target=self._persistence_scan_loop, daemon=True)
        self.persistence_scan_thread.start()
        
        security_logger.log_system_event("AGENT", "Agent de surveillance démarré", "INFO")
        print("[Agent] Surveillance démarrée")
    
    def stop(self):
        """Arrête l'agent de surveillance"""
        if not self.running:
            return
        
        self.running = False
        
        # Arrêter les composants
        self.process_monitor.stop()
        self.file_monitor.stop()
        
        # Attendre que les threads se terminent
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        if self.api_scan_thread:
            self.api_scan_thread.join(timeout=5)
        if self.persistence_scan_thread:
            self.persistence_scan_thread.join(timeout=5)
        
        security_logger.log_system_event("AGENT", "Agent de surveillance arrêté", "INFO")
        print("[Agent] Surveillance arrêtée")
    
    def _main_scan_loop(self):
        """Boucle principale de scan"""
        while self.running:
            try:
                self._perform_main_scan()
                time.sleep(self.scan_interval)
            except Exception as e:
                security_logger.log_system_event("ERROR", f"Erreur dans la boucle principale: {e}", "ERROR")
                time.sleep(self.scan_interval)
    
    def _api_scan_loop(self):
        """Boucle de scan des API"""
        while self.running:
            try:
                self._perform_api_scan()
                time.sleep(self.api_scan_interval)
            except Exception as e:
                security_logger.log_system_event("ERROR", f"Erreur dans le scan API: {e}", "ERROR")
                time.sleep(self.api_scan_interval)
    
    def _persistence_scan_loop(self):
        """Boucle de scan de persistance"""
        while self.running:
            try:
                self._perform_persistence_scan()
                time.sleep(self.persistence_scan_interval)
            except Exception as e:
                security_logger.log_system_event("ERROR", f"Erreur dans le scan de persistance: {e}", "ERROR")
                time.sleep(self.persistence_scan_interval)
    
    def _perform_main_scan(self):
        """Effectue un scan principal"""
        self.stats['total_scans'] += 1
        
        # Vérifier les alertes
        self.rules_engine.check_alerts()
        
        # Nettoyer les anciens processus
        self.rules_engine.cleanup_old_processes()
        
        # Log du résumé périodique
        if self.stats['total_scans'] % 10 == 0:  # Toutes les 10 scans
            self._log_summary()
    
    def _perform_api_scan(self):
        """Effectue un scan des API pour tous les processus"""
        try:
            processes = self.process_monitor.get_processes()
            self.stats['processes_scanned'] += len(processes)
            
            for process_info in processes.values():
                try:
                    # Créer un objet psutil.Process pour l'API detector
                    import psutil
                    process = psutil.Process(process_info.pid)
                    
                    # Scanner les API
                    api_results = self.api_detector.scan_process(process)
                    
                    # Créer un événement pour le moteur de règles
                    event = DetectionEvent('api_scan', api_results)
                    self.rules_engine.process_event(event)
                    
                    # Log si des API suspectes sont détectées
                    if api_results.get('suspicious_apis'):
                        security_logger.log_api_usage(
                            ', '.join([api['name'] for api in api_results['suspicious_apis']]),
                            process_info.name,
                            process_info.pid
                        )
                    
                except Exception as e:
                    continue  # Ignorer les erreurs sur des processus individuels
                    
        except Exception as e:
            security_logger.log_system_event("ERROR", f"Erreur lors du scan API: {e}", "ERROR")
    
    def _perform_persistence_scan(self):
        """Effectue un scan de persistance"""
        try:
            methods = self.persistence_checker.check_all_persistence_methods()
            
            for method in methods:
                if method.is_suspicious():
                    # Créer un événement pour le moteur de règles
                    event = DetectionEvent('persistence_method', method)
                    self.rules_engine.process_event(event)
                    
                    # Log la détection
                    security_logger.log_persistence_detection(
                        method.method_type,
                        method.location,
                        method.value,
                        method.risk_score
                    )
                    
        except Exception as e:
            security_logger.log_system_event("ERROR", f"Erreur lors du scan de persistance: {e}", "ERROR")
    
    def _on_process_change(self, new_processes: List[ProcessInfo], terminated_processes: List[ProcessInfo]):
        """Callback pour les changements de processus"""
        for process in new_processes:
            # Créer un événement pour le moteur de règles
            event = DetectionEvent('new_process', process.to_dict())
            self.rules_engine.process_event(event)
            
            # Log l'activité
            security_logger.log_process_activity(
                "NEW_PROCESS",
                process.name,
                process.pid,
                f"Exe: {process.exe}"
            )
        
        for process in terminated_processes:
            security_logger.log_process_activity(
                "TERMINATED_PROCESS",
                process.name,
                process.pid
            )
    
    def _on_file_activity(self, event_type: str, data):
        """Callback pour les activités de fichiers"""
        if event_type == 'file_activity':
            # Créer un événement pour le moteur de règles
            event = DetectionEvent('file_activity', data)
            self.rules_engine.process_event(event)
            
            # Log l'activité
            security_logger.log_file_activity(
                data.file_path,
                data.activity_type,
                data.process_name,
                data.process_pid
            )
        
        elif event_type == 'network_connection':
            # Créer un événement pour le moteur de règles
            event = DetectionEvent('network_connection', data)
            self.rules_engine.process_event(event)
            
            # Log l'activité
            if data.raddr:
                security_logger.log_network_activity(
                    "NEW_CONNECTION",
                    f"{data.raddr.ip}:{data.raddr.port}",
                    data.process_name,
                    data.pid
                )
    
    def _on_rules_alert(self, alert_data: Dict[str, Any]):
        """Callback pour les alertes du moteur de règles"""
        self.stats['alerts_generated'] += 1
        
        # Créer une alerte
        alert = self.alert_manager.create_keylogger_alert(
            alert_data['process_name'],
            alert_data['process_pid'],
            alert_data['total_score'],
            alert_data
        )
        
        # Log l'alerte
        security_logger.log_alert(
            alert.alert_type,
            alert.title,
            alert.severity.name,
            alert.process_name,
            alert.process_pid
        )
        
        # Incrémenter le compteur de keyloggers détectés
        if alert_data.get('total_score', 0) >= 30:  # Seuil élevé
            self.stats['keyloggers_detected'] += 1
    
    def _on_new_alert(self, alert):
        """Callback pour les nouvelles alertes"""
        # Log l'alerte
        security_logger.log_alert(
            alert.alert_type,
            alert.title,
            alert.severity.name,
            alert.process_name,
            alert.process_pid
        )
    
    def _log_summary(self):
        """Log un résumé des activités"""
        try:
            # Obtenir les résumés des composants
            rules_summary = self.rules_engine.get_detection_summary()
            alerts_summary = self.alert_manager.get_alert_summary()
            
            # Calculer le temps d'exécution
            uptime = time.time() - self.stats['start_time']
            uptime_str = f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m"
            
            # Log le résumé
            security_logger.log_summary({
                'total_processes': rules_summary['total_processes'],
                'suspicious_processes': rules_summary['suspicious_processes'],
                'high_risk_processes': rules_summary['high_risk_processes'],
                'total_alerts': alerts_summary['total_alerts'],
                'uptime': uptime_str,
                'total_scans': self.stats['total_scans'],
                'processes_scanned': self.stats['processes_scanned']
            })
            
        except Exception as e:
            security_logger.log_system_event("ERROR", f"Erreur lors du log du résumé: {e}", "ERROR")
    
    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut de l'agent"""
        uptime = 0
        if self.stats['start_time']:
            uptime = time.time() - self.stats['start_time']
        
        return {
            'running': self.running,
            'uptime': uptime,
            'stats': self.stats.copy(),
            'process_monitor_running': self.process_monitor.running,
            'file_monitor_running': self.file_monitor.running
        }
    
    def get_detection_summary(self) -> Dict[str, Any]:
        """Retourne un résumé des détections"""
        rules_summary = self.rules_engine.get_detection_summary()
        alerts_summary = self.alert_manager.get_alert_summary()
        
        return {
            'agent_stats': self.stats.copy(),
            'rules_summary': rules_summary,
            'alerts_summary': alerts_summary,
            'suspicious_processes': [
                score.to_dict() for score in self.rules_engine.get_suspicious_processes()
            ],
            'high_risk_processes': [
                score.to_dict() for score in self.rules_engine.get_high_risk_processes()
            ]
        }
    
    def force_scan(self):
        """Force un scan immédiat"""
        if not self.running:
            return
        
        # Effectuer tous les scans
        self._perform_main_scan()
        self._perform_api_scan()
        self._perform_persistence_scan()
        
        security_logger.log_system_event("SCAN", "Scan forcé effectué", "INFO")
    
    def get_alert_manager(self) -> AlertManager:
        """Retourne le gestionnaire d'alertes"""
        return self.alert_manager
    
    def get_rules_engine(self) -> RulesEngine:
        """Retourne le moteur de règles"""
        return self.rules_engine
