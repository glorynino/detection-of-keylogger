"""
Agent principal de surveillance et détection de keyloggers
"""

import time
import threading
from typing import Dict, List, Any, Optional, Callable
from core.process_monitor import ProcessMonitor, ProcessInfo
from core.api_detector import APIDetector
from core.file_monitor import FileMonitor, FileActivity, NetworkConnection
from core.persistence_check import PersistenceChecker, PersistenceMethod
from core.rules_engine import RulesEngine, DetectionEvent
from core.hook_monitor import HookMonitor
from core.behavioral_analyzer import BehavioralAnalyzer, BehavioralEvent
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
        self.hook_monitor = HookMonitor()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.rules_engine = RulesEngine()
        self.alert_manager = AlertManager()
        
        # État de l'agent
        self.running = False
        self.scan_thread = None
        self.api_scan_thread = None
        self.persistence_scan_thread = None
        self.hook_scan_thread = None
        
        # Configuration
        self.scan_interval = MONITOR_CONFIG['scan_interval']
        self.api_scan_interval = 30  # secondes
        self.persistence_scan_interval = 300  # 5 minutes
        self.hook_scan_interval = 60  # 1 minute
        
        # Statistiques
        self.stats = {
            'start_time': None,
            'total_scans': 0,
            'processes_scanned': 0,
            'alerts_generated': 0,
            'keyloggers_detected': 0
        }
        
        # Système de callback pour la GUI
        self.gui_callbacks = []
        
        # Données en temps réel pour la GUI
        self.recent_activities = []
        self.current_processes = {}
        
        # Configurer les callbacks internes
        self._setup_callbacks()
    
    def add_gui_callback(self, callback: Callable):
        """Ajoute un callback pour la GUI"""
        self.gui_callbacks.append(callback)
    
    def _notify_gui(self, event_type: str, data: Dict[str, Any]):
        """Notifie tous les callbacks GUI"""
        for callback in self.gui_callbacks:
            try:
                callback(event_type, data)
            except Exception as e:
                print(f"Erreur callback GUI: {e}")
    
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
        
        self.hook_scan_thread = threading.Thread(target=self._hook_scan_loop, daemon=True)
        self.hook_scan_thread.start()
        
        security_logger.log_system_event("AGENT", "Agent de surveillance démarré", "INFO")
        self._notify_gui("AGENT_STARTED", {"message": "Agent démarré"})
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
        if self.hook_scan_thread:
            self.hook_scan_thread.join(timeout=5)
        
        security_logger.log_system_event("AGENT", "Agent de surveillance arrêté", "INFO")
        self._notify_gui("AGENT_STOPPED", {"message": "Agent arrêté"})
        print("[Agent] Surveillance arrêtée")
    
    def _main_scan_loop(self):
        """Boucle principale de scan"""
        while self.running:
            try:
                self._perform_main_scan()
                
                # Notifier la GUI du scan
                self._notify_gui("SCAN_COMPLETE", {
                    "scan_type": "main",
                    "scan_id": self.stats['total_scans'],
                    "timestamp": time.time()
                })
                
                time.sleep(self.scan_interval)
            except Exception as e:
                error_msg = f"Erreur dans la boucle principale: {e}"
                security_logger.log_system_event("ERROR", error_msg, "ERROR")
                self._notify_gui("ERROR", {"message": error_msg})
                time.sleep(self.scan_interval)
    
    def _api_scan_loop(self):
        """Boucle de scan des API"""
        while self.running:
            try:
                scan_results = self._perform_api_scan()
                
                # Notifier la GUI des résultats API
                self._notify_gui("API_SCAN_COMPLETE", {
                    "processes_scanned": len(scan_results.get('processes', [])),
                    "suspicious_found": len(scan_results.get('suspicious_processes', [])),
                    "timestamp": time.time()
                })
                
                time.sleep(self.api_scan_interval)
            except Exception as e:
                error_msg = f"Erreur dans le scan API: {e}"
                security_logger.log_system_event("ERROR", error_msg, "ERROR")
                self._notify_gui("ERROR", {"message": error_msg})
                time.sleep(self.api_scan_interval)
    
    def _persistence_scan_loop(self):
        """Boucle de scan de persistance"""
        while self.running:
            try:
                scan_results = self._perform_persistence_scan()
                
                # Notifier la GUI des résultats de persistance
                self._notify_gui("PERSISTENCE_SCAN_COMPLETE", {
                    "methods_found": len(scan_results.get('methods', [])),
                    "suspicious_methods": len(scan_results.get('suspicious_methods', [])),
                    "timestamp": time.time()
                })
                
                time.sleep(self.persistence_scan_interval)
            except Exception as e:
                error_msg = f"Erreur dans le scan de persistance: {e}"
                security_logger.log_system_event("ERROR", error_msg, "ERROR")
                self._notify_gui("ERROR", {"message": error_msg})
                time.sleep(self.persistence_scan_interval)
    
    def _hook_scan_loop(self):
        """Boucle de scan des hooks Windows"""
        while self.running:
            try:
                scan_results = self._perform_hook_scan()
                
                # Notifier la GUI des résultats de hooks
                self._notify_gui("HOOK_SCAN_COMPLETE", {
                    "total_hooks": scan_results.get('total_hooks', 0),
                    "suspicious_hooks": scan_results.get('suspicious_hooks', 0),
                    "timestamp": time.time()
                })
                
                time.sleep(self.hook_scan_interval)
            except Exception as e:
                error_msg = f"Erreur dans le scan de hooks: {e}"
                security_logger.log_system_event("ERROR", error_msg, "ERROR")
                self._notify_gui("ERROR", {"message": error_msg})
                time.sleep(self.hook_scan_interval)
    
    def _perform_main_scan(self):
        """Effectue un scan principal"""
        self.stats['total_scans'] += 1
        
        # Vérifier les alertes
        self.rules_engine.check_alerts()
        
        # Vérifier les patterns comportementaux suspects
        self._check_behavioral_patterns()
        
        # Nettoyer les anciens processus
        self.rules_engine.cleanup_old_processes()
        
        # Mettre à jour les données pour la GUI
        self._update_gui_data()
        
        # Log du résumé périodique
        if self.stats['total_scans'] % 10 == 0:  # Toutes les 10 scans
            self._log_summary()
    
    def _check_behavioral_patterns(self):
        """Vérifie les patterns comportementaux suspects"""
        try:
            suspicious_patterns = self.behavioral_analyzer.get_suspicious_patterns()
            
            for pattern in suspicious_patterns:
                # Créer une alerte pour les patterns critiques
                if pattern['severity'] in ['HIGH', 'CRITICAL']:
                    alert = self.alert_manager.create_keylogger_alert(
                        pattern['process_name'],
                        pattern['process_pid'],
                        pattern.get('score', 0),
                        {
                            'type': 'BEHAVIORAL_PATTERN',
                            'pattern_type': pattern['pattern_type'],
                            'description': pattern['description'],
                            'evidence': pattern['evidence']
                        }
                    )
                    
                    security_logger.log_alert(
                        alert.alert_type,
                        alert.title,
                        alert.severity.name,
                        alert.process_name,
                        alert.process_pid
                    )
                    
                    self._notify_gui("NEW_ALERT", {
                        "alert_id": alert.alert_id,
                        "alert_type": alert.alert_type,
                        "severity": alert.severity.name,
                        "process_name": alert.process_name,
                        "process_pid": alert.process_pid,
                        "title": alert.title,
                        "description": alert.description,
                        "timestamp": alert.timestamp
                    })
        except Exception as e:
            security_logger.log_system_event("ERROR", f"Erreur lors de la vérification des patterns: {e}", "ERROR")
    
    def _perform_api_scan(self) -> Dict[str, Any]:
        """Effectue un scan des API pour tous les processus"""
        scan_results = {
            'processes': [],
            'suspicious_processes': [],
            'total_scanned': 0
        }
        
        try:
            processes = self.process_monitor.get_processes()
            self.stats['processes_scanned'] += len(processes)
            scan_results['total_scanned'] = len(processes)
            
            for process_info in processes.values():
                try:
                    # Créer un objet psutil.Process pour l'API detector
                    import psutil
                    process = psutil.Process(process_info.pid)
                    
                    # Scanner les API
                    api_results = self.api_detector.scan_process(process)
                    api_results['pid'] = process_info.pid
                    api_results['name'] = process_info.name
                    
                    scan_results['processes'].append(api_results)
                    
                    # Créer un événement pour le moteur de règles
                    event = DetectionEvent('api_scan', api_results)
                    self.rules_engine.process_event(event)
                    
                    # Ajouter un événement comportemental
                    if api_results.get('suspicious_apis'):
                        behavioral_event = BehavioralEvent(
                            'api_call',
                            process_info.pid,
                            process_info.name,
                            {'apis': [api['name'] for api in api_results['suspicious_apis']]}
                        )
                        self.behavioral_analyzer.add_event(behavioral_event)
                    
                    # Log si des API suspectes sont détectées
                    if api_results.get('suspicious_apis'):
                        security_logger.log_api_usage(
                            ', '.join([api['name'] for api in api_results['suspicious_apis']]),
                            process_info.name,
                            process_info.pid
                        )
                        scan_results['suspicious_processes'].append(api_results)
                    
                except Exception as e:
                    continue  # Ignorer les erreurs sur des processus individuels
                    
        except Exception as e:
            security_logger.log_system_event("ERROR", f"Erreur lors du scan API: {e}", "ERROR")
        
        return scan_results
    
    def _perform_persistence_scan(self) -> Dict[str, Any]:
        """Effectue un scan de persistance"""
        scan_results = {
            'methods': [],
            'suspicious_methods': []
        }
        
        try:
            methods = self.persistence_checker.check_all_persistence_methods()
            scan_results['methods'] = [method.to_dict() for method in methods]
            
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
                    
                    scan_results['suspicious_methods'].append(method.to_dict())
                    
        except Exception as e:
            security_logger.log_system_event("ERROR", f"Erreur lors du scan de persistance: {e}", "ERROR")
        
        return scan_results
    
    def _perform_hook_scan(self) -> Dict[str, Any]:
        """Effectue un scan des hooks Windows"""
        scan_results = {
            'total_hooks': 0,
            'suspicious_hooks': 0,
            'hooks': []
        }
        
        try:
            hooks = self.hook_monitor.enumerate_hooks()
            scan_results['total_hooks'] = len(hooks)
            
            suspicious_hooks = self.hook_monitor.get_suspicious_hooks()
            scan_results['suspicious_hooks'] = len(suspicious_hooks)
            scan_results['hooks'] = [hook.to_dict() for hook in hooks]
            
            # Créer des événements pour les hooks suspects
            for hook in suspicious_hooks:
                event = DetectionEvent('hook_installed', hook.to_dict())
                self.rules_engine.process_event(event)
                
                # Ajouter un événement comportemental
                behavioral_event = BehavioralEvent(
                    'hook_installed',
                    hook.process_id,
                    hook.process_name,
                    {'hook_type': hook.get_hook_type_name()}
                )
                self.behavioral_analyzer.add_event(behavioral_event)
                
                # Log la détection
                security_logger.log_system_event(
                    "HOOK",
                    f"Hook suspect détecté: {hook.get_hook_type_name()} dans {hook.process_name} (PID: {hook.process_id})",
                    "WARNING"
                )
        
        except Exception as e:
            security_logger.log_system_event("ERROR", f"Erreur lors du scan de hooks: {e}", "ERROR")
        
        return scan_results
    
    def _update_gui_data(self):
        """Met à jour les données pour la GUI"""
        try:
            # Obtenir les processus actuels
            self.current_processes = self.process_monitor.get_processes()
            
            # Obtenir les processus suspects
            suspicious_processes = self.rules_engine.get_suspicious_processes()
            
            # Notifier la GUI des données mises à jour
            self._notify_gui("DATA_UPDATE", {
                "total_processes": len(self.current_processes),
                "suspicious_processes": len(suspicious_processes),
                "active_alerts": len(self.alert_manager.alerts),
                "agent_stats": self.stats.copy()
            })
            
        except Exception as e:
            print(f"Erreur mise à jour données GUI: {e}")
    
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
            
            # Notifier la GUI
            self._notify_gui("NEW_PROCESS", {
                "pid": process.pid,
                "name": process.name,
                "exe": process.exe,
                "timestamp": time.time()
            })
        
        for process in terminated_processes:
            security_logger.log_process_activity(
                "TERMINATED_PROCESS",
                process.name,
                process.pid
            )
            
            # Notifier la GUI
            self._notify_gui("TERMINATED_PROCESS", {
                "pid": process.pid,
                "name": process.name,
                "timestamp": time.time()
            })
    
    def _on_file_activity(self, event_type: str, data):
        """Callback pour les activités de fichiers"""
        if event_type == 'file_activity':
            # Créer un événement pour le moteur de règles
            event = DetectionEvent('file_activity', data)
            self.rules_engine.process_event(event)
            
            # Ajouter un événement comportemental
            if data.activity_type in ['write', 'created']:
                behavioral_event = BehavioralEvent(
                    'file_write',
                    data.process_pid,
                    data.process_name,
                    {'file_path': data.file_path, 'activity_type': data.activity_type}
                )
                self.behavioral_analyzer.add_event(behavioral_event)
            
            # Log l'activité
            security_logger.log_file_activity(
                data.file_path,
                data.activity_type,
                data.process_name,
                data.process_pid
            )
            
            # Notifier la GUI
            self._notify_gui("FILE_ACTIVITY", {
                "file_path": data.file_path,
                "activity_type": data.activity_type,
                "process_name": data.process_name,
                "process_pid": data.process_pid,
                "timestamp": time.time()
            })
        
        elif event_type == 'network_connection':
            # Créer un événement pour le moteur de règles
            event = DetectionEvent('network_connection', data)
            self.rules_engine.process_event(event)
            
            # Ajouter un événement comportemental
            if data.raddr:
                behavioral_event = BehavioralEvent(
                    'network_send',
                    data.pid,
                    data.process_name,
                    {'remote_address': f"{data.raddr.ip}:{data.raddr.port}"}
                )
                self.behavioral_analyzer.add_event(behavioral_event)
                
                security_logger.log_network_activity(
                    "NEW_CONNECTION",
                    f"{data.raddr.ip}:{data.raddr.port}",
                    data.process_name,
                    data.pid
                )
                
                # Notifier la GUI
                self._notify_gui("NETWORK_ACTIVITY", {
                    "remote_address": f"{data.raddr.ip}:{data.raddr.port}",
                    "process_name": data.process_name,
                    "pid": data.pid,
                    "timestamp": time.time()
                })
    
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
        
        # Notifier la GUI
        self._notify_gui("NEW_ALERT", {
            "alert_id": alert.alert_id,
            "alert_type": alert.alert_type,
            "severity": alert.severity.name,
            "process_name": alert.process_name,
            "process_pid": alert.process_pid,
            "title": alert.title,
            "description": alert.description,
            "timestamp": alert.timestamp
        })
        
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
            
            # Notifier la GUI du résumé
            self._notify_gui("SUMMARY_UPDATE", {
                "uptime": uptime_str,
                "total_processes": rules_summary['total_processes'],
                "suspicious_processes": rules_summary['suspicious_processes'],
                "total_alerts": alerts_summary['total_alerts'],
                "total_scans": self.stats['total_scans']
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
        self._notify_gui("FORCED_SCAN", {"message": "Scan forcé effectué"})
    
    def get_alert_manager(self) -> AlertManager:
        """Retourne le gestionnaire d'alertes"""
        return self.alert_manager
    
    def get_rules_engine(self) -> RulesEngine:
        """Retourne le moteur de règles"""
        return self.rules_engine