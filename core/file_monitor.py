"""
Module de surveillance des fichiers et communications réseau
"""

import os
import psutil
import time
import threading
from typing import Dict, List, Set, Optional, Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import re


class FileActivity:
    """Représente une activité de fichier suspecte"""
    
    def __init__(self, file_path: str, activity_type: str, process_name: str, 
                 process_pid: int, timestamp: float = None):
        self.file_path = file_path
        self.activity_type = activity_type  # 'write', 'read', 'create', 'delete'
        self.process_name = process_name
        self.process_pid = process_pid
        self.timestamp = timestamp or time.time()
        self.size = 0
        self.content_preview = ""
        
        # Analyser le fichier si possible
        self._analyze_file()
    
    def _analyze_file(self):
        """Analyse le fichier pour extraire des informations"""
        try:
            if os.path.exists(self.file_path):
                self.size = os.path.getsize(self.file_path)
                
                # Lire un aperçu du contenu pour les petits fichiers
                if self.size < 1024:  # 1KB
                    with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        self.content_preview = f.read()[:200]
        except Exception:
            pass
    
    def is_suspicious(self) -> bool:
        """Détermine si cette activité de fichier est suspecte"""
        filename = os.path.basename(self.file_path).lower()
        file_path_lower = self.file_path.lower()
        
        # Exclure les processus légitimes
        legitimate_processes = [
            'msedge', 'chrome', 'firefox', 'opera', 'cursor', 'vscode',
            'explorer', 'winlogon', 'svchost', 'taskhost', 'dllhost',
            'systemsettings', 'runtimebroker', 'backgroundtask'
        ]
        if any(legit in self.process_name.lower() for legit in legitimate_processes):
            # Pour les processus légitimes, être plus strict
            # Seulement détecter si le nom est TRÈS suspect
            very_suspicious_names = ['keylog', 'keys.txt', 'capture.txt', 'input.log']
            if not any(name in filename for name in very_suspicious_names):
                return False
        
        # Critère 1: Nom de fichier TRÈS suspect (obligatoire)
        very_suspicious_names = ['keylog', 'keys.txt', 'capture.txt', 'input.log', 'logger.txt']
        has_very_suspicious_name = any(name in filename for name in very_suspicious_names)
        
        # Critère 2: Extension suspecte + nom suspect (pas juste extension)
        suspicious_extensions = ['.key', '.klg']  # Extensions vraiment suspectes
        has_suspicious_ext = any(filename.endswith(ext) for ext in suspicious_extensions)
        
        # Pour .txt et .log, exiger un nom suspect aussi
        if filename.endswith('.txt') or filename.endswith('.log'):
            suspicious_names = ['keylog', 'logger', 'keys', 'input', 'capture']
            has_suspicious_name = any(name in filename for name in suspicious_names)
            if not has_suspicious_name:
                return False  # Pas suspect si juste .txt/.log sans nom suspect
        
        # Critère 3: Processus suspect qui écrit
        suspicious_process_names = ['keylog', 'logger', 'spy', 'monitor', 'hook', 'capture']
        is_suspicious_process = any(sus in self.process_name.lower() for sus in suspicious_process_names)
        
        # Critère 4: Processus Python avec module suspect
        is_python_process = 'python' in self.process_name.lower()
        
        # Combinaison: (Nom très suspect) OU (Extension suspecte + Processus suspect) OU (Python + Nom suspect)
        if has_very_suspicious_name:
            return True
        
        if has_suspicious_ext and is_suspicious_process:
            return True
        
        if is_python_process and has_suspicious_name:
            return True
        
        # Critère 5: Contenu suspect (patterns de frappes) - seulement si déjà suspect
        if (has_suspicious_name or is_suspicious_process) and self.content_preview:
            keylog_patterns = [
                r'key:\s*\w+',  # Pattern "key: X"
                r'pressed|released',  # Mots-clés de keylogger
                r'keycode|scancode',  # Codes de touches
            ]
            
            for pattern in keylog_patterns:
                if re.search(pattern, self.content_preview, re.IGNORECASE):
                    return True
        
        return False
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            'file_path': self.file_path,
            'activity_type': self.activity_type,
            'process_name': self.process_name,
            'process_pid': self.process_pid,
            'timestamp': self.timestamp,
            'size': self.size,
            'content_preview': self.content_preview,
            'is_suspicious': self.is_suspicious()
        }


class NetworkConnection:
    """Représente une connexion réseau suspecte"""
    
    def __init__(self, connection):
        self.pid = connection.pid
        self.laddr = connection.laddr
        self.raddr = connection.raddr
        self.status = connection.status
        self.family = connection.family
        self.type = connection.type
        
        # Obtenir le nom du processus
        try:
            process = psutil.Process(self.pid)
            self.process_name = process.name()
        except:
            self.process_name = "Unknown"
    
    def is_suspicious(self) -> bool:
        """Détermine si cette connexion est suspecte avec analyse contextuelle"""
        # Vérifier d'abord le nom du processus
        suspicious_process_names = ['keylog', 'logger', 'spy', 'monitor', 'hook', 
                                   'capture', 'record', 'track', 'steal', 'grab']
        
        if any(sus in self.process_name.lower() for sus in suspicious_process_names):
            return True
        
        # Ports suspects (mais seulement pour les processus suspects)
        suspicious_ports = [4444, 6666, 7777, 1234, 4321, 31337, 1337]
        
        if self.raddr and self.raddr.port in suspicious_ports:
            # Ports non-standard suspects
            return True
        
        # Ports HTTP/HTTPS suspects seulement si le processus est suspect
        http_ports = [80, 443, 8080, 8443]
        if self.raddr and self.raddr.port in http_ports:
            # Vérifier si c'est un processus système légitime
            legitimate_processes = ['chrome', 'firefox', 'edge', 'opera', 'brave',
                                  'explorer', 'iexplore', 'msedge', 'winlogon']
            if not any(legit in self.process_name.lower() for legit in legitimate_processes):
                # Processus non-légitime utilisant HTTP/HTTPS = suspect
                if any(sus in self.process_name.lower() for sus in ['unknown', 'svchost', 'dllhost']):
                    return True
        
        # Connexions sortantes vers des IPs suspectes
        if self.raddr and self.raddr.ip:
            # IPs privées suspectes seulement si le processus est suspect
            if self.raddr.ip.startswith('192.168.') or self.raddr.ip.startswith('10.'):
                # Vérifier si c'est un processus système légitime
                system_processes = ['svchost', 'dllhost', 'explorer', 'winlogon']
                if not any(sys_proc in self.process_name.lower() for sys_proc in system_processes):
                    return True
            
            # IPs publiques suspectes (certaines plages connues)
            suspicious_ip_ranges = [
                '185.', '45.', '91.', '104.', '172.'
            ]
            # Ne pas marquer comme suspect automatiquement, juste noter
            
        return False
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            'pid': self.pid,
            'process_name': self.process_name,
            'local_address': f"{self.laddr.ip}:{self.laddr.port}" if self.laddr else None,
            'remote_address': f"{self.raddr.ip}:{self.raddr.port}" if self.raddr else None,
            'status': self.status,
            'family': self.family,
            'type': self.type,
            'is_suspicious': self.is_suspicious()
        }


class FileMonitorHandler(FileSystemEventHandler):
    """Gestionnaire d'événements de surveillance de fichiers"""
    
    def __init__(self, callback: Callable):
        self.callback = callback
        self.suspicious_paths = [
            os.path.expandvars('%TEMP%'),
            os.path.expandvars('%APPDATA%'),
            os.path.expandvars('%LOCALAPPDATA%'),
            'C:\\Windows\\Temp'
        ]
    
    def on_modified(self, event):
        if not event.is_directory:
            self._handle_file_event(event.src_path, 'modified')
    
    def on_created(self, event):
        if not event.is_directory:
            self._handle_file_event(event.src_path, 'created')
    
    def on_deleted(self, event):
        if not event.is_directory:
            self._handle_file_event(event.src_path, 'deleted')
    
    def _handle_file_event(self, file_path: str, event_type: str):
        """Gère un événement de fichier"""
        # Vérifier si le fichier est suspect (critères stricts)
        file_path_lower = file_path.lower()
        filename = os.path.basename(file_path_lower)
        
        # Noms TRÈS suspects (obligatoire)
        very_suspicious_names = ['keylog', 'keys.txt', 'capture.txt', 'input.log', 'logger.txt']
        has_very_suspicious_name = any(name in filename for name in very_suspicious_names)
        
        # Extensions vraiment suspectes
        has_suspicious_ext = filename.endswith('.key') or filename.endswith('.klg')
        
        # Pour .txt/.log, exiger un nom suspect aussi
        has_suspicious_name_and_ext = False
        if filename.endswith('.txt') or filename.endswith('.log'):
            suspicious_names = ['keylog', 'logger', 'keys', 'input', 'capture']
            has_suspicious_name_and_ext = any(name in filename for name in suspicious_names)
        
        # Vérifier si le fichier est dans un chemin suspect
        is_suspicious_path = any(suspicious_path in file_path for suspicious_path in self.suspicious_paths)
        
        # Détecter seulement les fichiers VRAIMENT suspects
        if has_very_suspicious_name or has_suspicious_ext or (has_suspicious_name_and_ext and is_suspicious_path):
            try:
                # Obtenir le processus qui a modifié le fichier
                process_name, process_pid = self._get_file_owner_process(file_path)
                
                activity = FileActivity(
                    file_path=file_path,
                    activity_type=event_type,
                    process_name=process_name,
                    process_pid=process_pid
                )
                
                # Vérifier à nouveau avec le processus (méthode is_suspicious)
                if activity.is_suspicious():
                    self.callback(activity)
                
            except Exception as e:
                print(f"[FileMonitor] Erreur lors du traitement de l'événement: {e}")
    
    def _get_file_owner_process(self, file_path: str) -> tuple:
        """Tente de déterminer le processus propriétaire d'un fichier"""
        try:
            # Méthode simple: utiliser le processus le plus récent qui a accès au fichier
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.open_files():
                        for f in proc.open_files():
                            if f.path == file_path:
                                return proc.info['name'], proc.info['pid']
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        
        return "Unknown", 0


class FileMonitor:
    """Surveillant de fichiers et communications réseau"""
    
    def __init__(self, scan_interval: float = 10.0):
        self.scan_interval = scan_interval
        self.running = False
        self.thread = None
        self.observer = None
        self.file_activities: List[FileActivity] = []
        self.network_connections: List[NetworkConnection] = []
        self.callbacks: List[Callable] = []
        self.lock = threading.Lock()
        
        # Chemins à surveiller (pour watchdog - surveillance en temps réel)
        # Note: On surveille aussi TOUS les fichiers via _scan_process_file_activities()
        self.watch_paths = [
            os.path.expandvars('%TEMP%'),
            os.path.expandvars('%APPDATA%'),
            os.path.expandvars('%LOCALAPPDATA%'),
            'C:\\Windows\\Temp',
            # Ajouter le dossier utilisateur courant (Documents, Desktop, etc.)
            os.path.expandvars('%USERPROFILE%\\Documents'),
            os.path.expandvars('%USERPROFILE%\\Desktop'),
        ]
        
        # Ajouter le dossier keylogger-test si il existe (pour les tests)
        test_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keylogger-test')
        if os.path.exists(test_dir):
            self.watch_paths.append(test_dir)
        
        # Nettoyer les chemins qui n'existent pas
        self.watch_paths = [path for path in self.watch_paths if os.path.exists(path)]
    
    def start(self):
        """Démarre la surveillance"""
        if self.running:
            return
        
        self.running = True
        
        # Démarrer la surveillance de fichiers
        self._start_file_watching()
        
        # Démarrer la surveillance réseau
        self.thread = threading.Thread(target=self._monitor_network, daemon=True)
        self.thread.start()
        
        print("[FileMonitor] Surveillance des fichiers et réseau démarrée")
    
    def stop(self):
        """Arrête la surveillance"""
        self.running = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        if self.thread:
            self.thread.join(timeout=5)
        
        print("[FileMonitor] Surveillance arrêtée")
    
    def add_callback(self, callback: Callable):
        """Ajoute un callback pour les événements"""
        self.callbacks.append(callback)
    
    def _start_file_watching(self):
        """Démarre la surveillance de fichiers avec watchdog"""
        try:
            self.observer = Observer()
            
            # Surveiller les dossiers spécifiques (pour les fichiers suspects)
            for path in self.watch_paths:
                if os.path.exists(path):
                    handler = FileMonitorHandler(self._on_file_activity)
                    self.observer.schedule(handler, path, recursive=True)
            
            # Démarrer aussi la surveillance basée sur les processus
            # (détecte les fichiers ouverts/écrits par tous les processus)
            self.observer.start()
            
        except Exception as e:
            print(f"[FileMonitor] Erreur lors du démarrage de la surveillance: {e}")
    
    def _scan_process_file_activities(self):
        """
        Scanne les fichiers ouverts/écrits par tous les processus
        Cette méthode détecte les fichiers même s'ils ne sont pas dans les dossiers surveillés
        """
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    process = psutil.Process(proc.info['pid'])
                    
                    # Obtenir les fichiers ouverts par le processus
                    try:
                        open_files = process.open_files()
                        for file_info in open_files:
                            file_path = file_info.path
                            
                            # Vérifier si le fichier est suspect
                            if self._is_suspicious_file_path(file_path):
                                # Vérifier si on a déjà détecté ce fichier récemment
                                if not self._recently_detected(file_path):
                                    activity = FileActivity(
                                        file_path=file_path,
                                        activity_type='write',  # Probablement en écriture
                                        process_name=proc.info['name'],
                                        process_pid=proc.info['pid']
                                    )
                                    
                                    # Si l'activité est suspecte, notifier
                                    if activity.is_suspicious():
                                        self._on_file_activity(activity)
                                        
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        continue
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"[FileMonitor] Erreur lors du scan des fichiers de processus: {e}")
    
    def _is_suspicious_file_path(self, file_path: str) -> bool:
        """Détermine si un chemin de fichier est suspect (plus strict)"""
        file_path_lower = file_path.lower()
        filename = os.path.basename(file_path_lower)
        
        # Noms de fichiers TRÈS suspects (obligatoire)
        very_suspicious_names = ['keylog', 'keys.txt', 'capture.txt', 'input.log', 'logger.txt']
        if any(name in filename for name in very_suspicious_names):
            return True
        
        # Extensions vraiment suspectes (seulement .key et .klg)
        if filename.endswith('.key') or filename.endswith('.klg'):
            return True
        
        # Pour .txt et .log, exiger un nom suspect aussi (pas juste l'extension)
        if filename.endswith('.txt') or filename.endswith('.log'):
            suspicious_names = ['keylog', 'logger', 'keys', 'input', 'capture']
            if any(name in filename for name in suspicious_names):
                return True
        
        return False
    
    def _recently_detected(self, file_path: str) -> bool:
        """Vérifie si un fichier a été détecté récemment (évite les doublons)"""
        current_time = time.time()
        with self.lock:
            # Vérifier les 100 dernières activités
            recent_activities = self.file_activities[-100:]
            for activity in recent_activities:
                if activity.file_path == file_path:
                    # Si détecté il y a moins de 30 secondes, ignorer
                    if current_time - activity.timestamp < 30:
                        return True
        return False
    
    def _monitor_network(self):
        """Surveille les connexions réseau et les fichiers des processus"""
        while self.running:
            try:
                self._scan_network_connections()
                # Scanner aussi les fichiers ouverts par les processus
                self._scan_process_file_activities()
                time.sleep(self.scan_interval)
            except Exception as e:
                print(f"[FileMonitor] Erreur dans la surveillance réseau: {e}")
                time.sleep(self.scan_interval)
    
    def _scan_network_connections(self):
        """Scanne les connexions réseau actuelles"""
        try:
            current_connections = []
            
            for conn in psutil.net_connections(kind='inet'):
                try:
                    network_conn = NetworkConnection(conn)
                    current_connections.append(network_conn)
                except Exception:
                    continue
            
            # Détecter les nouvelles connexions suspectes
            with self.lock:
                existing_pids = {conn.pid for conn in self.network_connections}
                new_suspicious = [
                    conn for conn in current_connections
                    if conn.pid not in existing_pids and conn.is_suspicious()
                ]
                
                self.network_connections = current_connections
            
            # Notifier les nouvelles connexions suspectes
            for conn in new_suspicious:
                self._notify_callbacks('network_connection', conn)
                
        except Exception as e:
            print(f"[FileMonitor] Erreur lors du scan réseau: {e}")
    
    def _on_file_activity(self, activity: FileActivity):
        """Gère une activité de fichier"""
        with self.lock:
            self.file_activities.append(activity)
            
            # Garder seulement les 1000 dernières activités
            if len(self.file_activities) > 1000:
                self.file_activities = self.file_activities[-1000:]
        
        # Notifier si l'activité est suspecte
        if activity.is_suspicious():
            self._notify_callbacks('file_activity', activity)
    
    def _notify_callbacks(self, event_type: str, data):
        """Notifie tous les callbacks"""
        for callback in self.callbacks:
            try:
                callback(event_type, data)
            except Exception as e:
                print(f"[FileMonitor] Erreur dans callback: {e}")
    
    def get_suspicious_activities(self) -> List[FileActivity]:
        """Retourne les activités de fichiers suspectes"""
        with self.lock:
            return [activity for activity in self.file_activities 
                   if activity.is_suspicious()]
    
    def get_suspicious_connections(self) -> List[NetworkConnection]:
        """Retourne les connexions réseau suspectes"""
        with self.lock:
            return [conn for conn in self.network_connections 
                   if conn.is_suspicious()]
    
    def get_summary(self) -> Dict:
        """Retourne un résumé des activités surveillées"""
        with self.lock:
            return {
                'total_file_activities': len(self.file_activities),
                'suspicious_file_activities': len(self.get_suspicious_activities()),
                'total_network_connections': len(self.network_connections),
                'suspicious_network_connections': len(self.get_suspicious_connections()),
                'watch_paths': self.watch_paths
            }
