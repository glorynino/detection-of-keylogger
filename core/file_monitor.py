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
        # Extensions suspectes
        suspicious_extensions = ['.log', '.txt', '.dat', '.tmp', '.key', '.klg']
        if any(self.file_path.lower().endswith(ext) for ext in suspicious_extensions):
            return True
        
        # Noms de fichiers suspects
        suspicious_names = ['keylog', 'logger', 'keys', 'input', 'capture']
        filename = os.path.basename(self.file_path).lower()
        if any(name in filename for name in suspicious_names):
            return True
        
        # Contenu suspect (patterns de frappes)
        if self.content_preview:
            keylog_patterns = [
                r'[a-zA-Z0-9]{1,2}:\d{2}:\d{2}',  # Pattern timestamp
                r'key:\s*\w+',  # Pattern "key: X"
                r'pressed|released',  # Mots-clés de keylogger
                r'[A-Za-z]\s+[A-Za-z]\s+[A-Za-z]'  # Séquences de caractères
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
        """Détermine si cette connexion est suspecte"""
        # Ports suspects
        suspicious_ports = [80, 443, 8080, 8443, 4444, 6666, 7777, 1234, 4321]
        
        if self.raddr and self.raddr.port in suspicious_ports:
            return True
        
        # Connexions sortantes vers des IPs suspectes
        if self.raddr and self.raddr.ip:
            # IPs privées suspectes (peut être un tunnel)
            if self.raddr.ip.startswith('192.168.') or self.raddr.ip.startswith('10.'):
                return True
        
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
        # Vérifier si le fichier est dans un chemin suspect
        if any(suspicious_path in file_path for suspicious_path in self.suspicious_paths):
            try:
                # Obtenir le processus qui a modifié le fichier
                process_name, process_pid = self._get_file_owner_process(file_path)
                
                activity = FileActivity(
                    file_path=file_path,
                    activity_type=event_type,
                    process_name=process_name,
                    process_pid=process_pid
                )
                
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
        
        # Chemins à surveiller
        self.watch_paths = [
            os.path.expandvars('%TEMP%'),
            os.path.expandvars('%APPDATA%'),
            os.path.expandvars('%LOCALAPPDATA%'),
            'C:\\Windows\\Temp'
        ]
    
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
            
            for path in self.watch_paths:
                if os.path.exists(path):
                    handler = FileMonitorHandler(self._on_file_activity)
                    self.observer.schedule(handler, path, recursive=True)
            
            self.observer.start()
            
        except Exception as e:
            print(f"[FileMonitor] Erreur lors du démarrage de la surveillance: {e}")
    
    def _monitor_network(self):
        """Surveille les connexions réseau"""
        while self.running:
            try:
                self._scan_network_connections()
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
