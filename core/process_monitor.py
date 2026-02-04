"""
Module de surveillance des processus en temps réel
"""

import psutil
import time
import threading
from typing import Dict, List, Set, Callable, Optional
from datetime import datetime


class ProcessInfo:
    """Information sur un processus"""
    
    def __init__(self, process: psutil.Process):
        self.pid = process.pid
        self.name = process.name()
        self.exe = process.exe() if hasattr(process, 'exe') else ""
        self.cmdline = ' '.join(process.cmdline()) if hasattr(process, 'cmdline') else ""
        self.create_time = process.create_time()
        self.cpu_percent = process.cpu_percent()
        self.memory_info = process.memory_info()
        self.status = process.status()
        self.username = process.username() if hasattr(process, 'username') else ""
        self.parent = process.ppid() if hasattr(process, 'ppid') else None
        
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire pour sérialisation"""
        return {
            'pid': self.pid,
            'name': self.name,
            'exe': self.exe,
            'cmdline': self.cmdline,
            'create_time': self.create_time,
            'cpu_percent': self.cpu_percent,
            'memory_rss': self.memory_info.rss,
            'memory_vms': self.memory_info.vms,
            'status': self.status,
            'username': self.username,
            'parent': self.parent
        }


class ProcessMonitor:
    """Surveillant de processus en temps réel"""
    
    def __init__(self, scan_interval: float = 2.0):
        self.scan_interval = scan_interval
        self.running = False
        self.thread = None
        self.processes: Dict[int, ProcessInfo] = {}
        self.callbacks: List[Callable] = []
        self.lock = threading.Lock()
        
    def start(self):
        """Démarre la surveillance"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print(f"[ProcessMonitor] Surveillance démarrée (intervalle: {self.scan_interval}s)")
    
    def stop(self):
        """Arrête la surveillance"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("[ProcessMonitor] Surveillance arrêtée")
    
    def add_callback(self, callback: Callable):
        """Ajoute un callback appelé lors de changements de processus"""
        self.callbacks.append(callback)
    
    def get_processes(self) -> Dict[int, ProcessInfo]:
        """Retourne la liste actuelle des processus"""
        with self.lock:
            return self.processes.copy()
    
    def get_process(self, pid: int) -> Optional[ProcessInfo]:
        """Retourne un processus spécifique par PID"""
        with self.lock:
            return self.processes.get(pid)
    
    def _monitor_loop(self):
        """Boucle principale de surveillance"""
        while self.running:
            try:
                self._scan_processes()
                time.sleep(self.scan_interval)
            except Exception as e:
                print(f"[ProcessMonitor] Erreur dans la boucle de surveillance: {e}")
                time.sleep(self.scan_interval)
    
    def _scan_processes(self):
        """Scanne tous les processus en cours"""
        current_processes = {}
        new_processes = []
        terminated_processes = []
        
        try:
            # Obtenir tous les processus actuels
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 
                                           'cpu_percent', 'memory_info', 'status', 'username', 'ppid']):
                try:
                    process_info = ProcessInfo(proc)
                    current_processes[process_info.pid] = process_info
                    
                    # Détecter les nouveaux processus
                    if process_info.pid not in self.processes:
                        new_processes.append(process_info)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Détecter les processus terminés
            with self.lock:
                for pid in self.processes:
                    if pid not in current_processes:
                        terminated_processes.append(self.processes[pid])
                
                # Mettre à jour la liste des processus
                self.processes = current_processes
            
            # Notifier les changements
            if new_processes or terminated_processes:
                self._notify_changes(new_processes, terminated_processes)
                
        except Exception as e:
            print(f"[ProcessMonitor] Erreur lors du scan: {e}")
    
    def _notify_changes(self, new_processes: List[ProcessInfo], 
                       terminated_processes: List[ProcessInfo]):
        """Notifie les callbacks des changements de processus"""
        for callback in self.callbacks:
            try:
                callback(new_processes, terminated_processes)
            except Exception as e:
                print(f"[ProcessMonitor] Erreur dans callback: {e}")
    
    def get_processes_by_name(self, name: str) -> List[ProcessInfo]:
        """Retourne tous les processus avec un nom donné"""
        with self.lock:
            return [proc for proc in self.processes.values() 
                   if name.lower() in proc.name.lower()]
    
    def get_processes_by_path(self, path: str) -> List[ProcessInfo]:
        """Retourne tous les processus avec un chemin donné"""
        with self.lock:
            return [proc for proc in self.processes.values() 
                   if path.lower() in proc.exe.lower()]
    
    def get_suspicious_processes(self) -> List[ProcessInfo]:
        """Retourne les processus suspects basés sur des critères simples"""
        suspicious = []
        
        with self.lock:
            for proc in self.processes.values():
                # Critères de suspicion basiques
                if self._is_suspicious_process(proc):
                    suspicious.append(proc)
        
        return suspicious
    
    def _is_suspicious_process(self, proc: ProcessInfo) -> bool:
        """Détermine si un processus est suspect"""
        # Processus sans nom d'exécutable
        if not proc.exe:
            return True
        
        # Processus avec des noms suspects
        suspicious_names = ['keylog', 'logger', 'hook', 'spy', 'monitor']
        if any(name in proc.name.lower() for name in suspicious_names):
            return True
        
        # Processus Python avec comportement suspect
        if proc.name.lower() in ['python.exe', 'pythonw.exe', 'python3.exe', 'python3.13.exe']:
            # Vérifier si le script contient des mots-clés suspects
            cmdline_str = ' '.join(proc.cmdline) if proc.cmdline else ''
            cmdline_lower = cmdline_str.lower()
            python_keylogger_keywords = ['pynput', 'keyboard', 'listener', 'keylog', 'listen-to-key']
            if any(keyword in cmdline_lower for keyword in python_keylogger_keywords):
                return True
        
        # Processus dans des dossiers temporaires
        temp_paths = ['temp', 'tmp', 'appdata', 'localappdata']
        if any(path in proc.exe.lower() for path in temp_paths):
            return True
        
        # Processus avec des arguments suspects
        suspicious_args = ['-k', '--key', '--log', '--hook']
        if any(arg in proc.cmdline.lower() for arg in suspicious_args):
            return True
        
        return False
