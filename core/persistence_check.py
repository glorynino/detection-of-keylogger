"""
Module de vérification de persistance (autostart, services, etc.)
"""

import os
import winreg
import psutil
import subprocess
from typing import Dict, List, Optional, Tuple
import re


class PersistenceMethod:
    """Représente une méthode de persistance détectée"""
    
    def __init__(self, method_type: str, location: str, value: str, 
                 process_name: str = "", risk_score: int = 0):
        self.method_type = method_type  # 'registry', 'service', 'startup', 'scheduled_task'
        self.location = location
        self.value = value
        self.process_name = process_name
        self.risk_score = risk_score
        self.timestamp = None
    
    def is_suspicious(self) -> bool:
        """Détermine si cette méthode de persistance est suspecte"""
        # Chemins suspects
        suspicious_paths = [
            '%TEMP%', '%APPDATA%', '%LOCALAPPDATA%',
            'temp', 'tmp', 'appdata'
        ]
        
        if any(path.lower() in self.value.lower() for path in suspicious_paths):
            return True
        
        # Noms de processus suspects
        suspicious_names = [
            'keylog', 'logger', 'spy', 'monitor', 'hook',
            'capture', 'record', 'track'
        ]
        
        if any(name in self.process_name.lower() for name in suspicious_names):
            return True
        
        # Extensions suspectes
        suspicious_extensions = ['.exe', '.bat', '.cmd', '.vbs', '.ps1']
        if any(self.value.lower().endswith(ext) for ext in suspicious_extensions):
            return True
        
        return False
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            'method_type': self.method_type,
            'location': self.location,
            'value': self.value,
            'process_name': self.process_name,
            'risk_score': self.risk_score,
            'is_suspicious': self.is_suspicious()
        }


class PersistenceChecker:
    """Vérificateur de méthodes de persistance"""
    
    def __init__(self):
        self.registry_keys = [
            # Autostart registry keys
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
            
            # Shell extensions
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions"),
            
            # Winlogon
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        ]
    
    def check_all_persistence_methods(self) -> List[PersistenceMethod]:
        """Vérifie toutes les méthodes de persistance"""
        persistence_methods = []
        
        # Vérifier le registre
        persistence_methods.extend(self._check_registry_persistence())
        
        # Vérifier les services
        persistence_methods.extend(self._check_services_persistence())
        
        # Vérifier les tâches planifiées
        persistence_methods.extend(self._check_scheduled_tasks())
        
        # Vérifier les dossiers de démarrage
        persistence_methods.extend(self._check_startup_folders())
        
        return persistence_methods
    
    def _check_registry_persistence(self) -> List[PersistenceMethod]:
        """Vérifie la persistance via le registre"""
        persistence_methods = []
        
        for hkey, subkey in self.registry_keys:
            try:
                with winreg.OpenKey(hkey, subkey) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            
                            # Analyser la valeur
                            if self._is_executable_path(value):
                                method = PersistenceMethod(
                                    method_type='registry',
                                    location=f"{hkey}\\{subkey}",
                                    value=value,
                                    risk_score=self._calculate_registry_risk(name, value)
                                )
                                persistence_methods.append(method)
                            
                            i += 1
                        except OSError:
                            break
                            
            except (OSError, FileNotFoundError):
                continue
        
        return persistence_methods
    
    def _check_services_persistence(self) -> List[PersistenceMethod]:
        """Vérifie la persistance via les services"""
        persistence_methods = []
        
        try:
            # Utiliser sc query pour lister les services
            result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                services = self._parse_services_output(result.stdout)
                
                for service in services:
                    if self._is_suspicious_service(service):
                        method = PersistenceMethod(
                            method_type='service',
                            location='Services',
                            value=service['name'],
                            process_name=service.get('binary_path', ''),
                            risk_score=self._calculate_service_risk(service)
                        )
                        persistence_methods.append(method)
                        
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, Exception) as e:
            print(f"[PersistenceChecker] Erreur lors de la vérification des services: {e}")
        
        return persistence_methods
    
    def _check_scheduled_tasks(self) -> List[PersistenceMethod]:
        """Vérifie la persistance via les tâches planifiées"""
        persistence_methods = []
        
        try:
            # Utiliser schtasks pour lister les tâches
            result = subprocess.run(['schtasks', '/query', '/fo', 'csv'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                tasks = self._parse_tasks_output(result.stdout)
                
                for task in tasks:
                    if self._is_suspicious_task(task):
                        method = PersistenceMethod(
                            method_type='scheduled_task',
                            location='Scheduled Tasks',
                            value=task['name'],
                            process_name=task.get('command', ''),
                            risk_score=self._calculate_task_risk(task)
                        )
                        persistence_methods.append(method)
                        
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, Exception) as e:
            print(f"[PersistenceChecker] Erreur lors de la vérification des tâches: {e}")
        
        return persistence_methods
    
    def _check_startup_folders(self) -> List[PersistenceMethod]:
        """Vérifie les dossiers de démarrage"""
        persistence_methods = []
        
        startup_folders = [
            os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.expandvars(r'%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.expandvars(r'%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
        ]
        
        for folder in startup_folders:
            if os.path.exists(folder):
                try:
                    for filename in os.listdir(folder):
                        filepath = os.path.join(folder, filename)
                        if os.path.isfile(filepath):
                            method = PersistenceMethod(
                                method_type='startup_folder',
                                location=folder,
                                value=filepath,
                                risk_score=self._calculate_startup_risk(filepath)
                            )
                            persistence_methods.append(method)
                            
                except (OSError, PermissionError):
                    continue
        
        return persistence_methods
    
    def _is_executable_path(self, value: str) -> bool:
        """Détermine si une valeur contient un chemin d'exécutable"""
        executable_extensions = ['.exe', '.bat', '.cmd', '.vbs', '.ps1', '.scr']
        return any(value.lower().endswith(ext) for ext in executable_extensions)
    
    def _calculate_registry_risk(self, name: str, value: str) -> int:
        """Calcule le score de risque pour une entrée de registre"""
        risk = 0
        
        # Chemins suspects
        if any(path in value.lower() for path in ['temp', 'tmp', 'appdata']):
            risk += 20
        
        # Noms suspects
        if any(sus in name.lower() for sus in ['keylog', 'logger', 'spy', 'monitor']):
            risk += 25
        
        # Extensions suspectes
        if value.lower().endswith('.exe'):
            risk += 10
        
        return risk
    
    def _parse_services_output(self, output: str) -> List[Dict]:
        """Parse la sortie de sc query"""
        services = []
        lines = output.split('\n')
        
        current_service = {}
        for line in lines:
            line = line.strip()
            if line.startswith('SERVICE_NAME:'):
                if current_service:
                    services.append(current_service)
                current_service = {'name': line.split(':', 1)[1].strip()}
            elif line.startswith('BINARY_PATH_NAME:'):
                current_service['binary_path'] = line.split(':', 1)[1].strip()
            elif line.startswith('DISPLAY_NAME:'):
                current_service['display_name'] = line.split(':', 1)[1].strip()
        
        if current_service:
            services.append(current_service)
        
        return services
    
    def _parse_tasks_output(self, output: str) -> List[Dict]:
        """Parse la sortie de schtasks"""
        tasks = []
        lines = output.split('\n')
        
        for line in lines[1:]:  # Skip header
            if line.strip():
                parts = line.split(',')
                if len(parts) >= 3:
                    task = {
                        'name': parts[0].strip('"'),
                        'command': parts[2].strip('"') if len(parts) > 2 else ''
                    }
                    tasks.append(task)
        
        return tasks
    
    def _is_suspicious_service(self, service: Dict) -> bool:
        """Détermine si un service est suspect"""
        name = str(service.get('name', '')).lower()
        binary_path = str(service.get('binary_path', '')).lower()
        
        # Noms suspects
        suspicious_names = ['keylog', 'logger', 'spy', 'monitor', 'hook']
        if any(sus in name for sus in suspicious_names):
            return True
        
        # Chemins suspects
        if any(path in binary_path for path in ['temp', 'tmp', 'appdata']):
            return True
        
        return False
    
    def _is_suspicious_task(self, task: Dict) -> bool:
        """Détermine si une tâche planifiée est suspecte"""
        name = str(task.get('name', '')).lower()
        command = str(task.get('command', '')).lower()
        
        # Noms suspects
        suspicious_names = ['keylog', 'logger', 'spy', 'monitor', 'hook']
        if any(sus in name for sus in suspicious_names):
            return True
        
        # Commandes suspectes
        if any(sus in command for sus in suspicious_names):
            return True
        
        return False
    
    def _calculate_service_risk(self, service: Dict) -> int:
        """Calcule le score de risque pour un service"""
        risk = 0
        
        name = str(service.get('name', '')).lower()
        binary_path = str(service.get('binary_path', '')).lower()
        
        # Noms suspects
        if any(sus in name for sus in ['keylog', 'logger', 'spy']):
            risk += 25
        
        # Chemins suspects
        if any(path in binary_path for path in ['temp', 'tmp']):
            risk += 20
        
        return risk
    
    def _calculate_task_risk(self, task: Dict) -> int:
        """Calcule le score de risque pour une tâche"""
        risk = 0
        
        name = str(task.get('name', '')).lower()
        command = str(task.get('command', '')).lower()
        
        # Noms suspects
        if any(sus in name for sus in ['keylog', 'logger', 'spy']):
            risk += 25
        
        # Commandes suspectes
        if any(sus in command for sus in ['keylog', 'logger', 'spy']):
            risk += 20
        
        return risk
    
    def _calculate_startup_risk(self, filepath: str) -> int:
        """Calcule le score de risque pour un fichier de démarrage"""
        risk = 0
        
        filename = os.path.basename(filepath).lower()
        
        # Noms suspects
        if any(sus in filename for sus in ['keylog', 'logger', 'spy', 'monitor']):
            risk += 25
        
        # Extensions suspectes
        if filename.endswith('.exe'):
            risk += 10
        
        return risk
    
    def get_persistence_summary(self) -> Dict:
        """Retourne un résumé des méthodes de persistance"""
        methods = self.check_all_persistence_methods()
        
        summary = {
            'total_methods': len(methods),
            'suspicious_methods': len([m for m in methods if m.is_suspicious()]),
            'by_type': {},
            'total_risk_score': sum(m.risk_score for m in methods)
        }
        
        # Grouper par type
        for method in methods:
            method_type = method.method_type
            if method_type not in summary['by_type']:
                summary['by_type'][method_type] = 0
            summary['by_type'][method_type] += 1
        
        return summary
