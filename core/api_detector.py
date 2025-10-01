"""
Détecteur d'API suspectes utilisées par les processus
"""

import psutil
import ctypes
from ctypes import wintypes
from typing import Dict, List, Set, Optional
import os


class APIDetector:
    """Détecteur d'API suspectes dans les processus"""
    
    def __init__(self):
        self.suspicious_apis = {
            'SetWindowsHookEx': 15,
            'SetWindowsHookExA': 15,
            'SetWindowsHookExW': 15,
            'GetAsyncKeyState': 10,
            'GetKeyState': 10,
            'ReadProcessMemory': 20,
            'WriteProcessMemory': 20,
            'VirtualAllocEx': 15,
            'CreateRemoteThread': 25,
            'SetWindowsHook': 15,
            'UnhookWindowsHookEx': 10,
            'CallNextHookEx': 5,
            'GetMessage': 5,
            'PeekMessage': 5,
            'TranslateMessage': 5,
            'DispatchMessage': 5
        }
        
        # APIs de hook spécifiques
        self.hook_apis = {
            'WH_KEYBOARD': 2,
            'WH_KEYBOARD_LL': 13,
            'WH_MOUSE': 7,
            'WH_MOUSE_LL': 14,
            'WH_GETMESSAGE': 3,
            'WH_CALLWNDPROC': 4
        }
    
    def scan_process(self, process: psutil.Process) -> Dict[str, any]:
        """
        Scanne un processus pour détecter l'utilisation d'API suspectes
        
        Args:
            process: Processus à scanner
            
        Returns:
            Dict contenant les résultats de l'analyse
        """
        result = {
            'process_name': process.name(),
            'process_pid': process.pid,
            'suspicious_apis': [],
            'hook_apis': [],
            'total_score': 0,
            'risk_level': 'LOW'
        }
        
        try:
            # Obtenir les modules chargés
            modules = self._get_process_modules(process)
            
            # Analyser chaque module
            for module_path in modules:
                api_results = self._analyze_module(module_path)
                result['suspicious_apis'].extend(api_results['suspicious_apis'])
                result['hook_apis'].extend(api_results['hook_apis'])
                result['total_score'] += api_results['score']
            
            # Déterminer le niveau de risque
            result['risk_level'] = self._calculate_risk_level(result['total_score'])
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            result['error'] = str(e)
        
        return result
    
    def _get_process_modules(self, process: psutil.Process) -> List[str]:
        """Récupère la liste des modules chargés par un processus"""
        modules = []
        
        try:
            # Utiliser memory_maps pour obtenir les modules
            if hasattr(process, 'memory_maps'):
                for mmap in process.memory_maps():
                    if mmap.path and os.path.exists(mmap.path):
                        modules.append(mmap.path)
            
            # Ajouter l'exécutable principal
            if hasattr(process, 'exe') and process.exe():
                modules.append(process.exe())
                
        except Exception as e:
            print(f"[APIDetector] Erreur lors de la récupération des modules: {e}")
        
        return list(set(modules))  # Supprimer les doublons
    
    def _analyze_module(self, module_path: str) -> Dict[str, any]:
        """
        Analyse un module pour détecter l'utilisation d'API suspectes
        
        Args:
            module_path: Chemin vers le module à analyser
            
        Returns:
            Dict contenant les APIs détectées et le score
        """
        result = {
            'suspicious_apis': [],
            'hook_apis': [],
            'score': 0
        }
        
        try:
            # Lire le contenu du fichier
            with open(module_path, 'rb') as f:
                content = f.read()
            
            # Rechercher les APIs suspectes
            for api_name, score in self.suspicious_apis.items():
                if api_name.encode() in content:
                    result['suspicious_apis'].append({
                        'name': api_name,
                        'score': score,
                        'module': module_path
                    })
                    result['score'] += score
            
            # Rechercher les types de hooks
            for hook_type, hook_id in self.hook_apis.items():
                if str(hook_id).encode() in content:
                    result['hook_apis'].append({
                        'type': hook_type,
                        'id': hook_id,
                        'module': module_path
                    })
                    result['score'] += 5  # Score bonus pour les hooks
            
        except (FileNotFoundError, PermissionError, OSError) as e:
            # Module non accessible, ignorer
            pass
        
        return result
    
    def _calculate_risk_level(self, score: int) -> str:
        """Calcule le niveau de risque basé sur le score"""
        if score >= 50:
            return 'CRITICAL'
        elif score >= 30:
            return 'HIGH'
        elif score >= 15:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_api_usage_summary(self, processes: List[psutil.Process]) -> Dict[str, any]:
        """
        Génère un résumé de l'utilisation d'API pour une liste de processus
        
        Args:
            processes: Liste des processus à analyser
            
        Returns:
            Dict contenant le résumé
        """
        summary = {
            'total_processes': len(processes),
            'suspicious_processes': 0,
            'total_score': 0,
            'api_usage': {},
            'risk_distribution': {
                'LOW': 0,
                'MEDIUM': 0,
                'HIGH': 0,
                'CRITICAL': 0
            }
        }
        
        for process in processes:
            try:
                result = self.scan_process(process)
                
                if result['total_score'] > 0:
                    summary['suspicious_processes'] += 1
                    summary['total_score'] += result['total_score']
                    summary['risk_distribution'][result['risk_level']] += 1
                    
                    # Compter l'utilisation des APIs
                    for api in result['suspicious_apis']:
                        api_name = api['name']
                        if api_name not in summary['api_usage']:
                            summary['api_usage'][api_name] = 0
                        summary['api_usage'][api_name] += 1
                        
            except Exception as e:
                continue
        
        return summary
    
    def is_keylogger_behavior(self, api_results: Dict[str, any]) -> bool:
        """
        Détermine si les résultats d'API indiquent un comportement de keylogger
        
        Args:
            api_results: Résultats de l'analyse d'API
            
        Returns:
            True si le comportement ressemble à un keylogger
        """
        # Critères pour identifier un keylogger
        keylogger_apis = ['GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookEx']
        hook_apis = ['WH_KEYBOARD', 'WH_KEYBOARD_LL']
        
        # Vérifier la présence d'APIs de keylogger
        has_keylogger_apis = any(
            api['name'] in keylogger_apis 
            for api in api_results.get('suspicious_apis', [])
        )
        
        # Vérifier la présence de hooks clavier
        has_keyboard_hooks = any(
            hook['type'] in hook_apis 
            for hook in api_results.get('hook_apis', [])
        )
        
        # Score élevé
        high_score = api_results.get('total_score', 0) >= 20
        
        return (has_keylogger_apis or has_keyboard_hooks) and high_score
