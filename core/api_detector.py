"""
Détecteur d'API suspectes utilisées par les processus
"""

import psutil
import ctypes
from ctypes import wintypes
from typing import Dict, List, Set, Optional
import os

# Essayer d'importer pefile, utiliser fallback si non disponible
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


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
        
        # Modules Python suspects (pour détecter pynput, etc.)
        self.suspicious_python_modules = [
            'pynput',
            'keyboard',
            'pyhook',
            'pyautogui'
        ]
        
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
            'suspicious_python_modules': [],
            'total_score': 0,
            'risk_level': 'LOW'
        }
        
        try:
            # Vérifier si c'est un processus Python
            process_name_lower = process.name().lower()
            if 'python' in process_name_lower:
                # Vérifier les modules Python chargés
                python_modules = self._check_python_modules(process)
                if python_modules:
                    result['suspicious_python_modules'] = python_modules
                    result['total_score'] += len(python_modules) * 15  # +15 points par module suspect
            
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
    
    def _check_python_modules(self, process: psutil.Process) -> List[str]:
        """Vérifie si un processus Python utilise des modules suspects"""
        suspicious_found = []
        
        try:
            # Vérifier la ligne de commande pour les imports
            cmdline = ' '.join(process.cmdline())
            cmdline_lower = cmdline.lower()
            
            for module in self.suspicious_python_modules:
                if module in cmdline_lower:
                    suspicious_found.append(module)
            
            # Vérifier les fichiers ouverts pour détecter pynput
            try:
                open_files = process.open_files()
                for file_info in open_files:
                    file_path_lower = file_info.path.lower()
                    for module in self.suspicious_python_modules:
                        if module in file_path_lower and module not in suspicious_found:
                            suspicious_found.append(module)
            except (psutil.AccessDenied, AttributeError):
                pass
                
        except Exception:
            pass
        
        return suspicious_found
    
    def _get_process_modules(self, process: psutil.Process) -> List[str]:
        """Récupère la liste des modules chargés par un processus"""
        modules = []
        
        try:
            # Ajouter l'exécutable principal en premier
            if hasattr(process, 'exe'):
                try:
                    exe_path = process.exe()
                    if exe_path and os.path.exists(exe_path):
                        modules.append(exe_path)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
            
            # Utiliser memory_maps pour obtenir les modules chargés
            if hasattr(process, 'memory_maps'):
                try:
                    for mmap in process.memory_maps():
                        if mmap.path and os.path.exists(mmap.path):
                            # Filtrer seulement les fichiers PE
                            if self._is_pe_file(mmap.path):
                                modules.append(mmap.path)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
            
            # Sur Windows, essayer d'obtenir les DLL chargées via pywin32
            try:
                import win32api
                import win32process
                import win32con
                
                # Obtenir les handles des modules
                try:
                    hProcess = win32api.OpenProcess(
                        win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                        False, process.pid
                    )
                    
                    modules_win32 = win32process.EnumProcessModules(hProcess)
                    for module_handle in modules_win32:
                        try:
                            module_path = win32process.GetModuleFileNameEx(hProcess, module_handle)
                            if os.path.exists(module_path) and self._is_pe_file(module_path):
                                modules.append(module_path)
                        except:
                            continue
                    
                    win32api.CloseHandle(hProcess)
                except:
                    pass
            except ImportError:
                # pywin32 non disponible, continuer sans
                pass
                
        except Exception as e:
            print(f"[APIDetector] Erreur lors de la récupération des modules: {e}")
        
        return list(set(modules))  # Supprimer les doublons
    
    def _analyze_module(self, module_path: str) -> Dict[str, any]:
        """
        Analyse un module pour détecter l'utilisation d'API suspectes
        Utilise l'analyse PE (IAT/EAT) au lieu de la recherche de chaînes
        
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
            # Vérifier si c'est un fichier PE
            if not self._is_pe_file(module_path):
                return result
            
            # Utiliser l'analyse PE si disponible
            if PEFILE_AVAILABLE:
                pe_result = self._analyze_pe_imports(module_path)
                result['suspicious_apis'].extend(pe_result['suspicious_apis'])
                result['hook_apis'].extend(pe_result['hook_apis'])
                result['score'] += pe_result['score']
            else:
                # Fallback: recherche de chaînes (moins fiable mais fonctionne)
                result = self._analyze_module_fallback(module_path)
            
        except (FileNotFoundError, PermissionError, OSError, Exception) as e:
            # Module non accessible ou erreur d'analyse, ignorer
            pass
        
        return result
    
    def _is_pe_file(self, file_path: str) -> bool:
        """Vérifie si un fichier est un exécutable PE"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(2)
                return header == b'MZ'  # Signature PE
        except:
            return False
    
    def _analyze_pe_imports(self, module_path: str) -> Dict[str, any]:
        """
        Analyse la table d'import PE (IAT) pour détecter les APIs suspectes
        C'est la méthode correcte pour détecter les APIs importées
        """
        result = {
            'suspicious_apis': [],
            'hook_apis': [],
            'score': 0
        }
        
        try:
            pe = pefile.PE(module_path)
            
            # Analyser les imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    
                    for imp in entry.imports:
                        if imp.name:
                            api_name = imp.name.decode('utf-8', errors='ignore')
                            
                            # Vérifier si c'est une API suspecte
                            if api_name in self.suspicious_apis:
                                score = self.suspicious_apis[api_name]
                                result['suspicious_apis'].append({
                                    'name': api_name,
                                    'dll': dll_name,
                                    'score': score,
                                    'module': module_path
                                })
                                result['score'] += score
                            
                            # Détecter les hooks clavier/souris
                            if api_name in ['SetWindowsHookEx', 'SetWindowsHookExA', 'SetWindowsHookExW']:
                                result['hook_apis'].append({
                                    'type': 'HOOK_API',
                                    'api': api_name,
                                    'dll': dll_name,
                                    'module': module_path
                                })
                                result['score'] += 15
            
            # Analyser les exports (EAT) pour les DLL
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exp_name = exp.name.decode('utf-8', errors='ignore')
                        if exp_name in self.suspicious_apis:
                            result['suspicious_apis'].append({
                                'name': exp_name,
                                'dll': os.path.basename(module_path),
                                'score': self.suspicious_apis[exp_name],
                                'module': module_path,
                                'type': 'export'
                            })
                            result['score'] += self.suspicious_apis[exp_name]
            
            pe.close()
            
        except (pefile.PEFormatError, Exception) as e:
            # Fichier PE invalide ou erreur, utiliser fallback
            pass
        
        return result
    
    def _analyze_module_fallback(self, module_path: str) -> Dict[str, any]:
        """
        Méthode de fallback: recherche de chaînes (moins fiable)
        Utilisée seulement si pefile n'est pas disponible
        """
        result = {
            'suspicious_apis': [],
            'hook_apis': [],
            'score': 0
        }
        
        try:
            # Lire seulement les premiers 1MB pour éviter les gros fichiers
            with open(module_path, 'rb') as f:
                content = f.read(1024 * 1024)  # 1MB max
            
            # Rechercher les APIs suspectes (moins fiable mais fonctionne)
            for api_name, score in self.suspicious_apis.items():
                # Rechercher avec différentes variations
                patterns = [
                    api_name.encode(),
                    api_name.lower().encode(),
                    api_name.upper().encode()
                ]
                
                for pattern in patterns:
                    if pattern in content:
                        result['suspicious_apis'].append({
                            'name': api_name,
                            'score': score,
                            'module': module_path,
                            'method': 'string_search'  # Indique que c'est moins fiable
                        })
                        result['score'] += score
                        break  # Éviter les doublons
            
        except (FileNotFoundError, PermissionError, OSError):
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
