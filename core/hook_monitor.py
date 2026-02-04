"""
Module de surveillance des hooks Windows installés
"""

import ctypes
from ctypes import wintypes
from typing import Dict, List, Optional
import psutil


class WindowsHook:
    """Représente un hook Windows installé"""
    
    def __init__(self, hook_type: int, hook_handle: int, process_id: int, 
                 process_name: str = ""):
        self.hook_type = hook_type
        self.hook_handle = hook_handle
        self.process_id = process_id
        self.process_name = process_name
        self.is_suspicious = False
        
        # Types de hooks suspects
        self.suspicious_hook_types = {
            2: 'WH_KEYBOARD',      # Hook clavier
            13: 'WH_KEYBOARD_LL',  # Low-level hook clavier
            7: 'WH_MOUSE',         # Hook souris
            14: 'WH_MOUSE_LL'      # Low-level hook souris
        }
        
        self._check_suspicious()
    
    def _check_suspicious(self):
        """Détermine si ce hook est suspect"""
        # Les hooks clavier/souris sont toujours suspects
        if self.hook_type in [2, 13, 7, 14]:
            self.is_suspicious = True
        
        # Vérifier le nom du processus
        suspicious_names = ['keylog', 'logger', 'spy', 'monitor', 'hook', 
                          'capture', 'record', 'track']
        if any(sus in self.process_name.lower() for sus in suspicious_names):
            self.is_suspicious = True
    
    def get_hook_type_name(self) -> str:
        """Retourne le nom du type de hook"""
        return self.suspicious_hook_types.get(self.hook_type, f'UNKNOWN({self.hook_type})')
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            'hook_type': self.hook_type,
            'hook_type_name': self.get_hook_type_name(),
            'hook_handle': self.hook_handle,
            'process_id': self.process_id,
            'process_name': self.process_name,
            'is_suspicious': self.is_suspicious
        }


class HookMonitor:
    """Surveillant des hooks Windows installés"""
    
    def __init__(self):
        # Constantes Windows pour les hooks
        self.WH_KEYBOARD = 2
        self.WH_KEYBOARD_LL = 13
        self.WH_MOUSE = 7
        self.WH_MOUSE_LL = 14
        self.WH_GETMESSAGE = 3
        self.WH_CALLWNDPROC = 4
        
        # Types de hooks à surveiller
        self.monitored_hook_types = [
            self.WH_KEYBOARD,
            self.WH_KEYBOARD_LL,
            self.WH_MOUSE,
            self.WH_MOUSE_LL
        ]
    
    def enumerate_hooks(self) -> List[WindowsHook]:
        """
        Énumère tous les hooks Windows installés
        Note: Windows ne fournit pas d'API directe pour énumérer les hooks,
        donc on utilise une méthode indirecte via l'analyse des processus
        """
        hooks = []
        
        try:
            # Méthode 1: Analyser les processus pour détecter les hooks installés
            # On vérifie les processus qui utilisent SetWindowsHookEx
            processes = psutil.process_iter(['pid', 'name'])
            
            for proc_info in processes:
                try:
                    process = psutil.Process(proc_info.info['pid'])
                    
                    # Vérifier si le processus utilise des hooks
                    # En analysant les modules chargés et les APIs utilisées
                    hook_info = self._check_process_hooks(process)
                    
                    if hook_info:
                        for hook in hook_info:
                            hooks.append(hook)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            print(f"[HookMonitor] Erreur lors de l'énumération des hooks: {e}")
        
        return hooks
    
    def _check_process_hooks(self, process: psutil.Process) -> List[WindowsHook]:
        """Vérifie si un processus a installé des hooks"""
        hooks = []
        
        try:
            # Obtenir le nom du processus
            process_name = process.name()
            process_pid = process.pid
            
            # Vérifier les modules chargés pour détecter l'utilisation de hooks
            # Cette méthode est indirecte mais fonctionne
            if hasattr(process, 'memory_maps'):
                for mmap in process.memory_maps():
                    if mmap.path:
                        # Analyser le module pour détecter les hooks
                        hook_types = self._analyze_module_for_hooks(mmap.path)
                        
                        for hook_type in hook_types:
                            hook = WindowsHook(
                                hook_type=hook_type,
                                hook_handle=0,  # Non disponible sans hook direct
                                process_id=process_pid,
                                process_name=process_name
                            )
                            hooks.append(hook)
        
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return hooks
    
    def _analyze_module_for_hooks(self, module_path: str) -> List[int]:
        """Analyse un module pour détecter les types de hooks utilisés"""
        hook_types = []
        
        try:
            # Essayer d'utiliser pefile pour analyser les imports
            try:
                import pefile
                pe = pefile.PE(module_path)
                
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        
                        # Vérifier si le module utilise SetWindowsHookEx
                        for imp in entry.imports:
                            if imp.name:
                                api_name = imp.name.decode('utf-8', errors='ignore')
                                
                                if api_name in ['SetWindowsHookEx', 'SetWindowsHookExA', 'SetWindowsHookExW']:
                                    # Si SetWindowsHookEx est utilisé, on suppose qu'un hook peut être installé
                                    # On retourne les types de hooks les plus suspects
                                    hook_types.extend([self.WH_KEYBOARD_LL, self.WH_KEYBOARD])
                
                pe.close()
            except:
                # Fallback: recherche de chaînes
                with open(module_path, 'rb') as f:
                    content = f.read(1024 * 1024)  # 1MB max
                    
                    # Rechercher les constantes de hooks
                    if b'WH_KEYBOARD_LL' in content or b'13' in content:
                        hook_types.append(self.WH_KEYBOARD_LL)
                    if b'WH_KEYBOARD' in content or b'2' in content:
                        hook_types.append(self.WH_KEYBOARD)
                    if b'WH_MOUSE_LL' in content or b'14' in content:
                        hook_types.append(self.WH_MOUSE_LL)
                    if b'WH_MOUSE' in content or b'7' in content:
                        hook_types.append(self.WH_MOUSE)
        
        except (FileNotFoundError, PermissionError, OSError):
            pass
        
        return list(set(hook_types))  # Supprimer les doublons
    
    def get_suspicious_hooks(self) -> List[WindowsHook]:
        """Retourne seulement les hooks suspects"""
        all_hooks = self.enumerate_hooks()
        return [hook for hook in all_hooks if hook.is_suspicious]
    
    def get_hooks_summary(self) -> Dict:
        """Retourne un résumé des hooks détectés"""
        hooks = self.enumerate_hooks()
        suspicious_hooks = self.get_suspicious_hooks()
        
        summary = {
            'total_hooks': len(hooks),
            'suspicious_hooks': len(suspicious_hooks),
            'by_type': {},
            'by_process': {}
        }
        
        # Grouper par type
        for hook in hooks:
            hook_type_name = hook.get_hook_type_name()
            if hook_type_name not in summary['by_type']:
                summary['by_type'][hook_type_name] = 0
            summary['by_type'][hook_type_name] += 1
        
        # Grouper par processus
        for hook in hooks:
            process_name = hook.process_name
            if process_name not in summary['by_process']:
                summary['by_process'][process_name] = 0
            summary['by_process'][process_name] += 1
        
        return summary

