"""
Règles de détection basées sur l'utilisation d'API suspectes
"""

import psutil
from typing import Dict, Any, List
from .base_rule import BaseRule, RuleResult, RuleSeverity
from config.settings import SUSPICIOUS_APIS


class SuspiciousAPIRule(BaseRule):
    """Détecte l'utilisation d'API suspectes par un processus"""
    
    def __init__(self):
        super().__init__(
            name="SuspiciousAPI",
            description="Détection d'utilisation d'API suspectes",
            score=10,
            severity=RuleSeverity.HIGH
        )
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie si un processus utilise des API suspectes"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        process = data.get('process')
        if not process:
            return RuleResult(self.name, False, 0, self.severity)
        
        try:
            # Obtenir les modules chargés par le processus
            modules = self._get_process_modules(process)
            suspicious_apis_found = []
            
            for module in modules:
                for api in SUSPICIOUS_APIS:
                    if api.lower() in module.lower():
                        suspicious_apis_found.append(api)
            
            if suspicious_apis_found:
                evidence = {
                    'process_name': process.name(),
                    'process_pid': process.pid,
                    'suspicious_apis': suspicious_apis_found,
                    'modules': modules
                }
                
                return RuleResult(
                    rule_name=self.name,
                    triggered=True,
                    score=self.score * len(suspicious_apis_found),
                    severity=self.severity,
                    details=f"API suspectes détectées: {', '.join(suspicious_apis_found)}",
                    evidence=evidence
                )
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        
        return RuleResult(self.name, False, 0, self.severity)
    
    def _get_process_modules(self, process) -> List[str]:
        """Récupère la liste des modules chargés par un processus"""
        try:
            # Sur Windows, on peut utiliser psutil pour obtenir les modules
            if hasattr(process, 'memory_maps'):
                modules = []
                for mmap in process.memory_maps():
                    if mmap.path:
                        modules.append(mmap.path)
                return modules
            else:
                # Fallback: utiliser le nom du processus
                return [process.name()]
        except:
            return []


class HookInstallationRule(BaseRule):
    """Détecte l'installation de hooks clavier/souris"""
    
    def __init__(self):
        super().__init__(
            name="HookInstallation",
            description="Détection d'installation de hooks système",
            score=15,
            severity=RuleSeverity.HIGH
        )
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie si un processus installe des hooks"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        process = data.get('process')
        if not process:
            return RuleResult(self.name, False, 0, self.severity)
        
        try:
            # Vérifier si le processus utilise des API de hook
            hook_apis = ['SetWindowsHookEx', 'SetWindowsHookExA', 'SetWindowsHookExW']
            modules = self._get_process_modules(process)
            
            hook_apis_found = []
            for module in modules:
                for api in hook_apis:
                    if api.lower() in module.lower():
                        hook_apis_found.append(api)
            
            if hook_apis_found:
                evidence = {
                    'process_name': process.name(),
                    'process_pid': process.pid,
                    'hook_apis': hook_apis_found
                }
                
                return RuleResult(
                    rule_name=self.name,
                    triggered=True,
                    score=self.score,
                    severity=self.severity,
                    details=f"Hooks système détectés: {', '.join(hook_apis_found)}",
                    evidence=evidence
                )
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        
        return RuleResult(self.name, False, 0, self.severity)
    
    def _get_process_modules(self, process) -> List[str]:
        """Récupère la liste des modules chargés par un processus"""
        try:
            if hasattr(process, 'memory_maps'):
                modules = []
                for mmap in process.memory_maps():
                    if mmap.path:
                        modules.append(mmap.path)
                return modules
            else:
                return [process.name()]
        except:
            return []


class MemoryAccessRule(BaseRule):
    """Détecte l'accès suspect à la mémoire d'autres processus"""
    
    def __init__(self):
        super().__init__(
            name="MemoryAccess",
            description="Détection d'accès suspect à la mémoire",
            score=20,
            severity=RuleSeverity.CRITICAL
        )
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie si un processus accède à la mémoire d'autres processus"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        process = data.get('process')
        if not process:
            return RuleResult(self.name, False, 0, self.severity)
        
        try:
            # Vérifier les API d'accès mémoire
            memory_apis = ['ReadProcessMemory', 'WriteProcessMemory', 'VirtualAllocEx']
            modules = self._get_process_modules(process)
            
            memory_apis_found = []
            for module in modules:
                for api in memory_apis:
                    if api.lower() in module.lower():
                        memory_apis_found.append(api)
            
            if memory_apis_found:
                evidence = {
                    'process_name': process.name(),
                    'process_pid': process.pid,
                    'memory_apis': memory_apis_found
                }
                
                return RuleResult(
                    rule_name=self.name,
                    triggered=True,
                    score=self.score,
                    severity=self.severity,
                    details=f"Accès mémoire suspect détecté: {', '.join(memory_apis_found)}",
                    evidence=evidence
                )
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        
        return RuleResult(self.name, False, 0, self.severity)
    
    def _get_process_modules(self, process) -> List[str]:
        """Récupère la liste des modules chargés par un processus"""
        try:
            if hasattr(process, 'memory_maps'):
                modules = []
                for mmap in process.memory_maps():
                    if mmap.path:
                        modules.append(mmap.path)
                return modules
            else:
                return [process.name()]
        except:
            return []
