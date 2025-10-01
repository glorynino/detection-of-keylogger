"""
Règles de détection basées sur le comportement des processus
"""

import os
import time
from typing import Dict, Any, List
from .base_rule import BaseRule, RuleResult, RuleSeverity


class SuspiciousProcessNameRule(BaseRule):
    """Détecte les processus avec des noms suspects"""
    
    def __init__(self):
        super().__init__(
            name="SuspiciousProcessName",
            description="Détection de processus avec des noms suspects",
            score=15,
            severity=RuleSeverity.MEDIUM
        )
        
        self.suspicious_names = [
            'keylog', 'logger', 'spy', 'monitor', 'hook', 'capture',
            'record', 'track', 'steal', 'grab', 'sniff', 'keyboard',
            'input', 'keystroke', 'typing', 'logkeys', 'keyghost'
        ]
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie si le nom du processus est suspect"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        process = data.get('process')
        if not process:
            return RuleResult(self.name, False, 0, self.severity)
        
        process_name = process.name().lower()
        
        for suspicious_name in self.suspicious_names:
            if suspicious_name in process_name:
                evidence = {
                    'process_name': process.name(),
                    'process_pid': process.pid,
                    'suspicious_keyword': suspicious_name
                }
                
                return RuleResult(
                    rule_name=self.name,
                    triggered=True,
                    score=self.score,
                    severity=self.severity,
                    details=f"Nom de processus suspect détecté: {process.name()}",
                    evidence=evidence
                )
        
        return RuleResult(self.name, False, 0, self.severity)


class SuspiciousPathRule(BaseRule):
    """Détecte les processus exécutés depuis des chemins suspects"""
    
    def __init__(self):
        super().__init__(
            name="SuspiciousPath",
            description="Détection de processus exécutés depuis des chemins suspects",
            score=20,
            severity=RuleSeverity.HIGH
        )
        
        self.suspicious_paths = [
            '%TEMP%', '%APPDATA%', '%LOCALAPPDATA%',
            'temp', 'tmp', 'appdata', 'localappdata',
            'downloads', 'documents', 'desktop'
        ]
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie si le processus est exécuté depuis un chemin suspect"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        process = data.get('process')
        if not process:
            return RuleResult(self.name, False, 0, self.severity)
        
        try:
            exe_path = process.exe()
            if not exe_path:
                return RuleResult(self.name, False, 0, self.severity)
            
            exe_path_lower = exe_path.lower()
            
            for suspicious_path in self.suspicious_paths:
                if suspicious_path.lower() in exe_path_lower:
                    evidence = {
                        'process_name': process.name(),
                        'process_pid': process.pid,
                        'exe_path': exe_path,
                        'suspicious_path': suspicious_path
                    }
                    
                    return RuleResult(
                        rule_name=self.name,
                        triggered=True,
                        score=self.score,
                        severity=self.severity,
                        details=f"Processus exécuté depuis un chemin suspect: {exe_path}",
                        evidence=evidence
                    )
        
        except (AttributeError, OSError):
            pass
        
        return RuleResult(self.name, False, 0, self.severity)


class HighCPUUsageRule(BaseRule):
    """Détecte les processus avec une utilisation CPU élevée"""
    
    def __init__(self):
        super().__init__(
            name="HighCPUUsage",
            description="Détection de processus avec utilisation CPU élevée",
            score=10,
            severity=RuleSeverity.MEDIUM
        )
        
        self.cpu_threshold = 50.0  # Pourcentage
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie si le processus utilise beaucoup de CPU"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        process = data.get('process')
        if not process:
            return RuleResult(self.name, False, 0, self.severity)
        
        try:
            cpu_percent = process.cpu_percent()
            
            if cpu_percent > self.cpu_threshold:
                evidence = {
                    'process_name': process.name(),
                    'process_pid': process.pid,
                    'cpu_percent': cpu_percent,
                    'threshold': self.cpu_threshold
                }
                
                return RuleResult(
                    rule_name=self.name,
                    triggered=True,
                    score=self.score,
                    severity=self.severity,
                    details=f"Utilisation CPU élevée: {cpu_percent:.1f}%",
                    evidence=evidence
                )
        
        except (AttributeError, OSError):
            pass
        
        return RuleResult(self.name, False, 0, self.severity)


class SuspiciousArgumentsRule(BaseRule):
    """Détecte les processus avec des arguments de ligne de commande suspects"""
    
    def __init__(self):
        super().__init__(
            name="SuspiciousArguments",
            description="Détection de processus avec des arguments suspects",
            score=15,
            severity=RuleSeverity.MEDIUM
        )
        
        self.suspicious_args = [
            '--keylog', '--log', '--hook', '--capture', '--record',
            '--steal', '--grab', '--sniff', '--monitor', '--spy',
            '-k', '-l', '-h', '-c', '-r', '-s', '-g', '-m'
        ]
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie si le processus a des arguments suspects"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        process = data.get('process')
        if not process:
            return RuleResult(self.name, False, 0, self.severity)
        
        try:
            cmdline = process.cmdline()
            if not cmdline:
                return RuleResult(self.name, False, 0, self.severity)
            
            cmdline_str = ' '.join(cmdline).lower()
            
            for suspicious_arg in self.suspicious_args:
                if suspicious_arg in cmdline_str:
                    evidence = {
                        'process_name': process.name(),
                        'process_pid': process.pid,
                        'cmdline': ' '.join(cmdline),
                        'suspicious_arg': suspicious_arg
                    }
                    
                    return RuleResult(
                        rule_name=self.name,
                        triggered=True,
                        score=self.score,
                        severity=self.severity,
                        details=f"Arguments suspects détectés: {suspicious_arg}",
                        evidence=evidence
                    )
        
        except (AttributeError, OSError):
            pass
        
        return RuleResult(self.name, False, 0, self.severity)


class MultipleSuspiciousProcessesRule(BaseRule):
    """Détecte la présence de plusieurs processus suspects"""
    
    def __init__(self):
        super().__init__(
            name="MultipleSuspiciousProcesses",
            description="Détection de plusieurs processus suspects simultanés",
            score=25,
            severity=RuleSeverity.HIGH
        )
        
        self.suspicious_names = [
            'keylog', 'logger', 'spy', 'monitor', 'hook', 'capture'
        ]
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie s'il y a plusieurs processus suspects"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        # Cette règle nécessite une vue globale des processus
        # Elle sera implémentée dans le moteur de règles
        return RuleResult(self.name, False, 0, self.severity)


class ProcessInjectionRule(BaseRule):
    """Détecte les tentatives d'injection de processus"""
    
    def __init__(self):
        super().__init__(
            name="ProcessInjection",
            description="Détection de tentatives d'injection de processus",
            score=30,
            severity=RuleSeverity.CRITICAL
        )
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie les signes d'injection de processus"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        process = data.get('process')
        if not process:
            return RuleResult(self.name, False, 0, self.severity)
        
        try:
            # Vérifier les modules chargés
            modules = []
            if hasattr(process, 'memory_maps'):
                for mmap in process.memory_maps():
                    if mmap.path:
                        modules.append(mmap.path)
            
            # Rechercher des modules suspects
            suspicious_modules = []
            for module in modules:
                module_lower = module.lower()
                if any(sus in module_lower for sus in ['inject', 'dll', 'hook', 'keylog']):
                    suspicious_modules.append(module)
            
            if suspicious_modules:
                evidence = {
                    'process_name': process.name(),
                    'process_pid': process.pid,
                    'suspicious_modules': suspicious_modules,
                    'total_modules': len(modules)
                }
                
                return RuleResult(
                    rule_name=self.name,
                    triggered=True,
                    score=self.score,
                    severity=self.severity,
                    details=f"Modules suspects détectés: {len(suspicious_modules)}",
                    evidence=evidence
                )
        
        except (AttributeError, OSError):
            pass
        
        return RuleResult(self.name, False, 0, self.severity)
