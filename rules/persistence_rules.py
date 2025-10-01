"""
Règles de détection pour les méthodes de persistance
"""

from typing import Dict, Any
from .base_rule import BaseRule, RuleResult, RuleSeverity


class RegistryPersistenceRule(BaseRule):
    """Détecte les méthodes de persistance via le registre"""
    
    def __init__(self):
        super().__init__(
            name="RegistryPersistence",
            description="Détection de persistance via le registre Windows",
            score=25,
            severity=RuleSeverity.HIGH
        )
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie les méthodes de persistance dans le registre"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        persistence_method = data.get('persistence_method')
        if not persistence_method:
            return RuleResult(self.name, False, 0, self.severity)
        
        if persistence_method.method_type == 'registry':
            evidence = {
                'method_type': persistence_method.method_type,
                'location': persistence_method.location,
                'value': persistence_method.value,
                'risk_score': persistence_method.risk_score
            }
            
            return RuleResult(
                rule_name=self.name,
                triggered=True,
                score=self.score,
                severity=self.severity,
                details=f"Persistance via registre détectée: {persistence_method.location}",
                evidence=evidence
            )
        
        return RuleResult(self.name, False, 0, self.severity)


class ServicePersistenceRule(BaseRule):
    """Détecte les services de persistance"""
    
    def __init__(self):
        super().__init__(
            name="ServicePersistence",
            description="Détection de services de persistance",
            score=30,
            severity=RuleSeverity.CRITICAL
        )
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie les services de persistance"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        persistence_method = data.get('persistence_method')
        if not persistence_method:
            return RuleResult(self.name, False, 0, self.severity)
        
        if persistence_method.method_type == 'service':
            evidence = {
                'method_type': persistence_method.method_type,
                'location': persistence_method.location,
                'value': persistence_method.value,
                'process_name': persistence_method.process_name,
                'risk_score': persistence_method.risk_score
            }
            
            return RuleResult(
                rule_name=self.name,
                triggered=True,
                score=self.score,
                severity=self.severity,
                details=f"Service de persistance détecté: {persistence_method.value}",
                evidence=evidence
            )
        
        return RuleResult(self.name, False, 0, self.severity)


class StartupFolderPersistenceRule(BaseRule):
    """Détecte la persistance via les dossiers de démarrage"""
    
    def __init__(self):
        super().__init__(
            name="StartupFolderPersistence",
            description="Détection de persistance via les dossiers de démarrage",
            score=20,
            severity=RuleSeverity.MEDIUM
        )
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie la persistance via les dossiers de démarrage"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        persistence_method = data.get('persistence_method')
        if not persistence_method:
            return RuleResult(self.name, False, 0, self.severity)
        
        if persistence_method.method_type == 'startup_folder':
            evidence = {
                'method_type': persistence_method.method_type,
                'location': persistence_method.location,
                'value': persistence_method.value,
                'risk_score': persistence_method.risk_score
            }
            
            return RuleResult(
                rule_name=self.name,
                triggered=True,
                score=self.score,
                severity=self.severity,
                details=f"Persistance via dossier de démarrage: {persistence_method.value}",
                evidence=evidence
            )
        
        return RuleResult(self.name, False, 0, self.severity)


class ScheduledTaskPersistenceRule(BaseRule):
    """Détecte la persistance via les tâches planifiées"""
    
    def __init__(self):
        super().__init__(
            name="ScheduledTaskPersistence",
            description="Détection de persistance via les tâches planifiées",
            score=25,
            severity=RuleSeverity.HIGH
        )
    
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """Vérifie la persistance via les tâches planifiées"""
        if not self.enabled:
            return RuleResult(self.name, False, 0, self.severity)
        
        persistence_method = data.get('persistence_method')
        if not persistence_method:
            return RuleResult(self.name, False, 0, self.severity)
        
        if persistence_method.method_type == 'scheduled_task':
            evidence = {
                'method_type': persistence_method.method_type,
                'location': persistence_method.location,
                'value': persistence_method.value,
                'process_name': persistence_method.process_name,
                'risk_score': persistence_method.risk_score
            }
            
            return RuleResult(
                rule_name=self.name,
                triggered=True,
                score=self.score,
                severity=self.severity,
                details=f"Tâche planifiée de persistance: {persistence_method.value}",
                evidence=evidence
            )
        
        return RuleResult(self.name, False, 0, self.severity)
