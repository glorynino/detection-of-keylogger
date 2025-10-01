"""
Classe de base pour toutes les règles de détection
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from enum import Enum


class RuleSeverity(Enum):
    """Niveaux de sévérité des règles"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class RuleResult:
    """Résultat d'une règle de détection"""
    
    def __init__(self, rule_name: str, triggered: bool, score: int, 
                 severity: RuleSeverity, details: str = "", 
                 evidence: Dict[str, Any] = None):
        self.rule_name = rule_name
        self.triggered = triggered
        self.score = score
        self.severity = severity
        self.details = details
        self.evidence = evidence or {}
        self.timestamp = None


class BaseRule(ABC):
    """Classe de base pour toutes les règles de détection"""
    
    def __init__(self, name: str, description: str, score: int, 
                 severity: RuleSeverity = RuleSeverity.MEDIUM):
        self.name = name
        self.description = description
        self.score = score
        self.severity = severity
        self.enabled = True
    
    @abstractmethod
    def check(self, data: Dict[str, Any]) -> RuleResult:
        """
        Vérifie si la règle est déclenchée
        
        Args:
            data: Données à analyser (processus, API, fichiers, etc.)
            
        Returns:
            RuleResult: Résultat de la vérification
        """
        pass
    
    def enable(self):
        """Active la règle"""
        self.enabled = True
    
    def disable(self):
        """Désactive la règle"""
        self.enabled = False
    
    def __str__(self):
        return f"Rule({self.name}): {self.description} [Score: {self.score}]"
