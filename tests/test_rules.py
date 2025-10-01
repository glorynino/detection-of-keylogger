"""
Tests unitaires pour les règles de détection
"""

import unittest
import sys
import os

# Ajouter le répertoire parent au path pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules.api_rules import SuspiciousAPIRule, HookInstallationRule, MemoryAccessRule
from rules.behavior_rules import SuspiciousProcessNameRule, SuspiciousPathRule
from rules.persistence_rules import RegistryPersistenceRule, ServicePersistenceRule
from rules.base_rule import RuleSeverity


class TestAPIRules(unittest.TestCase):
    """Tests pour les règles d'API"""
    
    def setUp(self):
        self.api_rule = SuspiciousAPIRule()
        self.hook_rule = HookInstallationRule()
        self.memory_rule = MemoryAccessRule()
    
    def test_rule_initialization(self):
        """Test l'initialisation des règles"""
        self.assertEqual(self.api_rule.name, "SuspiciousAPI")
        self.assertEqual(self.api_rule.score, 10)
        self.assertEqual(self.api_rule.severity, RuleSeverity.HIGH)
        self.assertTrue(self.api_rule.enabled)
    
    def test_rule_enable_disable(self):
        """Test l'activation/désactivation des règles"""
        self.api_rule.disable()
        self.assertFalse(self.api_rule.enabled)
        
        self.api_rule.enable()
        self.assertTrue(self.api_rule.enabled)
    
    def test_rule_with_no_process(self):
        """Test les règles avec des données vides"""
        result = self.api_rule.check({})
        self.assertFalse(result.triggered)
        self.assertEqual(result.score, 0)


class TestBehaviorRules(unittest.TestCase):
    """Tests pour les règles comportementales"""
    
    def setUp(self):
        self.name_rule = SuspiciousProcessNameRule()
        self.path_rule = SuspiciousPathRule()
    
    def test_suspicious_process_name(self):
        """Test la détection de noms de processus suspects"""
        # Simuler un processus avec un nom suspect
        mock_process = MockProcess("keylogger.exe", 1234, "C:\\Windows\\System32\\keylogger.exe")
        
        result = self.name_rule.check({'process': mock_process})
        self.assertTrue(result.triggered)
        self.assertEqual(result.score, 15)
        self.assertIn('keylog', result.evidence['suspicious_keyword'])
    
    def test_normal_process_name(self):
        """Test avec un nom de processus normal"""
        mock_process = MockProcess("notepad.exe", 1234, "C:\\Windows\\System32\\notepad.exe")
        
        result = self.name_rule.check({'process': mock_process})
        self.assertFalse(result.triggered)
        self.assertEqual(result.score, 0)
    
    def test_suspicious_path(self):
        """Test la détection de chemins suspects"""
        mock_process = MockProcess("suspicious.exe", 1234, "C:\\Users\\User\\AppData\\Temp\\suspicious.exe")
        
        result = self.path_rule.check({'process': mock_process})
        self.assertTrue(result.triggered)
        self.assertEqual(result.score, 20)
        self.assertIn('temp', result.evidence['exe_path'].lower())


class TestPersistenceRules(unittest.TestCase):
    """Tests pour les règles de persistance"""
    
    def setUp(self):
        self.registry_rule = RegistryPersistenceRule()
        self.service_rule = ServicePersistenceRule()
    
    def test_registry_persistence(self):
        """Test la détection de persistance via registre"""
        mock_persistence = MockPersistenceMethod(
            method_type='registry',
            location='HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            value='C:\\Temp\\keylogger.exe',
            risk_score=25
        )
        
        result = self.registry_rule.check({'persistence_method': mock_persistence})
        self.assertTrue(result.triggered)
        self.assertEqual(result.score, 25)
        self.assertEqual(result.severity, RuleSeverity.HIGH)
    
    def test_service_persistence(self):
        """Test la détection de persistance via service"""
        mock_persistence = MockPersistenceMethod(
            method_type='service',
            location='Services',
            value='KeyloggerService',
            process_name='keylogger.exe',
            risk_score=30
        )
        
        result = self.service_rule.check({'persistence_method': mock_persistence})
        self.assertTrue(result.triggered)
        self.assertEqual(result.score, 30)
        self.assertEqual(result.severity, RuleSeverity.CRITICAL)


class MockProcess:
    """Mock d'un processus pour les tests"""
    
    def __init__(self, name, pid, exe_path):
        self._name = name
        self._pid = pid
        self._exe_path = exe_path
    
    def name(self):
        return self._name
    
    def pid(self):
        return self._pid
    
    def exe(self):
        return self._exe_path


class MockPersistenceMethod:
    """Mock d'une méthode de persistance pour les tests"""
    
    def __init__(self, method_type, location, value, process_name="", risk_score=0):
        self.method_type = method_type
        self.location = location
        self.value = value
        self.process_name = process_name
        self.risk_score = risk_score
    
    def is_suspicious(self):
        return True


class TestRuleIntegration(unittest.TestCase):
    """Tests d'intégration des règles"""
    
    def test_multiple_rules_triggered(self):
        """Test le déclenchement de plusieurs règles"""
        # Créer un processus très suspect
        mock_process = MockProcess("keylogger.exe", 1234, "C:\\Users\\User\\AppData\\Temp\\keylogger.exe")
        
        name_rule = SuspiciousProcessNameRule()
        path_rule = SuspiciousPathRule()
        
        # Vérifier que les deux règles se déclenchent
        name_result = name_rule.check({'process': mock_process})
        path_result = path_rule.check({'process': mock_process})
        
        self.assertTrue(name_result.triggered)
        self.assertTrue(path_result.triggered)
        
        # Le score total devrait être la somme des deux
        total_score = name_result.score + path_result.score
        self.assertEqual(total_score, 35)  # 15 + 20


if __name__ == '__main__':
    # Créer une suite de tests
    test_suite = unittest.TestSuite()
    
    # Ajouter les tests
    test_suite.addTest(unittest.makeSuite(TestAPIRules))
    test_suite.addTest(unittest.makeSuite(TestBehaviorRules))
    test_suite.addTest(unittest.makeSuite(TestPersistenceRules))
    test_suite.addTest(unittest.makeSuite(TestRuleIntegration))
    
    # Exécuter les tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Afficher le résumé
    print(f"\n{'='*50}")
    print(f"Tests exécutés: {result.testsRun}")
    print(f"Échecs: {len(result.failures)}")
    print(f"Erreurs: {len(result.errors)}")
    print(f"Succès: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"{'='*50}")
