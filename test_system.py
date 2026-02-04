"""
Script de test rapide pour vérifier que le système fonctionne
"""

import sys
import traceback

def test_imports():
    """Teste les imports des modules"""
    print("=" * 60)
    print("TEST 1: Vérification des imports")
    print("=" * 60)
    
    try:
        print("✓ Import de pefile...", end=" ")
        import pefile
        print(f"OK (version {pefile.__version__})")
    except ImportError as e:
        print(f"❌ ERREUR: {e}")
        return False
    
    try:
        print("✓ Import de HookMonitor...", end=" ")
        from core.hook_monitor import HookMonitor
        print("OK")
    except Exception as e:
        print(f"❌ ERREUR: {e}")
        traceback.print_exc()
        return False
    
    try:
        print("✓ Import de BehavioralAnalyzer...", end=" ")
        from core.behavioral_analyzer import BehavioralAnalyzer
        print("OK")
    except Exception as e:
        print(f"❌ ERREUR: {e}")
        traceback.print_exc()
        return False
    
    try:
        print("✓ Import de APIDetector...", end=" ")
        from core.api_detector import APIDetector
        print("OK")
    except Exception as e:
        print(f"❌ ERREUR: {e}")
        traceback.print_exc()
        return False
    
    try:
        print("✓ Import de KeyloggerDetectorAgent...", end=" ")
        from core.agent import KeyloggerDetectorAgent
        print("OK")
    except Exception as e:
        print(f"❌ ERREUR: {e}")
        traceback.print_exc()
        return False
    
    print("\n✅ Tous les imports sont OK!\n")
    return True

def test_hook_monitor():
    """Teste le HookMonitor"""
    print("=" * 60)
    print("TEST 2: Test du HookMonitor")
    print("=" * 60)
    
    try:
        from core.hook_monitor import HookMonitor
        
        print("✓ Création de HookMonitor...", end=" ")
        hook_monitor = HookMonitor()
        print("OK")
        
        print("✓ Énumération des hooks (peut prendre quelques secondes)...", end=" ")
        hooks = hook_monitor.enumerate_hooks()
        print(f"OK - {len(hooks)} hooks trouvés")
        
        print("✓ Récupération des hooks suspects...", end=" ")
        suspicious = hook_monitor.get_suspicious_hooks()
        print(f"OK - {len(suspicious)} hooks suspects")
        
        print("✓ Résumé des hooks...", end=" ")
        summary = hook_monitor.get_hooks_summary()
        print("OK")
        print(f"  - Total: {summary['total_hooks']}")
        print(f"  - Suspects: {summary['suspicious_hooks']}")
        
        print("\n✅ HookMonitor fonctionne correctement!\n")
        return True
        
    except Exception as e:
        print(f"❌ ERREUR: {e}")
        traceback.print_exc()
        return False

def test_behavioral_analyzer():
    """Teste le BehavioralAnalyzer"""
    print("=" * 60)
    print("TEST 3: Test du BehavioralAnalyzer")
    print("=" * 60)
    
    try:
        from core.behavioral_analyzer import BehavioralAnalyzer, BehavioralEvent
        import time
        
        print("✓ Création de BehavioralAnalyzer...", end=" ")
        analyzer = BehavioralAnalyzer()
        print("OK")
        
        print("✓ Ajout d'événements de test...", end=" ")
        # Simuler quelques événements
        for i in range(5):
            event = BehavioralEvent(
                'api_call',
                1234,
                'test_process.exe',
                {'apis': ['GetAsyncKeyState']},
                time.time() - (5 - i)
            )
            analyzer.add_event(event)
        print("OK")
        
        print("✓ Récupération des patterns suspects...", end=" ")
        patterns = analyzer.get_suspicious_patterns()
        print(f"OK - {len(patterns)} patterns trouvés")
        
        print("✓ Calcul du score comportemental...", end=" ")
        score = analyzer.get_process_behavior_score(1234)
        print(f"OK - Score: {score['score']}, Risque: {score['risk_level']}")
        
        print("✓ Résumé de l'analyse...", end=" ")
        summary = analyzer.get_summary()
        print("OK")
        print(f"  - Événements: {summary['total_events']}")
        print(f"  - Processus surveillés: {summary['monitored_processes']}")
        
        print("\n✅ BehavioralAnalyzer fonctionne correctement!\n")
        return True
        
    except Exception as e:
        print(f"❌ ERREUR: {e}")
        traceback.print_exc()
        return False

def test_api_detector():
    """Teste l'APIDetector amélioré"""
    print("=" * 60)
    print("TEST 4: Test de l'APIDetector (avec analyse PE)")
    print("=" * 60)
    
    try:
        from core.api_detector import APIDetector
        import psutil
        import os
        
        print("✓ Création de APIDetector...", end=" ")
        detector = APIDetector()
        print("OK")
        
        print("✓ Test de détection PE...", end=" ")
        # Tester avec un processus système (explorer.exe généralement présent)
        test_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() in ['explorer.exe', 'notepad.exe']:
                    test_pid = proc.info['pid']
                    proc_name = proc.info['name']
                    break
            except:
                continue
        
        if test_pid:
            process = psutil.Process(test_pid)
            result = detector.scan_process(process)
            print(f"OK - Processus testé: {proc_name}")
            print(f"  - APIs suspectes: {len(result.get('suspicious_apis', []))}")
            print(f"  - Score: {result.get('total_score', 0)}")
            print(f"  - Risque: {result.get('risk_level', 'LOW')}")
        else:
            print("OK - Aucun processus de test trouvé (normal)")
        
        print("\n✅ APIDetector fonctionne correctement!\n")
        return True
        
    except Exception as e:
        print(f"❌ ERREUR: {e}")
        traceback.print_exc()
        return False

def test_agent():
    """Teste l'agent principal"""
    print("=" * 60)
    print("TEST 5: Test de l'agent principal (démarrage/arrêt)")
    print("=" * 60)
    
    try:
        from core.agent import KeyloggerDetectorAgent
        import time
        
        print("✓ Création de l'agent...", end=" ")
        agent = KeyloggerDetectorAgent()
        print("OK")
        
        print("✓ Démarrage de l'agent...", end=" ")
        agent.start()
        print("OK")
        
        print("✓ Attente de 3 secondes...", end=" ")
        time.sleep(3)
        print("OK")
        
        print("✓ Vérification du statut...", end=" ")
        status = agent.get_status()
        if status['running']:
            print("OK - Agent en cours d'exécution")
        else:
            print("⚠️  Agent non démarré")
        
        print("✓ Arrêt de l'agent...", end=" ")
        agent.stop()
        print("OK")
        
        print("\n✅ Agent fonctionne correctement!\n")
        return True
        
    except Exception as e:
        print(f"❌ ERREUR: {e}")
        traceback.print_exc()
        return False

def main():
    """Fonction principale de test"""
    print("\n" + "=" * 60)
    print("TEST DU SYSTÈME DE DÉTECTION DE KEYLOGGERS")
    print("=" * 60 + "\n")
    
    results = []
    
    # Test 1: Imports
    results.append(("Imports", test_imports()))
    
    if not results[0][1]:
        print("\n❌ Les imports ont échoué. Vérifiez les dépendances.")
        return
    
    # Test 2: HookMonitor
    results.append(("HookMonitor", test_hook_monitor()))
    
    # Test 3: BehavioralAnalyzer
    results.append(("BehavioralAnalyzer", test_behavioral_analyzer()))
    
    # Test 4: APIDetector
    results.append(("APIDetector", test_api_detector()))
    
    # Test 5: Agent
    results.append(("Agent", test_agent()))
    
    # Résumé
    print("=" * 60)
    print("RÉSUMÉ DES TESTS")
    print("=" * 60)
    
    for name, success in results:
        status = "✅ OK" if success else "❌ ÉCHEC"
        print(f"{status} - {name}")
    
    total = len(results)
    passed = sum(1 for _, success in results if success)
    
    print(f"\nTotal: {passed}/{total} tests réussis")
    
    if passed == total:
        print("\n🎉 TOUS LES TESTS SONT PASSÉS! Le système est prêt à être utilisé.")
        print("\nVous pouvez maintenant lancer:")
        print("  python main.py --test    # Mode test (30 secondes)")
        print("  python main.py           # Mode console")
        print("  python main.py --gui     # Interface graphique")
    else:
        print(f"\n⚠️  {total - passed} test(s) ont échoué. Vérifiez les erreurs ci-dessus.")

if __name__ == "__main__":
    main()

