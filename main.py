"""
Point d'entrée principal du détecteur de keyloggers
"""

import sys
import argparse
import time
import signal
from core.agent import KeyloggerDetectorAgent
from gui.main_window import KeyloggerDetectorGUI
from alerts.logger import security_logger
from core.agent import KeyloggerDetectorAgent


def signal_handler(signum, frame):
    """Gestionnaire de signaux pour l'arrêt propre"""
    print("\n[Main] Signal reçu, arrêt en cours...")
    if 'agent' in globals():
        agent.stop()
    sys.exit(0)


def run_console_mode():
    """Lance le mode console"""
    print("Détecteur de Keyloggers - Mode Console")
    print("=" * 50)
    
    # Créer l'agent
    agent = KeyloggerDetectorAgent()
    
    # Configurer le gestionnaire de signaux
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Démarrer l'agent
        agent.start()
        print("[Main] Agent démarré. Appuyez sur Ctrl+C pour arrêter.")
        
        # Boucle principale
        while True:
            time.sleep(5)
            
            # Afficher un résumé périodique
            status = agent.get_status()
            if status['running']:
                uptime = int(status['uptime'])
                print(f"[Main] Surveillance active - Uptime: {uptime}s, "
                      f"Scans: {status['stats']['total_scans']}, "
                      f"Alertes: {status['stats']['alerts_generated']}")
    
    except KeyboardInterrupt:
        print("\n[Main] Arrêt demandé par l'utilisateur")
    except Exception as e:
        print(f"[Main] Erreur: {e}")
        security_logger.log_system_event("ERROR", f"Erreur dans le mode console: {e}", "ERROR")
    finally:
        agent.stop()
        print("[Main] Agent arrêté")


def run_gui_mode():
    """Lance le mode interface graphique"""
    print("Détecteur de Keyloggers - Mode Interface Graphique")
    print("L'interface graphique va s'ouvrir...")
    print("Les logs s'afficheront dans l'interface, pas dans cette console.")
    
    try:
        # Créer et lancer l'interface graphique
        from gui.main_window import KeyloggerDetectorGUI
        app = KeyloggerDetectorGUI()
        app.run()
        
    except ImportError as e:
        print(f"Erreur import GUI: {e}")
        print("Vérifiez que gui/main_window.py existe et a les bonnes dépendances")
        input("Appuyez sur Entrée pour quitter...")
    except Exception as e:
        print(f"Erreur dans le mode GUI: {e}")
        import traceback
        traceback.print_exc()
        input("Appuyez sur Entrée pour quitter...")


def run_test_mode():
    """Lance le mode test"""
    print("Détecteur de Keyloggers - Mode Test")
    print("=" * 50)
    
    # Créer l'agent
    agent = KeyloggerDetectorAgent()
    
    try:
        # Démarrer l'agent
        agent.start()
        print("[Test] Agent démarré pour 30 secondes...")
        
        # Attendre 30 secondes
        time.sleep(30)
        
        # Obtenir un résumé
        summary = agent.get_detection_summary()
        
        print("\n[Test] Résumé des détections:")
        print(f"  - Processus surveillés: {summary['rules_summary']['total_processes']}")
        print(f"  - Processus suspects: {summary['rules_summary']['suspicious_processes']}")
        print(f"  - Processus haut risque: {summary['rules_summary']['high_risk_processes']}")
        print(f"  - Alertes générées: {summary['alerts_summary']['total_alerts']}")
        print(f"  - Scans effectués: {summary['agent_stats']['total_scans']}")
        
        # Afficher les processus suspects
        if summary['suspicious_processes']:
            print("\n[Test] Processus suspects détectés:")
            for process in summary['suspicious_processes']:
                print(f"  - {process['process_name']} (PID: {process['process_pid']}) "
                      f"- Score: {process['total_score']} - Risque: {process['risk_level']}")
        
        # Afficher les alertes
        if summary['alerts_summary']['total_alerts'] > 0:
            print("\n[Test] Alertes générées:")
            for alert in summary['alerts_summary']['recent_alerts']:
                print(f"  - [{alert['severity']}] {alert['title']}")
    
    except Exception as e:
        print(f"[Test] Erreur: {e}")
        security_logger.log_system_event("ERROR", f"Erreur dans le mode test: {e}", "ERROR")
    finally:
        agent.stop()
        print("[Test] Test terminé")


def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description="Détecteur de Keyloggers - Système de Sécurité",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python main.py                    # Mode console
  python main.py --gui              # Mode interface graphique
  python main.py --test             # Mode test (30 secondes)
  python main.py --console          # Mode console explicite
        """
    )
    
    parser.add_argument('--gui', action='store_true', 
                       help='Lance l\'interface graphique')
    parser.add_argument('--console', action='store_true', 
                       help='Lance le mode console')
    parser.add_argument('--test', action='store_true', 
                       help='Lance le mode test (30 secondes)')
    
    args = parser.parse_args()
    
    # Déterminer le mode d'exécution
    if args.gui:
        run_gui_mode()
    elif args.test:
        run_test_mode()
    else:
        # Mode console par défaut
        run_console_mode()


if __name__ == "__main__":
    main()
