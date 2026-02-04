"""
Point d'entrée principal du détecteur de keyloggers
Interface moderne avec design noir et blanc épuré
"""

import sys
import argparse
import time
import signal
from datetime import datetime
from core.agent import KeyloggerDetectorAgent
from gui.main_window import KeyloggerDetectorGUI
from alerts.logger import security_logger


# ═══════════════════════════════════════════════════════════════════════════
# Configuration de l'interface
# ═══════════════════════════════════════════════════════════════════════════

BANNER = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║                    DÉTECTEUR DE KEYLOGGERS v2.0                          ║
║                    Système de Sécurité Avancé                            ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

SEPARATOR = "─" * 79
DOUBLE_SEPARATOR = "═" * 79


# ═══════════════════════════════════════════════════════════════════════════
# Fonctions utilitaires
# ═══════════════════════════════════════════════════════════════════════════

def print_header(title):
    """Affiche un en-tête élégant"""
    print(f"\n{DOUBLE_SEPARATOR}")
    print(f"  {title.upper()}")
    print(DOUBLE_SEPARATOR)


def print_section(title):
    """Affiche un titre de section"""
    print(f"\n┌─ {title}")
    print(f"│")


def print_info(label, value, indent=1):
    """Affiche une information formatée"""
    spacing = "  " * indent
    print(f"{spacing}├─ {label}: {value}")


def print_status(message, status="INFO"):
    """Affiche un message de statut"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    symbols = {
        "INFO": "●",
        "SUCCESS": "✓",
        "WARNING": "⚠",
        "ERROR": "✗",
        "RUNNING": "▶"
    }
    symbol = symbols.get(status, "○")
    print(f"[{timestamp}] {symbol} {message}")


def print_table_row(col1, col2, col3, col4):
    """Affiche une ligne de tableau"""
    print(f"│ {col1:<20} │ {col2:>8} │ {col3:>10} │ {col4:>12} │")


def print_table_header():
    """Affiche l'en-tête du tableau"""
    print("┌" + "─" * 22 + "┬" + "─" * 10 + "┬" + "─" * 12 + "┬" + "─" * 14 + "┐")
    print_table_row("Processus", "PID", "Score", "Risque")
    print("├" + "─" * 22 + "┼" + "─" * 10 + "┼" + "─" * 12 + "┼" + "─" * 14 + "┤")


def print_table_footer():
    """Affiche le pied du tableau"""
    print("└" + "─" * 22 + "┴" + "─" * 10 + "┴" + "─" * 12 + "┴" + "─" * 14 + "┘")


# ═══════════════════════════════════════════════════════════════════════════
# Gestionnaires de signaux
# ═══════════════════════════════════════════════════════════════════════════

def signal_handler(signum, frame):
    """Gestionnaire de signaux pour l'arrêt propre"""
    print("\n")
    print_status("Signal d'arrêt reçu, fermeture en cours...", "WARNING")
    if 'agent' in globals():
        agent.stop()
    print_status("Arrêt terminé avec succès", "SUCCESS")
    sys.exit(0)


# ═══════════════════════════════════════════════════════════════════════════
# Mode Console
# ═══════════════════════════════════════════════════════════════════════════

def run_console_mode():
    """Lance le mode console avec interface améliorée - UNIQUEMENT CRITICAL/HIGH"""
    print(BANNER)
    print_header("Mode Console - Surveillance en Temps Réel")
    print_status("⚠ Mode filtré: Affichage UNIQUEMENT des menaces CRITICAL et HIGH", "WARNING")
    
    # Créer l'agent
    print_status("Initialisation de l'agent de détection...", "INFO")
    agent = KeyloggerDetectorAgent()
    
    # Configurer le gestionnaire de signaux
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Démarrer l'agent
        agent.start()
        print_status("Agent démarré avec succès", "SUCCESS")
        print_status("Surveillance active - Appuyez sur Ctrl+C pour arrêter", "RUNNING")
        print(SEPARATOR)
        
        # Boucle principale
        scan_count = 0
        last_threats_displayed = set()  # Pour éviter les doublons
        
        while True:
            time.sleep(5)
            scan_count += 1
            
            # Afficher un résumé périodique (toutes les 5 itérations = 25s)
            if scan_count % 5 == 0:
                status = agent.get_status()
                if status['running']:
                    uptime = int(status['uptime'])
                    hours = uptime // 3600
                    minutes = (uptime % 3600) // 60
                    seconds = uptime % 60
                    
                    print(f"\n┌─ Rapport de Surveillance [{datetime.now().strftime('%H:%M:%S')}]")
                    print_info("Temps actif", f"{hours:02d}h {minutes:02d}m {seconds:02d}s")
                    print_info("Scans effectués", status['stats']['total_scans'])
                    
                    # Obtenir UNIQUEMENT les alertes CRITICAL et HIGH
                    from alerts.alert_manager import AlertSeverity
                    alert_manager = agent.get_alert_manager()
                    all_alerts = alert_manager.get_alerts(resolved=False)
                    critical_alerts = [a for a in all_alerts if a.severity == AlertSeverity.CRITICAL]
                    high_alerts = [a for a in all_alerts if a.severity == AlertSeverity.HIGH]
                    
                    # Obtenir UNIQUEMENT les processus CRITICAL et HIGH
                    rules_engine = agent.get_rules_engine()
                    all_suspicious = rules_engine.get_suspicious_processes()
                    critical_processes = [p for p in all_suspicious if p.risk_level == 'CRITICAL']
                    high_processes = [p for p in all_suspicious if p.risk_level == 'HIGH']
                    
                    total_threats = len(critical_alerts) + len(high_alerts) + len(critical_processes) + len(high_processes)
                    
                    print_info("🔴 Menaces CRITICAL", len(critical_alerts) + len(critical_processes))
                    print_info("⚠ Menaces HIGH", len(high_alerts) + len(high_processes))
                    
                    # Afficher les menaces si présentes
                    if total_threats > 0:
                        print_info("⚠ MENACES DÉTECTÉES", f"{total_threats} menace(s) critique(s)", 0)
                        
                        # Afficher les alertes CRITICAL
                        if critical_alerts:
                            print("\n  🔴 ALERTES CRITICAL:")
                            for alert in sorted(critical_alerts, key=lambda x: x.timestamp, reverse=True)[:5]:
                                time_str = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
                                print(f"     ✗ [{time_str}] {alert.process_name} (PID: {alert.process_pid})")
                                print(f"       → {alert.title}")
                        
                        # Afficher les processus CRITICAL
                        if critical_processes:
                            print("\n  🔴 PROCESSUS CRITICAL:")
                            for proc in sorted(critical_processes, key=lambda x: x.total_score, reverse=True)[:5]:
                                print(f"     ✗ {proc.process_name} (PID: {proc.process_pid}) - Score: {proc.total_score}")
                        
                        # Afficher les alertes HIGH
                        if high_alerts:
                            print("\n  ⚠ ALERTES HIGH:")
                            for alert in sorted(high_alerts, key=lambda x: x.timestamp, reverse=True)[:3]:
                                time_str = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
                                print(f"     ⚠ [{time_str}] {alert.process_name} (PID: {alert.process_pid})")
                        
                        # Afficher les processus HIGH
                        if high_processes:
                            print("\n  ⚠ PROCESSUS HIGH:")
                            for proc in sorted(high_processes, key=lambda x: x.total_score, reverse=True)[:3]:
                                print(f"     ⚠ {proc.process_name} (PID: {proc.process_pid}) - Score: {proc.total_score}")
                    else:
                        print_info("✓ Système sécurisé", "Aucune menace critique", 0)
                    
                    print("└" + "─" * 78)
            else:
                # Afficher un indicateur de vie
                print(".", end="", flush=True)
    
    except KeyboardInterrupt:
        print("\n")
        print_status("Arrêt demandé par l'utilisateur", "INFO")
    except Exception as e:
        print_status(f"Erreur critique: {e}", "ERROR")
        security_logger.log_system_event("ERROR", f"Erreur dans le mode console: {e}", "ERROR")
    finally:
        agent.stop()
        print_status("Agent arrêté proprement", "SUCCESS")


# ═══════════════════════════════════════════════════════════════════════════
# Mode Interface Graphique
# ═══════════════════════════════════════════════════════════════════════════

def run_gui_mode():
    """Lance le mode interface graphique"""
    print(BANNER)
    print_header("Mode Interface Graphique")
    
    print_status("Chargement de l'interface graphique...", "INFO")
    print_status("Les logs seront affichés dans la fenêtre principale", "INFO")
    print(SEPARATOR)
    
    try:
        from gui.main_window import KeyloggerDetectorGUI
        print_status("Ouverture de l'interface...", "RUNNING")
        app = KeyloggerDetectorGUI()
        app.run()
        
    except ImportError as e:
        print_status(f"Erreur d'importation: {e}", "ERROR")
        print_info("Solution", "Vérifiez que gui/main_window.py existe", 0)
        input("\nAppuyez sur Entrée pour quitter...")
    except Exception as e:
        print_status(f"Erreur critique: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        input("\nAppuyez sur Entrée pour quitter...")


# ═══════════════════════════════════════════════════════════════════════════
# Mode Test
# ═══════════════════════════════════════════════════════════════════════════

def run_test_mode():
    """Lance le mode test avec rapport détaillé - UNIQUEMENT CRITICAL/HIGH"""
    print(BANNER)
    print_header("Mode Test - Analyse de 30 Secondes")
    print_status("⚠ Mode filtré: Affichage UNIQUEMENT des menaces CRITICAL et HIGH", "WARNING")
    
    # Créer l'agent
    print_status("Initialisation de l'agent de test...", "INFO")
    agent = KeyloggerDetectorAgent()
    
    try:
        # Démarrer l'agent
        agent.start()
        print_status("Agent de test démarré", "SUCCESS")
        print_status("Analyse en cours (30 secondes)...", "RUNNING")
        
        # Barre de progression
        for i in range(30):
            progress = "█" * (i + 1) + "░" * (29 - i)
            print(f"\r  [{progress}] {i + 1}/30s", end="", flush=True)
            time.sleep(1)
        
        print("\n")
        print_status("Analyse terminée, génération du rapport...", "INFO")
        
        # Obtenir le résumé
        summary = agent.get_detection_summary()
        
        # Afficher le rapport
        print_header("Rapport d'Analyse")
        
        print_section("Statistiques Générales")
        print_info("Processus surveillés", summary['rules_summary']['total_processes'])
        print_info("Processus suspects", summary['rules_summary']['suspicious_processes'])
        print_info("Processus haut risque", summary['rules_summary']['high_risk_processes'])
        print_info("Alertes générées", summary['alerts_summary']['total_alerts'])
        print_info("Scans effectués", summary['agent_stats']['total_scans'])
        
        # FILTRER: Obtenir UNIQUEMENT les processus CRITICAL et HIGH
        from alerts.alert_manager import AlertSeverity
        alert_manager = agent.get_alert_manager()
        all_alerts = alert_manager.get_alerts(resolved=False)
        critical_alerts = [a for a in all_alerts if a.severity == AlertSeverity.CRITICAL]
        high_alerts = [a for a in all_alerts if a.severity == AlertSeverity.HIGH]
        
        rules_engine = agent.get_rules_engine()
        all_suspicious = rules_engine.get_suspicious_processes()
        critical_processes = [p for p in all_suspicious if p.risk_level == 'CRITICAL']
        high_processes = [p for p in all_suspicious if p.risk_level == 'HIGH']
        
        # TRIER par score décroissant
        critical_processes_sorted = sorted(critical_processes, key=lambda x: x.total_score, reverse=True)
        high_processes_sorted = sorted(high_processes, key=lambda x: x.total_score, reverse=True)
        
        # Afficher UNIQUEMENT les processus CRITICAL et HIGH
        if critical_processes_sorted or high_processes_sorted:
            print_section("🔴 MENACES CRITIQUES ET PROBABLES (CRITICAL/HIGH uniquement)")
            print_table_header()
            
            # Afficher d'abord les CRITICAL
            for proc in critical_processes_sorted[:10]:
                name = proc.process_name[:20]
                pid = str(proc.process_pid)
                score = str(proc.total_score)
                risk = 'CRITICAL'
                print_table_row(name, pid, score, risk)
            
            # Puis les HIGH
            for proc in high_processes_sorted[:10]:
                name = proc.process_name[:20]
                pid = str(proc.process_pid)
                score = str(proc.total_score)
                risk = 'HIGH'
                print_table_row(name, pid, score, risk)
            
            print_table_footer()
            
            total_displayed = len(critical_processes_sorted[:10]) + len(high_processes_sorted[:10])
            total_filtered = len(critical_processes_sorted) + len(high_processes_sorted)
            if total_filtered > total_displayed:
                print(f"\n  ... et {total_filtered - total_displayed} autre(s) menace(s) critique(s)")
        else:
            print_status("✓ Aucune menace critique détectée", "SUCCESS")
        
        # Afficher UNIQUEMENT les alertes CRITICAL et HIGH
        if critical_alerts or high_alerts:
            print_section("🔴 ALERTES CRITIQUES ET PROBABLES")
            
            # Afficher d'abord les CRITICAL (triées par timestamp décroissant)
            for i, alert in enumerate(sorted(critical_alerts, key=lambda x: x.timestamp, reverse=True)[:5], 1):
                time_str = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
                print(f"  {i}. [CRITICAL] ✗ [{time_str}] {alert.process_name} (PID: {alert.process_pid})")
                print(f"     → {alert.title}")
            
            # Puis les HIGH
            for i, alert in enumerate(sorted(high_alerts, key=lambda x: x.timestamp, reverse=True)[:3], len(critical_alerts[:5]) + 1):
                time_str = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
                print(f"  {i}. [HIGH] ⚠ [{time_str}] {alert.process_name} (PID: {alert.process_pid})")
                print(f"     → {alert.title}")
            
            total_alerts = len(critical_alerts) + len(high_alerts)
            displayed = min(5, len(critical_alerts)) + min(3, len(high_alerts))
            if total_alerts > displayed:
                print(f"\n  ... et {total_alerts - displayed} autre(s) alerte(s) critique(s)")
        else:
            print_status("✓ Aucune alerte critique", "SUCCESS")
        
        print("\n" + DOUBLE_SEPARATOR)
        print_status("Test terminé avec succès", "SUCCESS")
    
    except Exception as e:
        print_status(f"Erreur pendant le test: {e}", "ERROR")
        security_logger.log_system_event("ERROR", f"Erreur dans le mode test: {e}", "ERROR")
    finally:
        agent.stop()


# ═══════════════════════════════════════════════════════════════════════════
# Point d'entrée principal
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Fonction principale avec interface améliorée"""
    parser = argparse.ArgumentParser(
        description="Détecteur de Keyloggers - Système de Sécurité Avancé",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔═══════════════════════════════════════════════════════════════════════════╗
║ EXEMPLES D'UTILISATION                                                    ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  python main.py                    Mode console (par défaut)              ║
║  python main.py --gui              Mode interface graphique               ║
║  python main.py --test             Mode test (30 secondes)                ║
║  python main.py --console          Mode console (explicite)               ║
╚═══════════════════════════════════════════════════════════════════════════╝
        """
    )
    
    parser.add_argument('--gui', action='store_true', 
                       help='Lance l\'interface graphique moderne')
    parser.add_argument('--console', action='store_true', 
                       help='Lance le mode console avec surveillance en temps réel')
    parser.add_argument('--test', action='store_true', 
                       help='Lance un test de 30 secondes avec rapport détaillé')
    
    args = parser.parse_args()
    
    # Déterminer le mode d'exécution
    try:
        if args.gui:
            run_gui_mode()
        elif args.test:
            run_test_mode()
        else:
            # Mode console par défaut
            run_console_mode()
    except Exception as e:
        print_status(f"Erreur fatale: {e}", "ERROR")
        sys.exit(1)


if __name__ == "__main__":
    main()