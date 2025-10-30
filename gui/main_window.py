"""
Interface graphique principale pour le détecteur de keyloggers
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import sys
import os

# Ajouter le chemin pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class KeyloggerDetectorGUI:
    """Interface graphique principale connectée à l'agent"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Détecteur de Keyloggers - Système de Sécurité")
        self.root.geometry("1200x800")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Agent principal (au lieu des composants séparés)
        self.agent = None
        self.monitoring = False
        
        # Configuration de l'interface
        self._setup_ui()
        
        # Démarrer la mise à jour périodique
        self._start_update_loop()
        
        # Statut
        self.status_bar.config(text="Prêt - Cliquez sur 'Démarrer la Surveillance'")
    
    def _setup_agent_callbacks(self):
        """Configure les callbacks avec l'agent"""
        if self.agent:
            self.agent.add_gui_callback(self._on_agent_update)

    def _on_agent_update(self, event_type, data):
        """Reçoit les mises à jour de l'agent"""
        # Cette méthode est appelée dans le thread de l'agent
        # On doit utiliser after() pour mettre à jour l'interface graphique
        self.root.after(0, self._process_agent_update, event_type, data)

    def _process_agent_update(self, event_type, data):
        """Traite les mises à jour de l'agent dans le thread GUI"""
        try:
            if event_type == "AGENT_STARTED":
                self._handle_agent_started(data)
            elif event_type == "AGENT_STOPPED":
                self._handle_agent_stopped(data)
            elif event_type == "SCAN_COMPLETE":
                self._handle_scan_complete(data)
            elif event_type == "API_SCAN_COMPLETE":
                self._handle_api_scan_complete(data)
            elif event_type == "PERSISTENCE_SCAN_COMPLETE":
                self._handle_persistence_scan_complete(data)
            elif event_type == "DATA_UPDATE":
                self._handle_data_update(data)
            elif event_type == "NEW_PROCESS":
                self._handle_new_process(data)
            elif event_type == "TERMINATED_PROCESS":
                self._handle_terminated_process(data)
            elif event_type == "FILE_ACTIVITY":
                self._handle_file_activity(data)
            elif event_type == "NETWORK_ACTIVITY":
                self._handle_network_activity(data)
            elif event_type == "NEW_ALERT":
                self._handle_new_alert(data)
            elif event_type == "SUMMARY_UPDATE":
                self._handle_summary_update(data)
            elif event_type == "ERROR":
                self._handle_error(data)
            elif event_type == "FORCED_SCAN":
                self._handle_forced_scan(data)
                
        except Exception as e:
            print(f"Erreur traitement update: {e}")

    def _handle_agent_started(self, data):
        """Traite le démarrage de l'agent"""
        self.log_activity("AGENT", "Agent démarré avec succès")
        self.status_bar.config(text="Surveillance active - Agent en cours d'exécution")

    def _handle_agent_stopped(self, data):
        """Traite l'arrêt de l'agent"""
        self.log_activity("AGENT", "Agent arrêté")
        self.status_bar.config(text="Surveillance arrêtée")

    def _handle_scan_complete(self, data):
        """Traite la complétion d'un scan"""
        scan_id = data.get("scan_id", 0)
        self.log_activity("SCAN", f"Scan #{scan_id} terminé")
        
        # Mettre à jour les indicateurs
        if self.agent:
            status = self.agent.get_status()
            if status:
                self.stats_labels['total_scans'].config(text=str(status.get('stats', {}).get('total_scans', 0)))
                self.stats_labels['last_scan'].config(text=f"Scan #{scan_id}")

    def _handle_api_scan_complete(self, data):
        """Traite la complétion d'un scan API"""
        processes_scanned = data.get("processes_scanned", 0)
        suspicious_found = data.get("suspicious_found", 0)
        
        if suspicious_found > 0:
            self.log_activity("API_SCAN", f"Scan API: {processes_scanned} processus, {suspicious_found} suspects")
        else:
            self.log_activity("API_SCAN", f"Scan API: {processes_scanned} processus analysés")

    def _handle_persistence_scan_complete(self, data):
        """Traite la complétion d'un scan de persistance"""
        methods_found = data.get("methods_found", 0)
        suspicious_methods = data.get("suspicious_methods", 0)
        
        if suspicious_methods > 0:
            self.log_activity("PERSISTENCE", f"Scan persistance: {methods_found} méthodes, {suspicious_methods} suspects")
        else:
            self.log_activity("PERSISTENCE", f"Scan persistance: {methods_found} méthodes analysées")

    def _handle_data_update(self, data):
        """Traite la mise à jour des données"""
        # Mettre à jour les indicateurs en temps réel
        total_processes = data.get("total_processes", 0)
        suspicious_processes = data.get("suspicious_processes", 0)
        active_alerts = data.get("active_alerts", 0)
        
        self.indicators['active_processes'].config(text=str(total_processes))
        self.indicators['monitored_processes'].config(text=str(total_processes))
        self.indicators['active_alerts'].config(text=str(active_alerts))
        self.indicators['scan_status'].config(text="Actif")
        
        # Mettre à jour les statistiques
        stats = data.get("agent_stats", {})
        self.stats_labels['total_scans'].config(text=str(stats.get('total_scans', 0)))
        self.stats_labels['alerts_generated'].config(text=str(stats.get('alerts_generated', 0)))
        self.stats_labels['processes_analyzed'].config(text=str(stats.get('processes_scanned', 0)))

    def _handle_new_process(self, data):
        """Traite un nouveau processus"""
        pid = data.get("pid", "N/A")
        name = data.get("name", "Inconnu")
        
        self.log_activity("PROCESS", f"Nouveau processus: {name} (PID: {pid})")
        self._add_detailed_log(f"Processus créé: {name} (PID: {pid})")

    def _handle_terminated_process(self, data):
        """Traite un processus terminé"""
        pid = data.get("pid", "N/A")
        name = data.get("name", "Inconnu")
        
        self.log_activity("PROCESS", f"Processus terminé: {name} (PID: {pid})")
        self._add_detailed_log(f"Processus terminé: {name} (PID: {pid})")

    def _handle_file_activity(self, data):
        """Traite une activité de fichier"""
        file_path = data.get("file_path", "N/A")
        activity_type = data.get("activity_type", "N/A")
        process_name = data.get("process_name", "Inconnu")
        
        self.log_activity("FILE", f"Activité fichier: {process_name} - {activity_type} - {file_path}")
        self._add_detailed_log(f"Activité fichier: {process_name} - {activity_type} - {file_path}")

    def _handle_network_activity(self, data):
        """Traite une activité réseau"""
        remote_address = data.get("remote_address", "N/A")
        process_name = data.get("process_name", "Inconnu")
        
        self.log_activity("NETWORK", f"Connexion réseau: {process_name} -> {remote_address}")
        self._add_detailed_log(f"Connexion réseau: {process_name} -> {remote_address}")

    def _handle_new_alert(self, data):
        """Traite une nouvelle alerte"""
        alert_type = data.get("alert_type", "N/A")
        severity = data.get("severity", "N/A")
        process_name = data.get("process_name", "Inconnu")
        title = data.get("title", "Sans titre")
        
        self.log_activity("ALERTE", f"NOUVELLE ALERTE [{severity}]: {title} - {process_name}")
        self._add_detailed_log(f"🚨 ALERTE {severity}: {title} - Processus: {process_name}")
        
        # Mettre à jour le compteur d'alertes
        if self.agent:
            status = self.agent.get_status()
            if status:
                self.stats_labels['alerts_generated'].config(text=str(status.get('stats', {}).get('alerts_generated', 0)))

    def _handle_summary_update(self, data):
        """Traite une mise à jour du résumé"""
        uptime = data.get("uptime", "0h 0m")
        total_processes = data.get("total_processes", 0)
        suspicious_processes = data.get("suspicious_processes", 0)
        total_alerts = data.get("total_alerts", 0)
        
        self.log_activity("SUMMARY", f"Résumé: {uptime} - {total_processes} processus - {suspicious_processes} suspects - {total_alerts} alertes")
        
        # Mettre à jour les statistiques
        self.stats_labels['uptime'].config(text=uptime)
        self.stats_labels['agent_status'].config(text="Actif")

    def _handle_error(self, data):
        """Traite une erreur"""
        error_message = data.get("message", "Erreur inconnue")
        self.log_activity("ERREUR", error_message)
        self._add_detailed_log(f"❌ ERREUR: {error_message}")

    def _handle_forced_scan(self, data):
        """Traite un scan forcé"""
        self.log_activity("SCAN", "Scan forcé effectué")
        self.status_bar.config(text="Scan forcé terminé")

    def _add_detailed_log(self, message):
        """Ajoute un message aux logs détaillés"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.detailed_logs.insert(tk.END, log_entry)
        self.detailed_logs.see(tk.END)

    def _setup_ui(self):
        """Configure l'interface utilisateur"""
        # Style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configuration de la grille
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Titre
        title_label = ttk.Label(main_frame, text="🔒 Détecteur de Keyloggers", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Contrôles
        self._create_control_panel(main_frame)
        
        # Onglets
        self._create_tabs(main_frame)
        
        # Barre de statut
        self.status_bar = ttk.Label(main_frame, text="Prêt", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
    
    def _create_control_panel(self, parent):
        """Crée le panneau de contrôle"""
        control_frame = ttk.LabelFrame(parent, text="Contrôles", padding="10")
        control_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Bouton de démarrage/arrêt
        self.start_button = ttk.Button(control_frame, text="Démarrer la Surveillance", 
                                      command=self.toggle_monitoring)
        self.start_button.grid(row=0, column=0, padx=(0, 10))
        
        # Bouton de scan rapide
        self.quick_scan_button = ttk.Button(control_frame, text="Scan Rapide", 
                                           command=self.quick_scan)
        self.quick_scan_button.grid(row=0, column=1, padx=(0, 10))
        
        # Bouton d'export des logs
        self.export_button = ttk.Button(control_frame, text="Exporter Logs", 
                                       command=self.export_logs)
        self.export_button.grid(row=0, column=2, padx=(0, 10))
        
        # Indicateur de statut
        self.status_indicator = ttk.Label(control_frame, text="● Arrêté", 
                                         foreground="red", font=('Arial', 10, 'bold'))
        self.status_indicator.grid(row=0, column=3, padx=(20, 0))
    
    def _create_tabs(self, parent):
        """Crée les onglets"""
        notebook = ttk.Notebook(parent)
        notebook.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Onglet Surveillance
        self._create_monitoring_tab(notebook)
        
        # Onglet Statistiques
        self._create_stats_tab(notebook)
        
        # Onglet Logs
        self._create_logs_tab(notebook)
    
    def _create_monitoring_tab(self, notebook):
        """Crée l'onglet de surveillance"""
        monitor_frame = ttk.Frame(notebook)
        notebook.add(monitor_frame, text="🔍 Surveillance")
        
        # Frame pour les indicateurs
        indicators_frame = ttk.LabelFrame(monitor_frame, text="Indicateurs en Temps Réel", padding="10")
        indicators_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Indicateurs
        self.indicators = {}
        indicator_config = [
            ("Processus Actifs", "active_processes", "0"),
            ("Processus Surveillés", "monitored_processes", "0"),
            ("Alertes Actives", "active_alerts", "0"),
            ("Scan en Cours", "scan_status", "Non")
        ]
        
        for i, (label, key, default) in enumerate(indicator_config):
            ttk.Label(indicators_frame, text=f"{label}:").grid(row=i, column=0, sticky=tk.W, padx=(0, 10))
            self.indicators[key] = ttk.Label(indicators_frame, text=default, font=('Arial', 10, 'bold'))
            self.indicators[key].grid(row=i, column=1, sticky=tk.W)
        
        # Zone de log en temps réel
        log_frame = ttk.LabelFrame(monitor_frame, text="Activité en Temps Réel", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.activity_log = scrolledtext.ScrolledText(log_frame, height=15, width=80)
        self.activity_log.pack(fill=tk.BOTH, expand=True)
        
        # Boutons pour les logs
        log_buttons_frame = ttk.Frame(log_frame)
        log_buttons_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(log_buttons_frame, text="Effacer", 
                command=self.clear_activity_log).pack(side=tk.LEFT, padx=(0, 10))
    
    def _create_stats_tab(self, notebook):
        """Crée l'onglet des statistiques"""
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="📊 Statistiques")
        
        # Frame pour les statistiques détaillées
        stats_info_frame = ttk.LabelFrame(stats_frame, text="Statistiques du Système", padding="10")
        stats_info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Labels pour les statistiques
        self.stats_labels = {}
        stats_items = [
            ("Temps de Surveillance", "uptime"),
            ("Total des Scans", "total_scans"),
            ("Processus Analysés", "processes_analyzed"),
            ("Alertes Générées", "alerts_generated"),
            ("Dernier Scan", "last_scan"),
            ("Statut Agent", "agent_status")
        ]
        
        for i, (label_text, key) in enumerate(stats_items):
            ttk.Label(stats_info_frame, text=f"{label_text}:").grid(row=i, column=0, sticky=tk.W, padx=(0, 10), pady=2)
            self.stats_labels[key] = ttk.Label(stats_info_frame, text="N/A", font=('Arial', 10))
            self.stats_labels[key].grid(row=i, column=1, sticky=tk.W, pady=2)
    
    def _create_logs_tab(self, notebook):
        """Crée l'onglet des logs"""
        logs_frame = ttk.Frame(notebook)
        notebook.add(logs_frame, text="📋 Logs Détaillés")
        
        # Zone de texte pour les logs
        self.detailed_logs = scrolledtext.ScrolledText(logs_frame, height=20, width=80)
        self.detailed_logs.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Boutons pour les logs
        logs_buttons_frame = ttk.Frame(logs_frame)
        logs_buttons_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        
        ttk.Button(logs_buttons_frame, text="Actualiser", 
                  command=self.refresh_detailed_logs).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(logs_buttons_frame, text="Effacer", 
                  command=self.clear_detailed_logs).pack(side=tk.LEFT, padx=(0, 10))
    
    def _start_update_loop(self):
        """Démarre la boucle de mise à jour de l'interface"""
        def update_loop():
            while True:
                try:
                    self.update_interface()
                    time.sleep(2)  # Mise à jour toutes les 2 secondes
                except Exception as e:
                    print(f"Erreur dans la boucle de mise à jour: {e}")
                    time.sleep(5)
        
        self.update_thread = threading.Thread(target=update_loop, daemon=True)
        self.update_thread.start()
    
    def toggle_monitoring(self):
        """Démarre ou arrête la surveillance"""
        if not self.monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Démarre la surveillance via l'agent"""
        try:
            from core.agent import KeyloggerDetectorAgent
            self.agent = KeyloggerDetectorAgent()
            
            # Configurer les callbacks AVANT de démarrer
            self._setup_agent_callbacks()
            
            # Démarrer l'agent
            self.agent.start()
            
            self.monitoring = True
            self.start_button.config(text="Arrêter la Surveillance")
            self.status_indicator.config(text="● En cours", foreground="green")
            self.status_bar.config(text="Surveillance démarrée - Agent actif")
            
            self.log_activity("SYSTEM", "Interface connectée à l'agent de surveillance")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de démarrer la surveillance: {e}")
            self.log_activity("ERREUR", f"Échec démarrage: {e}")
    
    def stop_monitoring(self):
        """Arrête la surveillance"""
        try:
            if self.agent:
                self.agent.stop()
                self.agent = None
            
            self.monitoring = False
            self.start_button.config(text="Démarrer la Surveillance")
            self.status_indicator.config(text="● Arrêté", foreground="red")
            self.status_bar.config(text="Surveillance arrêtée")
            
            self.log_activity("SURVEILLANCE", "Agent de surveillance arrêté")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'arrêt: {e}")
    
    def quick_scan(self):
        """Lance un scan rapide"""
        def scan_thread():
            try:
                self.status_bar.config(text="Scan rapide en cours...")
                self.log_activity("SCAN", "Démarrage du scan rapide")
                
                # Simuler un scan (à adapter avec votre logique)
                time.sleep(2)
                
                self.status_bar.config(text="Scan rapide terminé")
                self.log_activity("SCAN", "Scan rapide terminé")
                
            except Exception as e:
                self.status_bar.config(text="Erreur lors du scan")
                self.log_activity("ERREUR", f"Échec scan: {e}")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def export_logs(self):
        """Exporte les logs vers un fichier"""
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.detailed_logs.get(1.0, tk.END))
                
                messagebox.showinfo("Succès", f"Logs exportés vers {filename}")
                self.log_activity("EXPORT", f"Logs exportés: {filename}")
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'export: {e}")
    
    def update_interface(self):
        """Met à jour l'interface utilisateur"""
        try:
            if self.monitoring and self.agent:
                # Mettre à jour les indicateurs
                status = self.agent.get_status()
                if status:
                    self.indicators['active_processes'].config(text="N/A")  # À adapter
                    self.indicators['monitored_processes'].config(text="N/A")  # À adapter
                    self.indicators['active_alerts'].config(text="N/A")  # À adapter
                    self.indicators['scan_status'].config(text="Oui" if status.get('running', False) else "Non")
                    
                    # Mettre à jour les statistiques
                    self.stats_labels['uptime'].config(text=f"{int(status.get('uptime', 0))}s")
                    self.stats_labels['total_scans'].config(text=str(status.get('stats', {}).get('total_scans', 0)))
                    self.stats_labels['alerts_generated'].config(text=str(status.get('stats', {}).get('alerts_generated', 0)))
                    self.stats_labels['agent_status'].config(text="Actif" if status.get('running', False) else "Inactif")
                    
            # Actualiser les logs détaillés périodiquement
            if self.monitoring:
                self.refresh_detailed_logs()
                
        except Exception as e:
            print(f"Erreur mise à jour interface: {e}")
    
    def log_activity(self, category, message):
        """Ajoute un message au log d'activité en temps réel"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{category}] {message}\n"
        
        self.activity_log.insert(tk.END, log_entry)
        self.activity_log.see(tk.END)
    
    def refresh_detailed_logs(self):
        """Actualise les logs détaillés"""
        try:
            # Simuler des logs (à remplacer par vos vraies logs)
            if self.monitoring:
                current_content = self.detailed_logs.get(1.0, tk.END).strip()
                if not current_content or "Démarrage" in current_content:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    log_content = f"""=== LOGS DE SURVEILLANCE ===
Démarré le: {timestamp}
Agent: {'Actif' if self.agent else 'Inactif'}
Statut: {'En surveillance' if self.monitoring else 'Arrêté'}

[Logs système en temps réel...]
"""
                    self.detailed_logs.delete(1.0, tk.END)
                    self.detailed_logs.insert(1.0, log_content)
                    
        except Exception as e:
            print(f"Erreur actualisation logs: {e}")
    
    def clear_activity_log(self):
        """Efface le log d'activité"""
        self.activity_log.delete(1.0, tk.END)
    
    def clear_detailed_logs(self):
        """Efface les logs détaillés"""
        self.detailed_logs.delete(1.0, tk.END)
    
    def on_closing(self):
        """Gestionnaire de fermeture de l'application"""
        if self.monitoring:
            self.stop_monitoring()
        self.root.destroy()
    
    def run(self):
        """Lance l'interface graphique"""
        self.root.mainloop()


if __name__ == "__main__":
    app = KeyloggerDetectorGUI()
    app.run()