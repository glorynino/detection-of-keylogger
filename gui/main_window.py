"""
Interface graphique principale pour le détecteur de keyloggers
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from typing import Dict, List, Any
from alerts.alert_manager import AlertManager, AlertSeverity
from core.rules_engine import RulesEngine
from core.process_monitor import ProcessMonitor
from core.file_monitor import FileMonitor
from core.persistence_check import PersistenceChecker
from alerts.logger import security_logger


class KeyloggerDetectorGUI:
    """Interface graphique principale"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Détecteur de Keyloggers - Système de Sécurité")
        self.root.geometry("1200x800")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Composants du système
        self.alert_manager = AlertManager()
        self.rules_engine = RulesEngine()
        self.process_monitor = ProcessMonitor()
        self.file_monitor = FileMonitor()
        self.persistence_checker = PersistenceChecker()
        
        # État de l'application
        self.monitoring = False
        self.update_thread = None
        
        # Configuration de l'interface
        self._setup_ui()
        self._setup_callbacks()
        
        # Démarrer la mise à jour périodique
        self._start_update_loop()
    
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
        self._create_status_bar(main_frame)
    
    def _create_control_panel(self, parent):
        """Crée le panneau de contrôle"""
        control_frame = ttk.LabelFrame(parent, text="Contrôles", padding="10")
        control_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Bouton de démarrage/arrêt
        self.start_button = ttk.Button(control_frame, text="Démarrer la Surveillance", 
                                      command=self.toggle_monitoring)
        self.start_button.grid(row=0, column=0, padx=(0, 10))
        
        # Bouton de scan de persistance
        self.scan_button = ttk.Button(control_frame, text="Scanner la Persistance", 
                                     command=self.scan_persistence)
        self.scan_button.grid(row=0, column=1, padx=(0, 10))
        
        # Bouton d'export des alertes
        self.export_button = ttk.Button(control_frame, text="Exporter les Alertes", 
                                       command=self.export_alerts)
        self.export_button.grid(row=0, column=2, padx=(0, 10))
        
        # Indicateur de statut
        self.status_indicator = ttk.Label(control_frame, text="● Arrêté", 
                                         foreground="red", font=('Arial', 10, 'bold'))
        self.status_indicator.grid(row=0, column=3, padx=(20, 0))
    
    def _create_tabs(self, parent):
        """Crée les onglets"""
        notebook = ttk.Notebook(parent)
        notebook.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Onglet Alertes
        self._create_alerts_tab(notebook)
        
        # Onglet Processus
        self._create_processes_tab(notebook)
        
        # Onglet Logs
        self._create_logs_tab(notebook)
        
        # Onglet Statistiques
        self._create_stats_tab(notebook)
    
    def _create_alerts_tab(self, notebook):
        """Crée l'onglet des alertes"""
        alerts_frame = ttk.Frame(notebook)
        notebook.add(alerts_frame, text="🚨 Alertes")
        
        # Frame pour les contrôles d'alertes
        alerts_control_frame = ttk.Frame(alerts_frame)
        alerts_control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Filtres
        ttk.Label(alerts_control_frame, text="Filtrer par sévérité:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.severity_filter = ttk.Combobox(alerts_control_frame, values=["Tous", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.severity_filter.set("Tous")
        self.severity_filter.pack(side=tk.LEFT, padx=(0, 10))
        self.severity_filter.bind('<<ComboboxSelected>>', self.filter_alerts)
        
        # Bouton de rafraîchissement
        ttk.Button(alerts_control_frame, text="Rafraîchir", 
                  command=self.refresh_alerts).pack(side=tk.LEFT, padx=(0, 10))
        
        # Bouton d'acquittement
        ttk.Button(alerts_control_frame, text="Acquitter Sélectionné", 
                  command=self.acknowledge_selected).pack(side=tk.LEFT)
        
        # Treeview pour les alertes
        columns = ('ID', 'Type', 'Sévérité', 'Processus', 'PID', 'Timestamp', 'Description')
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=columns, show='headings', height=15)
        
        # Configuration des colonnes
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=100)
        
        # Scrollbar pour les alertes
        alerts_scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=alerts_scrollbar.set)
        
        # Pack des widgets
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
        alerts_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=5)
    
    def _create_processes_tab(self, notebook):
        """Crée l'onglet des processus"""
        processes_frame = ttk.Frame(notebook)
        notebook.add(processes_frame, text="🖥️ Processus")
        
        # Treeview pour les processus
        columns = ('PID', 'Nom', 'Score', 'Risque', 'Dernière MAJ', 'Règles')
        self.processes_tree = ttk.Treeview(processes_frame, columns=columns, show='headings', height=15)
        
        # Configuration des colonnes
        for col in columns:
            self.processes_tree.heading(col, text=col)
            self.processes_tree.column(col, width=120)
        
        # Scrollbar pour les processus
        processes_scrollbar = ttk.Scrollbar(processes_frame, orient=tk.VERTICAL, command=self.processes_tree.yview)
        self.processes_tree.configure(yscrollcommand=processes_scrollbar.set)
        
        # Pack des widgets
        self.processes_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
        processes_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=5)
    
    def _create_logs_tab(self, notebook):
        """Crée l'onglet des logs"""
        logs_frame = ttk.Frame(notebook)
        notebook.add(logs_frame, text="📋 Logs")
        
        # Zone de texte pour les logs
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=20, width=80)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Boutons pour les logs
        logs_buttons_frame = ttk.Frame(logs_frame)
        logs_buttons_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        
        ttk.Button(logs_buttons_frame, text="Effacer les Logs", 
                  command=self.clear_logs).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(logs_buttons_frame, text="Ouvrir Fichier de Log", 
                  command=self.open_log_file).pack(side=tk.LEFT)
    
    def _create_stats_tab(self, notebook):
        """Crée l'onglet des statistiques"""
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="📊 Statistiques")
        
        # Frame pour les statistiques
        stats_info_frame = ttk.LabelFrame(stats_frame, text="Résumé du Système", padding="10")
        stats_info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Labels pour les statistiques
        self.stats_labels = {}
        stats_items = [
            ("Total Processus", "total_processes"),
            ("Processus Suspects", "suspicious_processes"),
            ("Processus Haut Risque", "high_risk_processes"),
            ("Total Alertes", "total_alerts"),
            ("Alertes Non Acquittées", "unacknowledged_alerts"),
            ("Alertes Critiques", "critical_alerts")
        ]
        
        for i, (label_text, key) in enumerate(stats_items):
            row = i // 2
            col = (i % 2) * 2
            
            ttk.Label(stats_info_frame, text=f"{label_text}:").grid(row=row, column=col, sticky=tk.W, padx=(0, 5))
            self.stats_labels[key] = ttk.Label(stats_info_frame, text="0", font=('Arial', 10, 'bold'))
            self.stats_labels[key].grid(row=row, column=col+1, sticky=tk.W, padx=(0, 20))
    
    def _create_status_bar(self, parent):
        """Crée la barre de statut"""
        self.status_bar = ttk.Label(parent, text="Prêt", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
    
    def _setup_callbacks(self):
        """Configure les callbacks du système"""
        # Callback pour les alertes
        self.alert_manager.add_callback(self.on_new_alert)
        
        # Callback pour les nouveaux processus
        self.process_monitor.add_callback(self.on_process_change)
        
        # Callback pour les activités de fichiers
        self.file_monitor.add_callback(self.on_file_activity)
        
        # Callback pour le moteur de règles
        self.rules_engine.add_callback(self.on_rules_alert)
    
    def _start_update_loop(self):
        """Démarre la boucle de mise à jour de l'interface"""
        def update_loop():
            while True:
                try:
                    if self.monitoring:
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
        """Démarre la surveillance"""
        try:
            # Démarrer les composants
            self.process_monitor.start()
            self.file_monitor.start()
            
            self.monitoring = True
            self.start_button.config(text="Arrêter la Surveillance")
            self.status_indicator.config(text="● En cours", foreground="green")
            self.status_bar.config(text="Surveillance démarrée")
            
            security_logger.log_system_event("MONITORING", "Surveillance démarrée", "INFO")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de démarrer la surveillance: {e}")
            security_logger.log_system_event("ERROR", f"Erreur démarrage surveillance: {e}", "ERROR")
    
    def stop_monitoring(self):
        """Arrête la surveillance"""
        try:
            # Arrêter les composants
            self.process_monitor.stop()
            self.file_monitor.stop()
            
            self.monitoring = False
            self.start_button.config(text="Démarrer la Surveillance")
            self.status_indicator.config(text="● Arrêté", foreground="red")
            self.status_bar.config(text="Surveillance arrêtée")
            
            security_logger.log_system_event("MONITORING", "Surveillance arrêtée", "INFO")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'arrêt: {e}")
    
    def scan_persistence(self):
        """Lance un scan de persistance"""
        def scan_thread():
            try:
                self.status_bar.config(text="Scan de persistance en cours...")
                methods = self.persistence_checker.check_all_persistence_methods()
                
                # Traiter les méthodes de persistance
                for method in methods:
                    if method.is_suspicious():
                        self.alert_manager.create_persistence_alert(
                            method.method_type, method.location, method.value
                        )
                
                self.status_bar.config(text=f"Scan terminé: {len(methods)} méthodes trouvées")
                security_logger.log_system_event("PERSISTENCE_SCAN", f"{len(methods)} méthodes trouvées", "INFO")
                
            except Exception as e:
                self.status_bar.config(text="Erreur lors du scan")
                messagebox.showerror("Erreur", f"Erreur lors du scan: {e}")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def export_alerts(self):
        """Exporte les alertes vers un fichier"""
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                self.alert_manager.export_alerts(filename)
                messagebox.showinfo("Succès", f"Alertes exportées vers {filename}")
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'export: {e}")
    
    def update_interface(self):
        """Met à jour l'interface utilisateur"""
        try:
            # Mettre à jour les alertes
            self.refresh_alerts()
            
            # Mettre à jour les processus
            self.refresh_processes()
            
            # Mettre à jour les statistiques
            self.update_statistics()
            
        except Exception as e:
            print(f"Erreur lors de la mise à jour de l'interface: {e}")
    
    def refresh_alerts(self):
        """Rafraîchit la liste des alertes"""
        # Effacer les éléments existants
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Ajouter les nouvelles alertes
        severity_filter = self.severity_filter.get()
        
        for alert in self.alert_manager.alerts:
            if severity_filter != "Tous" and alert.severity.name != severity_filter:
                continue
            
            timestamp_str = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
            
            self.alerts_tree.insert('', 'end', values=(
                alert.alert_id[:8] + "...",
                alert.alert_type,
                alert.severity.name,
                alert.process_name,
                alert.process_pid,
                timestamp_str,
                alert.description[:50] + "..." if len(alert.description) > 50 else alert.description
            ))
    
    def refresh_processes(self):
        """Rafraîchit la liste des processus"""
        # Effacer les éléments existants
        for item in self.processes_tree.get_children():
            self.processes_tree.delete(item)
        
        # Ajouter les processus suspects
        for process_score in self.rules_engine.get_suspicious_processes():
            last_updated = time.strftime("%H:%M:%S", time.localtime(process_score.last_updated))
            
            self.processes_tree.insert('', 'end', values=(
                process_score.process_pid,
                process_score.process_name,
                process_score.total_score,
                process_score.risk_level,
                last_updated,
                len(process_score.rule_results)
            ))
    
    def update_statistics(self):
        """Met à jour les statistiques"""
        try:
            # Statistiques du moteur de règles
            rules_summary = self.rules_engine.get_detection_summary()
            
            # Statistiques des alertes
            alerts_summary = self.alert_manager.get_alert_summary()
            
            # Mettre à jour les labels
            self.stats_labels['total_processes'].config(text=str(rules_summary['total_processes']))
            self.stats_labels['suspicious_processes'].config(text=str(rules_summary['suspicious_processes']))
            self.stats_labels['high_risk_processes'].config(text=str(rules_summary['high_risk_processes']))
            self.stats_labels['total_alerts'].config(text=str(alerts_summary['total_alerts']))
            self.stats_labels['unacknowledged_alerts'].config(text=str(alerts_summary['unacknowledged_alerts']))
            self.stats_labels['critical_alerts'].config(text=str(alerts_summary['critical_alerts']))
            
        except Exception as e:
            print(f"Erreur lors de la mise à jour des statistiques: {e}")
    
    def filter_alerts(self, event=None):
        """Filtre les alertes par sévérité"""
        self.refresh_alerts()
    
    def acknowledge_selected(self):
        """Acquitte l'alerte sélectionnée"""
        selection = self.alerts_tree.selection()
        if not selection:
            messagebox.showwarning("Attention", "Veuillez sélectionner une alerte")
            return
        
        item = self.alerts_tree.item(selection[0])
        alert_id = item['values'][0] + "..."  # Approximation
        
        # Trouver l'alerte correspondante
        for alert in self.alert_manager.alerts:
            if alert.alert_id.startswith(alert_id.replace("...", "")):
                self.alert_manager.acknowledge_alert(alert.alert_id)
                self.refresh_alerts()
                break
    
    def clear_logs(self):
        """Efface les logs affichés"""
        self.logs_text.delete(1.0, tk.END)
    
    def open_log_file(self):
        """Ouvre le fichier de log"""
        try:
            import subprocess
            import os
            log_file = security_logger.get_log_file_path()
            if os.path.exists(log_file):
                subprocess.Popen(['notepad.exe', log_file])
            else:
                messagebox.showwarning("Attention", "Fichier de log non trouvé")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'ouvrir le fichier de log: {e}")
    
    # Callbacks du système
    def on_new_alert(self, alert):
        """Callback pour les nouvelles alertes"""
        # Ajouter à l'interface (sera mis à jour par la boucle de mise à jour)
        pass
    
    def on_process_change(self, new_processes, terminated_processes):
        """Callback pour les changements de processus"""
        for process in new_processes:
            event = {
                'event_type': 'new_process',
                'data': process.to_dict()
            }
            self.rules_engine.process_event(event)
    
    def on_file_activity(self, event_type, data):
        """Callback pour les activités de fichiers"""
        if event_type == 'file_activity':
            event = {
                'event_type': 'file_activity',
                'data': data
            }
            self.rules_engine.process_event(event)
    
    def on_rules_alert(self, alert_data):
        """Callback pour les alertes du moteur de règles"""
        self.alert_manager.create_keylogger_alert(
            alert_data['process_name'],
            alert_data['process_pid'],
            alert_data['total_score'],
            alert_data
        )
    
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
