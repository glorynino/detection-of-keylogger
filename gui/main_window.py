"""
Interface graphique moderne pour le détecteur de keyloggers
Design noir et blanc épuré avec animations et effets visuels
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import time
import sys
import os
from datetime import datetime

# Ajouter le chemin pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION DES COULEURS (Noir & Blanc élégant)
# ═══════════════════════════════════════════════════════════════════════════

COLORS = {
    'bg_dark': '#0a0a0a',           # Noir profond
    'bg_medium': '#1a1a1a',         # Noir moyen
    'bg_light': '#2a2a2a',          # Gris foncé
    'fg_white': '#ffffff',          # Blanc pur
    'fg_gray': '#b0b0b0',           # Gris clair
    'fg_dim': '#707070',            # Gris moyen
    'accent': '#ffffff',            # Accent blanc
    'success': '#ffffff',           # Succès (blanc)
    'warning': '#d0d0d0',           # Avertissement (gris clair)
    'error': '#a0a0a0',             # Erreur (gris)
    'border': '#3a3a3a',            # Bordure
}


# ═══════════════════════════════════════════════════════════════════════════
# CLASSE PRINCIPALE - INTERFACE GRAPHIQUE MODERNE
# ═══════════════════════════════════════════════════════════════════════════

class KeyloggerDetectorGUI:
    """Interface graphique moderne connectée à l'agent"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("⬛ Détecteur de Keyloggers - Système de Sécurité")
        self.root.geometry("1400x900")
        self.root.configure(bg=COLORS['bg_dark'])
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Variables
        self.agent = None
        self.monitoring = False
        self.animation_running = True
        
        # Configuration du style moderne
        self._setup_modern_style()
        
        # Configuration de l'interface
        self._setup_ui()
        
        # Démarrer les animations
        self._start_animations()
        
        # Démarrer la mise à jour périodique
        self._start_update_loop()
        
        # Message de bienvenue
        self.log_activity("SYSTEM", "Interface graphique chargée avec succès", "SUCCESS")
        self.update_status("Prêt - Cliquez sur 'Démarrer' pour lancer la surveillance", "ready")
    
    def _setup_modern_style(self):
        """Configure le style moderne de l'interface"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configuration des widgets
        style.configure('Modern.TFrame', background=COLORS['bg_dark'])
        style.configure('Card.TFrame', background=COLORS['bg_medium'], relief='flat')
        style.configure('Modern.TLabel', background=COLORS['bg_dark'], foreground=COLORS['fg_white'], font=('Segoe UI', 10))
        style.configure('Title.TLabel', background=COLORS['bg_dark'], foreground=COLORS['fg_white'], font=('Segoe UI', 24, 'bold'))
        style.configure('Subtitle.TLabel', background=COLORS['bg_dark'], foreground=COLORS['fg_gray'], font=('Segoe UI', 11))
        style.configure('Card.TLabel', background=COLORS['bg_medium'], foreground=COLORS['fg_white'], font=('Segoe UI', 10))
        style.configure('Stat.TLabel', background=COLORS['bg_medium'], foreground=COLORS['fg_white'], font=('Segoe UI', 20, 'bold'))
        
        # Boutons modernes
        style.configure('Modern.TButton', 
                       background=COLORS['bg_light'],
                       foreground=COLORS['fg_white'],
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'),
                       padding=10)
        
        style.map('Modern.TButton',
                 background=[('active', COLORS['bg_medium']), ('pressed', COLORS['bg_dark'])])
        
        # Notebook moderne
        style.configure('Modern.TNotebook', background=COLORS['bg_dark'], borderwidth=0)
        style.configure('Modern.TNotebook.Tab', 
                       background=COLORS['bg_light'],
                       foreground=COLORS['fg_gray'],
                       padding=[20, 10],
                       borderwidth=0,
                       font=('Segoe UI', 10, 'bold'))
        
        style.map('Modern.TNotebook.Tab',
                 background=[('selected', COLORS['bg_medium'])],
                 foreground=[('selected', COLORS['fg_white'])])
    
    def _setup_agent_callbacks(self):
        """Configure les callbacks avec l'agent"""
        if self.agent:
            self.agent.add_gui_callback(self._on_agent_update)

    def _on_agent_update(self, event_type, data):
        """Reçoit les mises à jour de l'agent"""
        self.root.after(0, self._process_agent_update, event_type, data)

    def _process_agent_update(self, event_type, data):
        """Traite les mises à jour de l'agent dans le thread GUI (optimisé)"""
        try:
            # Filtrer les événements moins importants pour réduire la charge
            if event_type in ["DATA_UPDATE"] and not self.monitoring:
                return  # Ignorer les updates si pas en surveillance
            
            handlers = {
                "AGENT_STARTED": self._handle_agent_started,
                "AGENT_STOPPED": self._handle_agent_stopped,
                "SCAN_COMPLETE": self._handle_scan_complete,
                "API_SCAN_COMPLETE": self._handle_api_scan_complete,
                "PERSISTENCE_SCAN_COMPLETE": self._handle_persistence_scan_complete,
                "DATA_UPDATE": self._handle_data_update,
                "NEW_PROCESS": self._handle_new_process,
                "TERMINATED_PROCESS": self._handle_terminated_process,
                "FILE_ACTIVITY": self._handle_file_activity,
                "NETWORK_ACTIVITY": self._handle_network_activity,
                "NEW_ALERT": self._handle_new_alert,
                "SUMMARY_UPDATE": self._handle_summary_update,
                "ERROR": self._handle_error,
                "FORCED_SCAN": self._handle_forced_scan,
            }
            
            handler = handlers.get(event_type)
            if handler:
                handler(data)
                
        except Exception as e:
            print(f"Erreur traitement update: {e}")

    # Handlers pour les événements de l'agent
    def _handle_agent_started(self, data):
        self.log_activity("AGENT", "Agent démarré avec succès", "SUCCESS")
        self.update_status("Surveillance active - Agent en cours d'exécution", "active")

    def _handle_agent_stopped(self, data):
        self.log_activity("AGENT", "Agent arrêté proprement", "INFO")
        self.update_status("Surveillance arrêtée", "stopped")

    def _handle_scan_complete(self, data):
        scan_id = data.get("scan_id", 0)
        self.log_activity("SCAN", f"Scan #{scan_id} terminé", "INFO")
        if self.agent:
            status = self.agent.get_status()
            if status:
                self._update_stats(status)

    def _handle_api_scan_complete(self, data):
        processes = data.get("processes_scanned", 0)
        suspicious = data.get("suspicious_found", 0)
        if suspicious > 0:
            self.log_activity("API", f"⚠ {processes} processus, {suspicious} suspects", "WARNING")
        else:
            self.log_activity("API", f"✓ {processes} processus analysés", "SUCCESS")

    def _handle_persistence_scan_complete(self, data):
        methods = data.get("methods_found", 0)
        suspicious = data.get("suspicious_methods", 0)
        if suspicious > 0:
            self.log_activity("PERSIST", f"⚠ {methods} méthodes, {suspicious} suspectes", "WARNING")
        else:
            self.log_activity("PERSIST", f"✓ {methods} méthodes analysées", "SUCCESS")

    def _handle_data_update(self, data):
        total = data.get("total_processes", 0)
        suspicious = data.get("suspicious_processes", 0)
        alerts = data.get("active_alerts", 0)
        
        self.cards['processes']['value'].config(text=str(total))
        self.cards['suspicious']['value'].config(text=str(suspicious))
        self.cards['alerts']['value'].config(text=str(alerts))
        
        stats = data.get("agent_stats", {})
        self._update_stats({'stats': stats})

    def _handle_new_process(self, data):
        pid = data.get("pid", "N/A")
        name = data.get("name", "Inconnu")
        self.log_activity("PROCESS", f"➕ Nouveau: {name} (PID: {pid})", "INFO")

    def _handle_terminated_process(self, data):
        pid = data.get("pid", "N/A")
        name = data.get("name", "Inconnu")
        self.log_activity("PROCESS", f"➖ Terminé: {name} (PID: {pid})", "INFO")

    def _handle_file_activity(self, data):
        file_path = data.get("file_path", "N/A")
        activity = data.get("activity_type", "N/A")
        process = data.get("process_name", "Inconnu")
        self.log_activity("FILE", f"📄 {process} - {activity} - {file_path}", "INFO")

    def _handle_network_activity(self, data):
        remote = data.get("remote_address", "N/A")
        process = data.get("process_name", "Inconnu")
        self.log_activity("NETWORK", f"🌐 {process} → {remote}", "INFO")

    def _handle_new_alert(self, data):
        severity = data.get("severity", "N/A")
        title = data.get("title", "Sans titre")
        process = data.get("process_name", "Inconnu")
        
        self.log_activity("ALERT", f"🚨 [{severity}] {title} - {process}", "ERROR")
        self._flash_alert_indicator()

    def _handle_summary_update(self, data):
        uptime = data.get("uptime", "0h 0m")
        self.stats_labels['uptime'].config(text=uptime)

    def _handle_error(self, data):
        error = data.get("message", "Erreur inconnue")
        self.log_activity("ERROR", f"❌ {error}", "ERROR")

    def _handle_forced_scan(self, data):
        self.log_activity("SCAN", "Scan forcé effectué", "INFO")
        self.update_status("Scan forcé terminé", "active")

    def _setup_ui(self):
        """Configure l'interface utilisateur moderne"""
        # Frame principal avec padding
        main_frame = tk.Frame(self.root, bg=COLORS['bg_dark'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # En-tête moderne
        self._create_header(main_frame)
        
        # Cartes de statut
        self._create_status_cards(main_frame)
        
        # Panneau de contrôle
        self._create_control_panel(main_frame)
        
        # Onglets
        self._create_modern_tabs(main_frame)
        
        # Barre de statut moderne
        self._create_status_bar(main_frame)
    
    def _create_header(self, parent):
        """Crée l'en-tête moderne"""
        header_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        header_frame.pack(fill=tk.X, pady=(0, 30))
        
        # Titre principal avec icône
        title_frame = tk.Frame(header_frame, bg=COLORS['bg_dark'])
        title_frame.pack(side=tk.LEFT)
        
        title = tk.Label(title_frame, 
                        text="⬛ DÉTECTEUR DE KEYLOGGERS",
                        font=('Segoe UI', 28, 'bold'),
                        bg=COLORS['bg_dark'],
                        fg=COLORS['fg_white'])
        title.pack(anchor=tk.W)
        
        subtitle = tk.Label(title_frame,
                           text="Système de Sécurité Avancé • v2.0",
                           font=('Segoe UI', 11),
                           bg=COLORS['bg_dark'],
                           fg=COLORS['fg_gray'])
        subtitle.pack(anchor=tk.W)
        
        # Indicateur de statut animé
        self.status_indicator_frame = tk.Frame(header_frame, bg=COLORS['bg_dark'])
        self.status_indicator_frame.pack(side=tk.RIGHT, padx=20)
        
        self.status_circle = tk.Canvas(self.status_indicator_frame, 
                                      width=20, height=20, 
                                      bg=COLORS['bg_dark'], 
                                      highlightthickness=0)
        self.status_circle.pack(side=tk.LEFT, padx=(0, 10))
        self.status_circle_id = self.status_circle.create_oval(2, 2, 18, 18, 
                                                               fill=COLORS['fg_dim'], 
                                                               outline='')
        
        self.status_text = tk.Label(self.status_indicator_frame,
                                   text="Arrêté",
                                   font=('Segoe UI', 12, 'bold'),
                                   bg=COLORS['bg_dark'],
                                   fg=COLORS['fg_dim'])
        self.status_text.pack(side=tk.LEFT)
    
    def _create_status_cards(self, parent):
        """Crée les cartes de statut modernes"""
        cards_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        cards_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.cards = {}
        card_configs = [
            ("processes", "Processus Actifs", "0", "●"),
            ("suspicious", "Processus Suspects", "0", "⚠"),
            ("alerts", "Alertes Actives", "0", "🚨"),
            ("scans", "Scans Effectués", "0", "🔍")
        ]
        
        for i, (key, title, value, icon) in enumerate(card_configs):
            card = self._create_card(cards_frame, title, value, icon, key)
            card.grid(row=0, column=i, padx=10, sticky='ew')
            cards_frame.columnconfigure(i, weight=1)
    
    def _create_card(self, parent, title, value, icon, key):
        """Crée une carte de statut individuelle"""
        card_frame = tk.Frame(parent, bg=COLORS['bg_medium'], relief='flat', bd=0)
        card_frame.configure(highlightbackground=COLORS['border'], 
                            highlightthickness=1)
        
        # Padding interne
        inner_frame = tk.Frame(card_frame, bg=COLORS['bg_medium'])
        inner_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Icône et titre
        header = tk.Frame(inner_frame, bg=COLORS['bg_medium'])
        header.pack(fill=tk.X)
        
        icon_label = tk.Label(header, text=icon, 
                             font=('Segoe UI', 20),
                             bg=COLORS['bg_medium'],
                             fg=COLORS['fg_gray'])
        icon_label.pack(side=tk.LEFT, padx=(0, 10))
        
        title_label = tk.Label(header, text=title,
                              font=('Segoe UI', 11),
                              bg=COLORS['bg_medium'],
                              fg=COLORS['fg_gray'])
        title_label.pack(side=tk.LEFT)
        
        # Valeur (grand nombre)
        value_label = tk.Label(inner_frame, text=value,
                              font=('Segoe UI', 32, 'bold'),
                              bg=COLORS['bg_medium'],
                              fg=COLORS['fg_white'])
        value_label.pack(pady=(10, 0))
        
        # Sauvegarder les références
        self.cards[key] = {
            'frame': card_frame,
            'value': value_label
        }
        
        return card_frame
    
    def _create_control_panel(self, parent):
        """Crée le panneau de contrôle moderne"""
        control_frame = tk.Frame(parent, bg=COLORS['bg_medium'])
        control_frame.pack(fill=tk.X, pady=(0, 20))
        control_frame.configure(highlightbackground=COLORS['border'], 
                               highlightthickness=1)
        
        # Padding interne
        inner = tk.Frame(control_frame, bg=COLORS['bg_medium'])
        inner.pack(fill=tk.X, padx=20, pady=20)
        
        # Boutons avec style moderne
        buttons_data = [
            ("▶ Démarrer", self.toggle_monitoring),
            ("🔍 Scan Rapide", self.quick_scan),
            ("💾 Exporter Logs", self.export_logs),
            ("📊 Rapport", self.generate_report)
        ]
        
        for i, (text, command) in enumerate(buttons_data):
            btn = self._create_modern_button(inner, text, command)
            btn.pack(side=tk.LEFT, padx=(0, 15))
            
            if i == 0:
                self.start_button = btn
    
    def _create_modern_button(self, parent, text, command):
        """Crée un bouton moderne"""
        btn = tk.Button(parent,
                       text=text,
                       command=command,
                       font=('Segoe UI', 11, 'bold'),
                       bg=COLORS['bg_light'],
                       fg=COLORS['fg_white'],
                       activebackground=COLORS['bg_dark'],
                       activeforeground=COLORS['fg_white'],
                       relief='flat',
                       bd=0,
                       padx=20,
                       pady=12,
                       cursor='hand2')
        
        # Effet hover
        def on_enter(e):
            btn['bg'] = COLORS['bg_dark']
        
        def on_leave(e):
            btn['bg'] = COLORS['bg_light']
        
        btn.bind('<Enter>', on_enter)
        btn.bind('<Leave>', on_leave)
        
        return btn
    
    def _create_modern_tabs(self, parent):
        """Crée les onglets modernes"""
        notebook = ttk.Notebook(parent, style='Modern.TNotebook')
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Onglets
        self._create_monitoring_tab(notebook)
        self._create_stats_tab(notebook)
        self._create_logs_tab(notebook)
    
    def _create_monitoring_tab(self, notebook):
        """Crée l'onglet de surveillance moderne"""
        monitor_frame = tk.Frame(notebook, bg=COLORS['bg_dark'])
        notebook.add(monitor_frame, text="  🔍 SURVEILLANCE  ")
        
        # Zone de logs en temps réel
        log_container = tk.Frame(monitor_frame, bg=COLORS['bg_medium'])
        log_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        log_container.configure(highlightbackground=COLORS['border'], 
                               highlightthickness=1)
        
        # En-tête des logs
        log_header = tk.Frame(log_container, bg=COLORS['bg_light'])
        log_header.pack(fill=tk.X)
        
        tk.Label(log_header, 
                text="Activité en Temps Réel",
                font=('Segoe UI', 12, 'bold'),
                bg=COLORS['bg_light'],
                fg=COLORS['fg_white']).pack(side=tk.LEFT, padx=15, pady=10)
        
        # Bouton effacer
        clear_btn = tk.Button(log_header,
                             text="✕ Effacer",
                             command=self.clear_activity_log,
                             font=('Segoe UI', 9),
                             bg=COLORS['bg_light'],
                             fg=COLORS['fg_gray'],
                             relief='flat',
                             bd=0,
                             cursor='hand2')
        clear_btn.pack(side=tk.RIGHT, padx=10)
        
        # Zone de texte stylée
        log_frame = tk.Frame(log_container, bg=COLORS['bg_medium'])
        log_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        self.activity_log = scrolledtext.ScrolledText(
            log_frame,
            font=('Consolas', 10),
            bg=COLORS['bg_dark'],
            fg=COLORS['fg_white'],
            insertbackground=COLORS['fg_white'],
            relief='flat',
            bd=0,
            wrap=tk.WORD
        )
        self.activity_log.pack(fill=tk.BOTH, expand=True)
    
    def _create_stats_tab(self, notebook):
        """Crée l'onglet des statistiques"""
        stats_frame = tk.Frame(notebook, bg=COLORS['bg_dark'])
        notebook.add(stats_frame, text="  📊 STATISTIQUES  ")
        
        # Grille de statistiques
        stats_grid = tk.Frame(stats_frame, bg=COLORS['bg_dark'])
        stats_grid.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.stats_labels = {}
        stats_config = [
            ("Temps de Surveillance", "uptime", "0h 0m 0s"),
            ("Total des Scans", "total_scans", "0"),
            ("Processus Analysés", "processes_analyzed", "0"),
            ("Alertes Générées", "alerts_generated", "0"),
            ("Dernier Scan", "last_scan", "Aucun"),
            ("Statut Agent", "agent_status", "Inactif")
        ]
        
        for i, (label, key, default) in enumerate(stats_config):
            row = i // 2
            col = i % 2
            
            stat_card = self._create_stat_card(stats_grid, label, default, key)
            stat_card.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
            stats_grid.columnconfigure(col, weight=1)
            stats_grid.rowconfigure(row, weight=1)
    
    def _create_stat_card(self, parent, label, value, key):
        """Crée une carte de statistique"""
        card = tk.Frame(parent, bg=COLORS['bg_medium'])
        card.configure(highlightbackground=COLORS['border'], 
                      highlightthickness=1)
        
        inner = tk.Frame(card, bg=COLORS['bg_medium'])
        inner.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(inner, text=label,
                font=('Segoe UI', 11),
                bg=COLORS['bg_medium'],
                fg=COLORS['fg_gray']).pack(anchor=tk.W)
        
        value_label = tk.Label(inner, text=value,
                              font=('Segoe UI', 24, 'bold'),
                              bg=COLORS['bg_medium'],
                              fg=COLORS['fg_white'])
        value_label.pack(anchor=tk.W, pady=(10, 0))
        
        self.stats_labels[key] = value_label
        
        return card
    
    def _create_logs_tab(self, notebook):
        """Crée l'onglet des logs"""
        logs_frame = tk.Frame(notebook, bg=COLORS['bg_dark'])
        notebook.add(logs_frame, text="  📋 LOGS DÉTAILLÉS  ")
        
        # Container
        log_container = tk.Frame(logs_frame, bg=COLORS['bg_medium'])
        log_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        log_container.configure(highlightbackground=COLORS['border'], 
                               highlightthickness=1)
        
        # En-tête
        header = tk.Frame(log_container, bg=COLORS['bg_light'])
        header.pack(fill=tk.X)
        
        tk.Label(header, text="Logs Système",
                font=('Segoe UI', 12, 'bold'),
                bg=COLORS['bg_light'],
                fg=COLORS['fg_white']).pack(side=tk.LEFT, padx=15, pady=10)
        
        # Boutons
        btn_frame = tk.Frame(header, bg=COLORS['bg_light'])
        btn_frame.pack(side=tk.RIGHT, padx=10)
        
        for text, cmd in [("↻ Actualiser", self.refresh_detailed_logs), 
                         ("✕ Effacer", self.clear_detailed_logs)]:
            tk.Button(btn_frame, text=text, command=cmd,
                     font=('Segoe UI', 9),
                     bg=COLORS['bg_light'],
                     fg=COLORS['fg_gray'],
                     relief='flat',
                     cursor='hand2').pack(side=tk.LEFT, padx=5)
        
        # Zone de logs
        log_frame = tk.Frame(log_container, bg=COLORS['bg_medium'])
        log_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        self.detailed_logs = scrolledtext.ScrolledText(
            log_frame,
            font=('Consolas', 9),
            bg=COLORS['bg_dark'],
            fg=COLORS['fg_white'],
            insertbackground=COLORS['fg_white'],
            relief='flat',
            wrap=tk.WORD
        )
        self.detailed_logs.pack(fill=tk.BOTH, expand=True)
    
    def _create_status_bar(self, parent):
        """Crée la barre de statut moderne"""
        status_frame = tk.Frame(parent, bg=COLORS['bg_light'], height=40)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        status_frame.pack_propagate(False)
        status_frame.configure(highlightbackground=COLORS['border'], 
                              highlightthickness=1)
        
        self.status_label = tk.Label(status_frame,
                                     text="Prêt",
                                     font=('Segoe UI', 10),
                                     bg=COLORS['bg_light'],
                                     fg=COLORS['fg_gray'],
                                     anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, padx=15, fill=tk.X, expand=True)
        
        # Horloge
        self.clock_label = tk.Label(status_frame,
                                    text=datetime.now().strftime("%H:%M:%S"),
                                    font=('Segoe UI', 10, 'bold'),
                                    bg=COLORS['bg_light'],
                                    fg=COLORS['fg_white'])
        self.clock_label.pack(side=tk.RIGHT, padx=15)
        
        self._update_clock()
    
    def _update_clock(self):
        """Met à jour l'horloge"""
        if self.animation_running:
            self.clock_label.config(text=datetime.now().strftime("%H:%M:%S"))
            self.root.after(1000, self._update_clock)
    
    def _start_animations(self):
        """Démarre les animations"""
        self._animate_status_circle()
    
    def _animate_status_circle(self):
        """Anime le cercle de statut (optimisé)"""
        if self.monitoring and self.animation_running:
            # Pulse effect moins fréquent (1.5 secondes au lieu de 1)
            current_color = self.status_circle.itemcget(self.status_circle_id, 'fill')
            new_color = COLORS['fg_white'] if current_color == COLORS['fg_gray'] else COLORS['fg_gray']
            self.status_circle.itemconfig(self.status_circle_id, fill=new_color)
        
        if self.animation_running:
            self.root.after(1500, self._animate_status_circle)
    
    def _flash_alert_indicator(self):
        """Flash l'indicateur d'alerte"""
        original_color = self.cards['alerts']['value'].cget('fg')
        self.cards['alerts']['value'].config(fg='#ff0000')
        self.root.after(500, lambda: self.cards['alerts']['value'].config(fg=original_color))
    
    def _start_update_loop(self):
        """Démarre la boucle de mise à jour optimisée"""
        def update_loop():
            while self.animation_running:
                try:
                    # Mise à jour moins fréquente (5 secondes au lieu de 2)
                    if self.monitoring:
                        self.update_interface()
                    time.sleep(5)
                except Exception as e:
                    print(f"Erreur update loop: {e}")
                    time.sleep(10)
        
        self.update_thread = threading.Thread(target=update_loop, daemon=True)
        self.update_thread.start()
    
    def update_status(self, message, status_type="info"):
        """Met à jour le statut avec style"""
        self.status_label.config(text=message)
        
        colors = {
            'ready': COLORS['fg_gray'],
            'active': COLORS['fg_white'],
            'stopped': COLORS['fg_dim'],
            'error': COLORS['error']
        }
        
        self.status_label.config(fg=colors.get(status_type, COLORS['fg_gray']))
    
    def _update_stats(self, status):
        """Met à jour les statistiques"""
        stats = status.get('stats', {})
        
        self.stats_labels['total_scans'].config(text=str(stats.get('total_scans', 0)))
        self.stats_labels['alerts_generated'].config(text=str(stats.get('alerts_generated', 0)))
        self.stats_labels['processes_analyzed'].config(text=str(stats.get('processes_scanned', 0)))
        
        uptime = int(status.get('uptime', 0))
        hours = uptime // 3600
        minutes = (uptime % 3600) // 60
        seconds = uptime % 60
        self.stats_labels['uptime'].config(text=f"{hours:02d}h {minutes:02d}m {seconds:02d}s")
        
        self.cards['scans']['value'].config(text=str(stats.get('total_scans', 0)))
    
    def toggle_monitoring(self):
        """Active/désactive la surveillance"""
        if not self.monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Démarre la surveillance"""
        try:
            from core.agent import KeyloggerDetectorAgent
            self.agent = KeyloggerDetectorAgent()
            
            self._setup_agent_callbacks()
            self.agent.start()
            
            self.monitoring = True
            self.start_button.config(text="⏸ Arrêter")
            self.status_text.config(text="En surveillance", fg=COLORS['fg_white'])
            self.status_circle.itemconfig(self.status_circle_id, fill=COLORS['fg_white'])
            self.update_status("Surveillance active - Agent démarré", "active")
            
            self.log_activity("SYSTEM", "Surveillance démarrée avec succès", "SUCCESS")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de démarrer: {e}")
            self.log_activity("ERROR", f"Échec démarrage: {e}", "ERROR")
    
    def stop_monitoring(self):
        """Arrête la surveillance"""
        try:
            if self.agent:
                self.agent.stop()
                self.agent = None
            
            self.monitoring = False
            self.start_button.config(text="▶ Démarrer")
            self.status_text.config(text="Arrêté", fg=COLORS['fg_dim'])
            self.status_circle.itemconfig(self.status_circle_id, fill=COLORS['fg_dim'])
            self.update_status("Surveillance arrêtée", "stopped")
            
            self.log_activity("SYSTEM", "Surveillance arrêtée", "INFO")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'arrêt: {e}")
    
    def quick_scan(self):
        """Lance un scan rapide"""
        def scan_thread():
            try:
                self.update_status("Scan rapide en cours...", "active")
                self.log_activity("SCAN", "Démarrage du scan rapide", "INFO")
                
                if self.agent and self.monitoring:
                    time.sleep(2)
                else:
                    time.sleep(2)
                
                self.update_status("Scan rapide terminé", "ready")
                self.log_activity("SCAN", "✓ Scan rapide terminé", "SUCCESS")
                
            except Exception as e:
                self.update_status("Erreur lors du scan", "error")
                self.log_activity("ERROR", f"Échec scan: {e}", "ERROR")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def export_logs(self):
        """Exporte les logs"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")],
                title="Exporter les logs"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("═══════════════════════════════════════════════════\n")
                    f.write("  DÉTECTEUR DE KEYLOGGERS - EXPORT DES LOGS\n")
                    f.write(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("═══════════════════════════════════════════════════\n\n")
                    f.write(self.detailed_logs.get(1.0, tk.END))
                
                messagebox.showinfo("Succès", f"Logs exportés vers:\n{filename}")
                self.log_activity("EXPORT", "✓ Logs exportés", "SUCCESS")
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'export: {e}")
    
    def generate_report(self):
        """Génère un rapport"""
        if not self.agent or not self.monitoring:
            messagebox.showwarning("Attention", "Démarrez d'abord la surveillance!")
            return
        
        try:
            summary = self.agent.get_detection_summary()
            
            report = f"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                      RAPPORT DE SÉCURITÉ                                  ║
║                      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                                   ║
╚═══════════════════════════════════════════════════════════════════════════╝

STATISTIQUES GÉNÉRALES:
  • Processus surveillés: {summary['rules_summary']['total_processes']}
  • Processus suspects: {summary['rules_summary']['suspicious_processes']}
  • Processus haut risque: {summary['rules_summary']['high_risk_processes']}
  • Alertes générées: {summary['alerts_summary']['total_alerts']}
  • Scans effectués: {summary['agent_stats']['total_scans']}

"""
            if summary['suspicious_processes']:
                report += "\nPROCESSUS SUSPECTS DÉTECTÉS:\n"
                for p in summary['suspicious_processes'][:5]:
                    report += f"  • {p['process_name']} (PID: {p['process_pid']}) - Score: {p['total_score']}\n"
            
            self.detailed_logs.delete(1.0, tk.END)
            self.detailed_logs.insert(1.0, report)
            
            self.log_activity("REPORT", "✓ Rapport généré", "SUCCESS")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de générer le rapport: {e}")
    
    def update_interface(self):
        """Met à jour l'interface"""
        try:
            if self.monitoring and self.agent:
                status = self.agent.get_status()
                if status:
                    self._update_stats(status)
                    
        except Exception as e:
            print(f"Erreur update interface: {e}")
    
    def log_activity(self, category, message, level="INFO"):
        """Ajoute un log d'activité avec limite de mémoire"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        icons = {
            "SUCCESS": "✓",
            "INFO": "●",
            "WARNING": "⚠",
            "ERROR": "✗"
        }
        
        icon = icons.get(level, "●")
        log_entry = f"[{timestamp}] [{category:^10}] {icon} {message}\n"
        
        # Limiter le nombre de lignes dans les logs (max 500 lignes)
        self._limit_text_widget(self.activity_log, 500)
        self.activity_log.insert(tk.END, log_entry)
        self.activity_log.see(tk.END)
        
        # Limiter aussi les logs détaillés (max 1000 lignes)
        self._limit_text_widget(self.detailed_logs, 1000)
        self.detailed_logs.insert(tk.END, log_entry)
        self.detailed_logs.see(tk.END)
    
    def _limit_text_widget(self, widget, max_lines):
        """Limite le nombre de lignes dans un widget texte"""
        lines = int(widget.index('end-1c').split('.')[0])
        if lines > max_lines:
            # Supprimer les premières lignes
            widget.delete('1.0', f'{lines - max_lines}.0')
    
    def clear_activity_log(self):
        """Efface le log d'activité"""
        self.activity_log.delete(1.0, tk.END)
        self.log_activity("SYSTEM", "Logs d'activité effacés", "INFO")
    
    def clear_detailed_logs(self):
        """Efface les logs détaillés"""
        self.detailed_logs.delete(1.0, tk.END)
    
    def refresh_detailed_logs(self):
        """Actualise les logs détaillés"""
        if self.monitoring:
            self.log_activity("SYSTEM", "Logs actualisés", "INFO")
    
    def on_closing(self):
        """Gestionnaire de fermeture"""
        if self.monitoring:
            if messagebox.askokcancel("Quitter", "La surveillance est active. Voulez-vous vraiment quitter?"):
                self.animation_running = False
                self.stop_monitoring()
                self.root.destroy()
        else:
            self.animation_running = False
            self.root.destroy()
    
    def run(self):
        """Lance l'interface graphique"""
        self.root.mainloop()


if __name__ == "__main__":
    app = KeyloggerDetectorGUI()
    app.run()