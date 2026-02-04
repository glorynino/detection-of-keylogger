"""
Module d'analyse comportementale pour détecter les keyloggers
"""

import time
from typing import Dict, List, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta
import psutil


class BehavioralEvent:
    """Représente un événement comportemental"""
    
    def __init__(self, event_type: str, process_pid: int, process_name: str, 
                 data: Dict = None, timestamp: float = None):
        self.event_type = event_type  # 'api_call', 'file_write', 'network_send', etc.
        self.process_pid = process_pid
        self.process_name = process_name
        self.data = data or {}
        self.timestamp = timestamp or time.time()
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            'event_type': self.event_type,
            'process_pid': self.process_pid,
            'process_name': self.process_name,
            'data': self.data,
            'timestamp': self.timestamp
        }


class BehavioralAnalyzer:
    """Analyseur comportemental pour détecter les patterns de keyloggers"""
    
    def __init__(self, time_window: float = 300.0):  # 5 minutes par défaut
        self.time_window = time_window
        self.events: deque = deque(maxlen=10000)  # Garder les 10000 derniers événements
        self.process_patterns: Dict[int, Dict] = defaultdict(dict)
        self.suspicious_patterns: List[Dict] = []
    
    def add_event(self, event: BehavioralEvent):
        """Ajoute un événement à l'analyse"""
        self.events.append(event)
        
        # Mettre à jour les patterns du processus
        pid = event.process_pid
        if pid not in self.process_patterns:
            self.process_patterns[pid] = {
                'process_name': event.process_name,
                'api_calls': [],
                'file_writes': [],
                'network_sends': [],
                'first_seen': event.timestamp,
                'last_seen': event.timestamp
            }
        
        pattern = self.process_patterns[pid]
        pattern['last_seen'] = event.timestamp
        
        # Catégoriser l'événement
        if event.event_type == 'api_call':
            pattern['api_calls'].append(event)
        elif event.event_type == 'file_write':
            pattern['file_writes'].append(event)
        elif event.event_type == 'network_send':
            pattern['network_sends'].append(event)
        
        # Analyser les patterns suspects
        self._analyze_patterns(pid)
    
    def _analyze_patterns(self, process_pid: int):
        """Analyse les patterns comportementaux d'un processus"""
        if process_pid not in self.process_patterns:
            return
        
        pattern = self.process_patterns[process_pid]
        current_time = time.time()
        
        # Filtrer les événements dans la fenêtre de temps
        window_start = current_time - self.time_window
        
        # Pattern 1: Fréquence élevée d'appels API suspectes
        recent_api_calls = [
            e for e in pattern['api_calls']
            if e.timestamp >= window_start
        ]
        
        if len(recent_api_calls) > 50:  # Plus de 50 appels API en 5 minutes
            self._add_suspicious_pattern(
                process_pid,
                'HIGH_API_FREQUENCY',
                f"Forte fréquence d'appels API: {len(recent_api_calls)} appels en {self.time_window}s",
                {'api_call_count': len(recent_api_calls)}
            )
        
        # Pattern 2: Combinaison API suspecte + écriture fichier
        recent_file_writes = [
            e for e in pattern['file_writes']
            if e.timestamp >= window_start
        ]
        
        if len(recent_api_calls) > 10 and len(recent_file_writes) > 5:
            # API suspectes suivies d'écritures de fichiers = pattern keylogger
            self._add_suspicious_pattern(
                process_pid,
                'API_FILE_CORRELATION',
                f"Corrélation suspecte: {len(recent_api_calls)} appels API + {len(recent_file_writes)} écritures fichiers",
                {
                    'api_calls': len(recent_api_calls),
                    'file_writes': len(recent_file_writes)
                }
            )
        
        # Pattern 3: Combinaison API suspecte + envoi réseau
        recent_network_sends = [
            e for e in pattern['network_sends']
            if e.timestamp >= window_start
        ]
        
        if len(recent_api_calls) > 10 and len(recent_network_sends) > 3:
            # API suspectes suivies d'envois réseau = pattern keylogger réseau
            self._add_suspicious_pattern(
                process_pid,
                'API_NETWORK_CORRELATION',
                f"Corrélation suspecte: {len(recent_api_calls)} appels API + {len(recent_network_sends)} envois réseau",
                {
                    'api_calls': len(recent_api_calls),
                    'network_sends': len(recent_network_sends)
                }
            )
        
        # Pattern 4: Écritures de fichiers à intervalles réguliers (capture périodique)
        if len(recent_file_writes) > 10:
            intervals = []
            sorted_writes = sorted(recent_file_writes, key=lambda x: x.timestamp)
            for i in range(1, len(sorted_writes)):
                interval = sorted_writes[i].timestamp - sorted_writes[i-1].timestamp
                intervals.append(interval)
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                # Si les intervalles sont réguliers (écart type faible), c'est suspect
                if avg_interval > 0:
                    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                    std_dev = variance ** 0.5
                    
                    # Si l'écart type est faible (< 20% de la moyenne), c'est régulier
                    if std_dev < avg_interval * 0.2:
                        self._add_suspicious_pattern(
                            process_pid,
                            'REGULAR_FILE_WRITES',
                            f"Écritures de fichiers à intervalles réguliers: ~{avg_interval:.1f}s",
                            {'avg_interval': avg_interval, 'std_dev': std_dev}
                        )
        
        # Pattern 5: Triade complète (API + fichier + réseau)
        if (len(recent_api_calls) > 5 and 
            len(recent_file_writes) > 3 and 
            len(recent_network_sends) > 2):
            self._add_suspicious_pattern(
                process_pid,
                'COMPLETE_KEYLOGGER_PATTERN',
                "Pattern complet de keylogger détecté: API + Fichier + Réseau",
                {
                    'api_calls': len(recent_api_calls),
                    'file_writes': len(recent_file_writes),
                    'network_sends': len(recent_network_sends)
                }
            )
    
    def _add_suspicious_pattern(self, process_pid: int, pattern_type: str, 
                                description: str, evidence: Dict):
        """Ajoute un pattern suspect détecté"""
        pattern = {
            'process_pid': process_pid,
            'process_name': self.process_patterns[process_pid]['process_name'],
            'pattern_type': pattern_type,
            'description': description,
            'evidence': evidence,
            'timestamp': time.time(),
            'severity': self._calculate_pattern_severity(pattern_type)
        }
        
        # Éviter les doublons récents
        recent_patterns = [
            p for p in self.suspicious_patterns
            if (p['process_pid'] == process_pid and 
                p['pattern_type'] == pattern_type and
                time.time() - p['timestamp'] < 60)  # Moins d'1 minute
        ]
        
        if not recent_patterns:
            self.suspicious_patterns.append(pattern)
    
    def _calculate_pattern_severity(self, pattern_type: str) -> str:
        """Calcule la sévérité d'un pattern"""
        severity_map = {
            'HIGH_API_FREQUENCY': 'MEDIUM',
            'API_FILE_CORRELATION': 'HIGH',
            'API_NETWORK_CORRELATION': 'HIGH',
            'REGULAR_FILE_WRITES': 'MEDIUM',
            'COMPLETE_KEYLOGGER_PATTERN': 'CRITICAL'
        }
        return severity_map.get(pattern_type, 'LOW')
    
    def get_suspicious_patterns(self, process_pid: Optional[int] = None) -> List[Dict]:
        """Retourne les patterns suspects"""
        if process_pid:
            return [
                p for p in self.suspicious_patterns
                if p['process_pid'] == process_pid
            ]
        return self.suspicious_patterns
    
    def get_process_behavior_score(self, process_pid: int) -> Dict:
        """Calcule un score comportemental pour un processus"""
        if process_pid not in self.process_patterns:
            return {
                'score': 0,
                'risk_level': 'LOW',
                'patterns': []
            }
        
        pattern = self.process_patterns[process_pid]
        current_time = time.time()
        window_start = current_time - self.time_window
        
        # Compter les événements récents
        recent_api_calls = len([
            e for e in pattern['api_calls']
            if e.timestamp >= window_start
        ])
        recent_file_writes = len([
            e for e in pattern['file_writes']
            if e.timestamp >= window_start
        ])
        recent_network_sends = len([
            e for e in pattern['network_sends']
            if e.timestamp >= window_start
        ])
        
        # Calculer le score
        score = 0
        score += min(recent_api_calls * 2, 50)  # Max 50 points
        score += min(recent_file_writes * 5, 30)  # Max 30 points
        score += min(recent_network_sends * 10, 40)  # Max 40 points
        
        # Bonus pour les patterns suspects
        suspicious_patterns = self.get_suspicious_patterns(process_pid)
        score += len(suspicious_patterns) * 20
        
        # Déterminer le niveau de risque
        if score >= 100:
            risk_level = 'CRITICAL'
        elif score >= 60:
            risk_level = 'HIGH'
        elif score >= 30:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'score': score,
            'risk_level': risk_level,
            'api_calls': recent_api_calls,
            'file_writes': recent_file_writes,
            'network_sends': recent_network_sends,
            'patterns': suspicious_patterns,
            'process_name': pattern['process_name']
        }
    
    def get_summary(self) -> Dict:
        """Retourne un résumé de l'analyse comportementale"""
        suspicious_processes = set()
        for pattern in self.suspicious_patterns:
            suspicious_processes.add(pattern['process_pid'])
        
        return {
            'total_events': len(self.events),
            'monitored_processes': len(self.process_patterns),
            'suspicious_processes': len(suspicious_processes),
            'suspicious_patterns': len(self.suspicious_patterns),
            'pattern_types': {
                p['pattern_type']: sum(1 for pat in self.suspicious_patterns 
                                     if pat['pattern_type'] == p['pattern_type'])
                for p in self.suspicious_patterns
            }
        }

