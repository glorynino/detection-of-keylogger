"""
Système de cache pour optimiser les scans et éviter les rescans inutiles
"""

import time
import hashlib
from typing import Dict, Optional, Tuple
from collections import defaultdict


class ScanCache:
    """Cache pour éviter de rescanner les mêmes processus"""
    
    def __init__(self, cache_ttl: int = 300):  # 5 minutes par défaut
        self.cache_ttl = cache_ttl
        self.api_scan_cache: Dict[int, Tuple[Dict, float]] = {}  # PID -> (result, timestamp)
        self.process_hash_cache: Dict[int, str] = {}  # PID -> hash du processus
        self.lock = None
        try:
            import threading
            self.lock = threading.Lock()
        except:
            pass
    
    def _get_process_hash(self, process_info) -> str:
        """Génère un hash unique pour un processus"""
        try:
            # Hash basé sur le nom, exe, et cmdline
            key = f"{process_info.name}|{process_info.exe}|{process_info.cmdline}"
            return hashlib.md5(key.encode()).hexdigest()
        except:
            return ""
    
    def should_scan_process(self, pid: int, process_info) -> bool:
        """Détermine si un processus doit être scanné"""
        current_hash = self._get_process_hash(process_info)
        current_time = time.time()
        
        # Vérifier si le processus a changé
        if pid in self.process_hash_cache:
            if self.process_hash_cache[pid] == current_hash:
                # Processus identique, vérifier le cache
                if pid in self.api_scan_cache:
                    result, timestamp = self.api_scan_cache[pid]
                    if current_time - timestamp < self.cache_ttl:
                        return False  # Cache valide, ne pas rescanner
                else:
                    return False  # Pas de cache mais processus identique
        
        # Processus nouveau ou modifié
        self.process_hash_cache[pid] = current_hash
        return True
    
    def get_cached_result(self, pid: int) -> Optional[Dict]:
        """Récupère un résultat en cache"""
        current_time = time.time()
        
        if pid in self.api_scan_cache:
            result, timestamp = self.api_scan_cache[pid]
            if current_time - timestamp < self.cache_ttl:
                return result
            else:
                # Cache expiré
                del self.api_scan_cache[pid]
        
        return None
    
    def cache_result(self, pid: int, result: Dict):
        """Met en cache un résultat de scan"""
        current_time = time.time()
        self.api_scan_cache[pid] = (result, current_time)
    
    def clear_expired(self):
        """Nettoie les entrées expirées du cache"""
        current_time = time.time()
        expired_pids = []
        
        for pid, (result, timestamp) in self.api_scan_cache.items():
            if current_time - timestamp >= self.cache_ttl:
                expired_pids.append(pid)
        
        for pid in expired_pids:
            del self.api_scan_cache[pid]
            if pid in self.process_hash_cache:
                del self.process_hash_cache[pid]
    
    def clear_process(self, pid: int):
        """Supprime un processus du cache"""
        if pid in self.api_scan_cache:
            del self.api_scan_cache[pid]
        if pid in self.process_hash_cache:
            del self.process_hash_cache[pid]
    
    def get_cache_stats(self) -> Dict:
        """Retourne les statistiques du cache"""
        return {
            'cached_processes': len(self.api_scan_cache),
            'total_hashes': len(self.process_hash_cache),
            'cache_ttl': self.cache_ttl
        }
