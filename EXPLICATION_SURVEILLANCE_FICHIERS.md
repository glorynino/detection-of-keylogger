# Explication : Surveillance de Tous les Fichiers

## 🎯 Problème Identifié

Vous avez raison ! Un système de détection de keyloggers devrait surveiller **TOUS les fichiers**, pas seulement certains dossiers spécifiques.

## ✅ Solution Implémentée

J'ai modifié le système pour utiliser **deux méthodes complémentaires** :

### 1. **Surveillance par Dossiers** (watchdog)
- Surveille les dossiers suspects en temps réel
- Détecte immédiatement les créations/modifications
- **Limitation** : Seulement certains dossiers

### 2. **Surveillance par Processus** (NOUVEAU) ⭐
- Scanne **TOUS les processus** en cours
- Vérifie les fichiers ouverts/écrits par chaque processus
- Détecte les fichiers suspects **peu importe leur emplacement**
- **Avantage** : Détecte les fichiers partout sur le système

## 🔍 Comment ça fonctionne maintenant

### Méthode 1 : Surveillance des dossiers (watchdog)
```
Surveille en temps réel :
- %TEMP%
- %APPDATA%
- %LOCALAPPDATA%
- Documents
- Desktop
- keylogger-test/
```

### Méthode 2 : Scan des processus (NOUVEAU)
```
Toutes les 10 secondes :
1. Parcourt TOUS les processus
2. Vérifie les fichiers ouverts par chaque processus
3. Détecte les fichiers avec noms suspects :
   - keylog.txt
   - keys.txt
   - input.log
   - capture.txt
   - etc.
4. Peu importe où se trouve le fichier !
```

## 📊 Détection des Fichiers Suspects

Un fichier est considéré suspect si :

1. **Nom suspect** : Contient `keylog`, `logger`, `keys`, `input`, `capture`
2. **Extension suspecte** : `.log`, `.txt`, `.dat`, `.tmp`, `.key`, `.klg`
3. **Emplacement suspect** : Dans TEMP, APPDATA, etc.

**Exemple :**
```
Fichier: C:\Users\neili\Desktop\keylog.txt
→ Nom suspect: "keylog" ✅
→ Extension suspecte: ".txt" ✅
→ DÉTECTÉ ! (même si pas dans un dossier surveillé)
```

## 🎯 Résultat

Maintenant le système détecte :
- ✅ Les fichiers dans les dossiers surveillés (watchdog)
- ✅ **Les fichiers partout ailleurs** (scan des processus)
- ✅ **Peu importe l'emplacement** du fichier

## ⚡ Performance

- **Scan des processus** : Toutes les 10 secondes
- **Évite les doublons** : Ignore les fichiers détectés il y a moins de 30 secondes
- **Optimisé** : Ne scanne que les fichiers avec noms/extensions suspects

## 📝 Exemple Concret

**Avant :**
```
keylog.txt dans C:\Users\neili\Documents\
→ ❌ NON DÉTECTÉ (Documents n'était pas surveillé)
```

**Maintenant :**
```
keylog.txt dans C:\Users\neili\Documents\
→ ✅ DÉTECTÉ ! (scan des processus trouve le fichier ouvert)
→ ✅ DÉTECTÉ ! (Documents est maintenant surveillé aussi)
```

Le système surveille maintenant **beaucoup plus de fichiers** ! 🎉

