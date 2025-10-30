@echo off
echo Lancement du Detecteur de Keyloggers...
echo L'interface graphique va s'ouvrir...
echo Les resultats s'afficheront dans l'interface, pas dans cette console.
echo.

REM Activer l'environnement virtuel
if exist "keylogger_detector_env\Scripts\activate.bat" (
    call keylogger_detector_env\Scripts\activate.bat
)

REM Lancer le programme principal avec l'interface graphique
python main.py --gui

if %errorlevel% neq 0 (
    echo.
    echo Erreur lors du lancement de l'interface graphique.
    echo Tentative en mode console...
    python main.py --console
)

pause