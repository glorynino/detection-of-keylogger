@echo off
echo Activation de l'environnement virtuel pour le detecteur de keyloggers...
call keylogger_detector_env\Scripts\activate.bat
echo Environnement virtuel active!
echo.
echo Commandes disponibles:
echo   python main.py          - Mode console
echo   python main.py --gui    - Interface graphique
echo   python main.py --test   - Mode test (30 secondes)
echo.
cmd /k
