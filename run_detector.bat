@echo off
echo ========================================
echo   DETECTEUR DE KEYLOGGERS
echo ========================================
echo.

REM Activer l'environnement virtuel
call keylogger_detector_env\Scripts\activate.bat

echo Selectionnez le mode d'execution:
echo 1. Mode Console
echo 2. Interface Graphique  
echo 3. Mode Test (30 secondes)
echo.
set /p choice="Votre choix (1-3): "

if "%choice%"=="1" (
    echo Lancement en mode console...
    python main.py
) else if "%choice%"=="2" (
    echo Lancement de l'interface graphique...
    python main.py --gui
) else if "%choice%"=="3" (
    echo Lancement du mode test...
    python main.py --test
) else (
    echo Choix invalide. Lancement du mode console par defaut...
    python main.py
)

pause
