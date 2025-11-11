@echo off
title DESEMAP Installer - 0x1A7
color 0a
echo.
echo [*] DEEPMAP (0x1A7) Kurulum Basliyor...
echo ---------------------------------------------

REM 
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python yüklü degil. https://www.python.org/downloads adresinden kur.
    echo Kurulumda "Add Python to PATH" secenegini isaretle.
    pause
    exit /b
)

REM Virtualenv olustur
echo [*] Virtual environment (venv) olusturuluyor...
python -m venv .venv
if errorlevel 1 (
    echo [!] venv olusturulamadi.
    pause
    exit /b
)

call .venv\Scripts\activate

REM pip guncelle
echo [*] pip guncelleniyor...
python -m pip install --upgrade pip >nul

REM Paketleri yukle
if exist requirements.txt (
    echo [*] Gerekli kutuphaneler yukleniyor...
    pip install -r requirements.txt
) else (
    echo [*] requirements.txt bulunamadi, manuel yukleme yapiliyor...
    pip install requests beautifulsoup4 lxml
)

echo ---------------------------------------------
echo [OK] Kurulum tamamlandi!
echo.
echo [Kullanim Ornekleri]
echo   python desemap.py https://testphp.vulnweb.com
echo   python desemap.py https://site.com --depth 2 --format all
echo.
echo [Not]
echo Programi calistirmadan once:
echo   call .venv\Scripts\activate
echo yazmayi unutma!
echo ---------------------------------------------
pause
