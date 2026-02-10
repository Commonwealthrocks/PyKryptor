:: build.bat
:: last updated: 10/02/2026 <d/m/y>
:: p-y-k-x
@echo off
setlocal enabledelayedexpansion
if "%1"=="clean" goto :clean
if "%1"=="quick" goto :quick
if "%1"=="rebuild" (
    call :clean
    goto :interactive
)

:interactive
echo ------------------------------------------------------------
echo   PyKryptor build automation (Windows)
echo   You may not question my methods.
echo ------------------------------------------------------------
echo.

where nuitka >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Nuitka not found in PATH. Please install it first.
    exit /b 1
)

where gcc >nul 2>nul
if %errorlevel% neq 0 (
    echo [WARNING] GCC not found. C library compilation will be skipped.
    set GCC_AVAILABLE=0
) else (
    set GCC_AVAILABLE=1
)

echo You will be asked a series of questions / preferences.
echo Type 1 for "yeah" or 0 for "fuh nah"; starting now.
echo.
echo ------------------------------------------------------------

:ask_compile_c
if "%GCC_AVAILABLE%"=="0" (
    set COMP_C=0
    goto :ask_build_mode
)
set /p COMP_C="Compile C libraries? (chc_cmp, secure_mem) >> "
if "%COMP_C%"=="0" goto :ask_compile_c_ok
if "%COMP_C%"=="1" goto :ask_compile_c_ok
echo Invalid input. Enter 1 or 0.
goto :ask_compile_c

:ask_compile_c_ok
echo OK.
echo.

:ask_build_mode
set /p BUILD_TYPE="Build as onefile executable? >> "
if "%BUILD_TYPE%"=="0" goto :ask_build_mode_ok
if "%BUILD_TYPE%"=="1" goto :ask_build_mode_ok
echo Invalid input. Enter 1 or 0.
goto :ask_build_mode

:ask_build_mode_ok
echo Noted.
echo.

:ask_jobs
set /p JOBS="Number of parallel jobs? [default=6] >> "
if "%JOBS%"=="" set JOBS=6
echo Understood.
echo.

:ask_clean
set /p CLEAN_BUILD="Clean build directory first? >> "
if "%CLEAN_BUILD%"=="0" goto :ask_clean_ok
if "%CLEAN_BUILD%"=="1" goto :ask_clean_ok
echo Invalid input. Enter 1 or 0.
goto :ask_clean

:ask_clean_ok
echo Acknowledged.
echo.

echo ------------------------------------------------------------
echo Processing your choices...
goto :build

:quick
set COMP_C=1
set BUILD_TYPE=1
set JOBS=6
set CLEAN_BUILD=1
echo Quick build mode (no questions asked)...
goto :build

:build
echo.

if "%COMP_C%"=="1" (
    echo [CONFIG] C libraries: compiling...
    if not exist "src\c\win32" mkdir "src\c\win32"
    
    echo [CC] chc_cmp.c
    gcc -shared -o src\c\win32\chc_cmp.dll src\c\chc_cmp.c -O2 -Wall -fvisibility=hidden -fno-strict-aliasing -fno-lto -static-libgcc -static-libstdc++ 2>nul
    if errorlevel 1 (
        echo [ERROR] Compilation failed for chc_cmp.c.
        exit /b 1
    )
    
    echo [CC] secure_mem.c
    gcc -shared -o src\c\win32\secure_mem.dll src\c\secure_mem.c -O2 -Wall -static-libgcc -static-libstdc++ -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic 2>nul
    if errorlevel 1 (
        echo [ERROR] Compilation failed for secure_mem.c.
        exit /b 1
    )
    
    echo [CC] C libraries compiled successfully.
) else (
    echo [CONFIG] C libraries: using existing.
)

if "%BUILD_TYPE%"=="1" (
    set N_TYPE=--onefile
    echo [CONFIG] Build mode: onefile ^(portable .exe^).
) else (
    set N_TYPE=--standalone
    echo [CONFIG] Build mode: standalone ^(folder^).
)

echo [CONFIG] Jobs: %JOBS%.
echo.

if "%CLEAN_BUILD%"=="1" (
    echo [CLEAN] Removing old artifacts...
    if exist "gui.dist" rmdir /s /q "gui.dist"
    if exist "gui.build" rmdir /s /q "gui.build"
    if exist "gui.onefile-build" rmdir /s /q "gui.onefile-build"
    if exist "gui.exe" del "gui.exe"
    if exist "gui.cmd" del "gui.cmd"
    echo [CLEAN] Build directory cleaned.
)

echo.
echo ------------------------------------------------------------
echo Starting Nuitka build...
echo ------------------------------------------------------------

nuitka %N_TYPE% ^
    --jobs=%JOBS% ^
    --mingw64 ^
    --assume-yes-for-downloads ^
    --windows-console-mode=disable ^
    --windows-icon-from-ico=src/img/pykryptor_icon.png ^
    --enable-plugin=pyside6 ^
    --include-data-dir=src/img=img ^
    --include-data-dir=src/txts=txts ^
    --include-data-dir=src/sfx=sfx ^
    --include-data-files=src/sfx/*.wav=sfx/ ^
    --include-data-files=src/c/win32/*.dll=c/win32/ ^
    --include-data-files=src/c/penguin/*.so=c/penguin/ ^
    --nofollow-import-to=*.tests ^
    --nofollow-import-to=*.test ^
    src/py/gui.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Nuitka build failed.
    exit /b 1
)

echo.
echo ------------------------------------------------------------
echo   Finished compiling.
echo ------------------------------------------------------------
if "%BUILD_TYPE%"=="1" (
    echo   Output: gui.exe
    for %%A in (gui.exe) do echo   Size: %%~zA bytes
) else (
    echo   Output: gui.dist\
)
echo ------------------------------------------------------------
exit /b 0

:clean
echo Purging all build artifacts...
if exist "gui.dist" rmdir /s /q "gui.dist"
if exist "gui.build" rmdir /s /q "gui.build"
if exist "gui.onefile-build" rmdir /s /q "gui.onefile-build"
if exist "gui.exe" del "gui.exe"
if exist "gui.cmd" del "gui.cmd"
echo [CLEAN] Cleaned.
exit /b 0

:: end