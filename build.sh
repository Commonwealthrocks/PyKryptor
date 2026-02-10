#!/bin/bash
## build.sh
## last updated: 10/02/2026 <d/m/y>
## p-y-k-x
if [ "$1" == "clean" ]; then
    echo "Purging all build artifacts..."
    rm -rf gui.dist gui.build gui.onefile-build gui.bin gui
    echo "[CLEAN] Cleaned."
    exit 0
fi

if [ "$1" == "quick" ]; then
    QUICK_MODE=1
fi

if [ "$1" == "rebuild" ]; then
    echo "Purging all build artifacts..."
    rm -rf gui.dist gui.build gui.onefile-build gui.bin gui
    echo "[CLEAN] Cleaned."
    echo ""
fi
OS_TYPE="linux"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    OS_TYPE="win32"
fi

echo "------------------------------------------------------------"
echo "  PyKryptor build automation ($OS_TYPE)"
echo "  You may not question my methods."
echo "------------------------------------------------------------"
echo ""

if ! command -v nuitka &> /dev/null; then
    echo "[ERROR] Nuitka not found; please install it first."
    exit 1
fi

if ! command -v gcc &> /dev/null; then
    echo "[WARNING] GCC not found. C library compilation will be skipped."
    GCC_AVAILABLE=0
else
    GCC_AVAILABLE=1
fi

if [ "$QUICK_MODE" == "1" ]; then
    echo "Quick build mode (no questions asked)..."
    COMP_C=1
    BUILD_TYPE=1
    JOBS=6
    CLEAN_BUILD=1
else
    echo "You will be asked a series of questions / preferences."
    echo "Type 1 for \"yeah\" or 0 for \"fuh nah\"; starting now."
    echo ""
    echo "------------------------------------------------------------"

    if [ "$GCC_AVAILABLE" == "0" ]; then
        COMP_C=0
    else
        while true; do
            read -p "Compile C libraries? (chc_cmp, secure_mem) >> " COMP_C
            if [ "$COMP_C" == "0" ] || [ "$COMP_C" == "1" ]; then
                echo "OK."
                echo ""
                break
            fi
            echo "Invalid input. Enter 1 or 0."
        done
    fi
    while true; do
        read -p "Build as onefile executable? >> " BUILD_TYPE
        if [ "$BUILD_TYPE" == "0" ] || [ "$BUILD_TYPE" == "1" ]; then
            echo "Noted."
            echo ""
            break
        fi
        echo "Invalid input. Enter 1 or 0."
    done
    read -p "Number of parallel jobs? [default=6] >> " JOBS
    if [ -z "$JOBS" ]; then
        JOBS=6
    fi
    echo "Understood."
    echo ""
    while true; do
        read -p "Clean build directory first? >> " CLEAN_BUILD
        if [ "$CLEAN_BUILD" == "0" ] || [ "$CLEAN_BUILD" == "1" ]; then
            echo "Acknowledged."
            echo ""
            break
        fi
        echo "Invalid input. Enter 1 or 0."
    done
    
    echo "------------------------------------------------------------"
    echo "Processing your choices..."
fi

echo ""

if [ "$COMP_C" == "1" ]; then
    echo "[CONFIG] C libraries: compiling..."
    
    if [ "$OS_TYPE" == "win32" ]; then
        mkdir -p src/c/win32
        echo "[CC] chc_cmp.c"
        gcc -shared -o src/c/win32/chc_cmp.dll src/c/chc_cmp.c -O2 -Wall -fvisibility=hidden -fno-strict-aliasing -fno-lto -static-libgcc -static-libstdc++ 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "[ERROR] Compilation failed for chc_cmp.c."
            exit 1
        fi
        
        echo "[CC] secure_mem.c"
        gcc -shared -o src/c/win32/secure_mem.dll src/c/secure_mem.c -O2 -Wall -static-libgcc -static-libstdc++ -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "[ERROR] Compilation failed for secure_mem.c."
            exit 1
        fi
    else
        mkdir -p src/c/penguin
        echo "[CC] chc_cmp.c"
        gcc -shared -fPIC -o src/c/penguin/chc_cmp.so src/c/chc_cmp.c -O2 -Wall -fvisibility=hidden -fno-strict-aliasing -fno-lto -lm 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "[ERROR] Compilation failed for chc_cmp.c."
            exit 1
        fi
        
        echo "[CC] secure_mem.c"
        gcc -shared -fPIC -o src/c/penguin/secure_mem.so src/c/secure_mem.c -O2 -Wall 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "[ERROR] Compilation failed for secure_mem.c."
            exit 1
        fi
    fi
    
    echo "[CC] C libraries compiled successfully."
else
    echo "[CONFIG] C libraries: using existing."
fi

if [ "$BUILD_TYPE" == "1" ]; then
    N_TYPE="--onefile"
    echo "[CONFIG] Build mode: onefile (portable executable)."
else
    N_TYPE="--standalone"
    echo "[CONFIG] Build mode: standalone (folder)."
fi

echo "[CONFIG] Jobs: $JOBS."
echo ""

if [ "$CLEAN_BUILD" == "1" ]; then
    echo "[CLEAN] Removing old artifacts..."
    rm -rf gui.dist gui.build gui.onefile-build gui.bin gui
    echo "[CLEAN] Build directory cleaned."
fi

echo ""
echo "------------------------------------------------------------"
echo "Starting Nuitka build..."
echo "------------------------------------------------------------"

COMMON_FLAGS="--jobs=$JOBS \
--assume-yes-for-downloads \
--enable-plugin=pyside6 \
--include-data-dir=src/img=img \
--include-data-dir=src/txts=txts \
--include-data-dir=src/sfx=sfx \
--include-data-files=src/sfx/*.wav=sfx/ \
--nofollow-import-to=*.tests \
--nofollow-import-to=*.test"
if [ "$OS_TYPE" == "win32" ]; then
    nuitka $N_TYPE $COMMON_FLAGS \
    --mingw64 \
    --windows-console-mode=disable \
    --windows-icon-from-ico=src/img/pykryptor_icon.png \
    --include-data-files=src/c/win32/*.dll=c/win32/ \
    --include-data-files=src/c/penguin/*.so=c/penguin/ \
    src/py/gui.py
else
    nuitka $N_TYPE $COMMON_FLAGS \
    --include-data-files=src/c/penguin/*.so=c/penguin/ \
    --include-data-files=src/c/win32/*.dll=c/win32/ \
    src/py/gui.py
fi

if [ $? -ne 0 ]; then
    echo ""
    echo "[ERROR] Nuitka build failed."
    exit 1
fi

echo ""
echo "------------------------------------------------------------"
echo "  Finished compiling..."
echo "------------------------------------------------------------"
if [ "$BUILD_TYPE" == "1" ]; then
    if [ "$OS_TYPE" == "win32" ]; then
        OUTPUT="gui.exe"
    else
        OUTPUT="gui.bin"
    fi
    echo "  Output: $OUTPUT"
    if [ -f "$OUTPUT" ]; then
        SIZE=$(stat -f%z "$OUTPUT" 2>/dev/null || stat -c%s "$OUTPUT" 2>/dev/null)
        echo "  Size: $SIZE bytes"
    fi
else
    echo "  Output: gui.dist/"
fi
echo "------------------------------------------------------------"

## end