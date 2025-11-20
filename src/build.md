# **Build file for PyKryptor - v1.5**
If you want to manually compile **PyKryptor** (or you just are using **Linux**), this file here is for you!!

## **Basic requirements**

### **Python**
To compile **PyKryptor** with **Nuitka** you will need either **Python** `3.12` or `3.13` depending on your OS and compiler.

If you are using **GCC** / **MinGW64** as your general **C** compiler; use **Python** `3.12`, same case scenario if you use **Linux**.

If you are using **MSVC** (**Windows** only) as your general **C** compiler; you can use `3.13` or any version that is supported with **Nuitka** and dependencies.

#### [**Python 3.12 download page**](https://www.python.org/downloads/release/python-3120/)

#### [**Python 3.13 download page**](https://www.python.org/downloads/release/python-3130/)

## **Install dependencies**

### **pip + Python in PATH**
When doing this bit you need to ensure that both **Python** and **pip** are in your systems PATH.

Once you verify that, you may run the following command...

```bash
pip install numpy cryptography argon2-cffi colorama pyside6 pygame reedsolo zstandard pyzstd zxcvbn
```
If everything is correct you should get zero errors unless your **pip** is not bootstrapped.

## **Compilers**
Briefly mentioned this but we shall go over it once more quickly.

### **GCC**
**GCC** works both on **Windows** and **Linux**; when using **Nuitka** it will install a specific version of **GCC** so there isn't any real need to download the normal compiler unless you use it too.

### **MSVC**
**MSVC** is a **Windows** only compiler made by **Microsoft**. If you wish to use this you are free to do so, keep in mind you will need **Visual Studio** installed too for it to be detected by **Nuitka**.

## **C files**
**PyKryptor** uses **C** too! These files come precompiled but if for some reason they aren't you may use **GCC** and **GCC** only to compile them yourself.

### Windows (win32)
```bash
gcc -shared -o win32/chc_aes_ni.dll c/chc_aes_ni.c -O2 -Wall -fvisibility=hidden -fno-strict-aliasing -fno-lto -static-libgcc -static-libstdc++
```
```bash
gcc -shared -o win32/secure_mem.dll c/secure_mem.c -O2 -Wall -fvisibility=hidden -fno-strict-aliasing -fno-lto -static-libgcc -static-libstdc++
```

Both of the files are needed to be compiled and this will work as long as you have `gcc.exe` in your systems PATH or use something like **UCRT64** that relies on `gcc.exe`.

### Linux (penguin)
```bash
gcc -shared -fPIC -o penguin/chc_aes_ni.so c/chc_aes_ni.c -O2 -Wall -fvisibility=hidden -fno-strict-aliasing -fno-lto
```
```bash
gcc -shared -fPIC -o penguin/secure_mem.so c/secure_mem.c -O2 -Wall -fvisibility=hidden -fno-strict-aliasing -fno-lto
```

Same case here; needs `gcc.exe` in PATH or use something like **MinGW64**.

Depending on your OS the compile commands will place `.dll` / `.so` files where needed. These commands can be ran anywhere that is a CLI environment; **CMD**, **PowerShell**, **Terminal**, **UCRT64** and so on...

You may run these commands in the same root directory; aka where **THIS** file you are reading lives.

## **Compiling the actual app**
Now for this it will again depend on your OS but I'll give a quick run down of the command, all of the commands are *one-liners* so they should work in about any CLI environment!

### **GCC (Windows)**
```bash
nuitka --standalone --jobs=6 --windows-icon-from-ico=pykryptor_icon.ico --mingw64 --windows-console-mode=disable --onefile --enable-plugin=pyside6 --include-data-dir=txts=txts --include-data-dir=sfx=sfx --include-data-dir=img=img --include-data-files=c/win32/secure_mem.dll=c/win32/secure_mem.dll --include-data-files=c/win32/chc_aes_ni.dll=c/win32/chc_aes_ni.dll --include-data-files=c/penguin/secure_mem.so=c/penguin/secure_mem.so --include-data-files=c/penguin/chc_aes_ni.so=c/penguin/chc_aes_ni.so py/gui.py
```
This here will use **GCC** to turn our **Python** based app into a `.exe` file for **Windows**.

### **MSVC (Windows)**
```bash
nuitka --standalone --jobs=6 --windows-icon-from-ico=pykryptor_icon.ico --windows-console-mode=disable --onefile --enable-plugin=pyside6 --include-data-dir=txts=txts --include-data-dir=sfx=sfx --include-data-dir=img=img --include-data-files=c/win32/secure_mem.dll=c/win32/secure_mem.dll --include-data-files=c/win32/chc_aes_ni.dll=c/win32/chc_aes_ni.dll --include-data-files=c/penguin/secure_mem.so=c/penguin/secure_mem.so --include-data-files=c/penguin/chc_aes_ni.so=c/penguin/chc_aes_ni.so py/gui.py
```
Same idea as **GCC** but for **MSVC** to be used instead we remove the `--mingw64` flag in the compile command.

### **GCC (Linux)**
```bash
nuitka --standalone --jobs=6 --onefile --enable-plugin=pyside6 --include-data-dir=txts=txts --include-data-dir=sfx=sfx --include-data-dir=img=img --include-data-files=c/penguin/secure_mem.so=c/penguin/secure_mem.so --include-data-files=c/penguin/chc_aes_ni.so=c/penguin/chc_aes_ni.so py/gui.py
```
This compile command is only for **Linux** and will compile the Python code to `ELF` based file for running.

In the end the following product will be `gui.exe` / `gui` which you can rename to about anything example `PyKryptor.exe` / `PyKryptor`; for all I care...

It is also recommended to turn off your **Windows Defender** if you are doing this on **Windows** since that will save you a headache or two...

## End of `build.md`