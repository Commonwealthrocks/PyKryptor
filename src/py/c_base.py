## c_base.py
## last updated: 21/11/2025 <d/m/y>
## p-y-k-x
import ctypes 
import os
import tempfile
import glob
import struct
import sys
from colorama import *

def get_resource_path(relative_path):
    candidates = []
    if getattr(sys, "frozen", False):
        if hasattr(sys, "_MEIPASS"):
            candidates.append(sys._MEIPASS)
        nuitka_temp = os.environ.get("NUITKA_ONEFILE_TEMP")
        if nuitka_temp:
            candidates.append(nuitka_temp)
        try:
            candidates.append(os.path.dirname(sys.executable))
        except Exception:
            pass
        try:
            candidates.append(os.path.dirname(os.path.abspath(sys.argv[0])))
        except Exception:
            pass
        try:
            candidates.append(tempfile.gettempdir())
        except Exception:
            pass
        candidates.extend([os.environ.get("TEMP"), os.environ.get("TMP")])
    candidates.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    candidates.append(os.getcwd())
    tried = []
    first_seg = relative_path.split(os.sep)[0]
    for base in candidates:
        if not base:
            continue
        candidate_path = os.path.join(base, relative_path)
        tried.append(candidate_path)
        if os.path.exists(candidate_path):
            return candidate_path
        if os.sep in relative_path:
            alt = os.path.join(base, first_seg, *relative_path.split(os.sep)[1:])
            tried.append(alt)
            if os.path.exists(alt):
                return alt
    try:
        tempdir = tempfile.gettempdir()
        pattern = os.path.join(tempdir, "**", first_seg)
        for match in glob.glob(pattern, recursive=True):
            if os.path.isdir(match):
                candidate = os.path.join(match, *relative_path.split(os.sep)[1:]) if os.sep in relative_path else os.path.join(match, relative_path)
                tried.append(candidate)
                if os.path.exists(candidate):
                    return candidate
    except Exception:
        pass
    raise FileNotFoundError("Resource not found: {!r}. Tried:\n{}".format(relative_path, "\n".join(tried)))

_secure_mem_lib = None
secure_mem_lib_name = None
secure_mem_lib_dir = None
if sys.platform == "win32":
    secure_mem_lib_name = "secure_mem.dll"
    secure_mem_lib_dir = "win32"
elif sys.platform.startswith("linux"):
    secure_mem_lib_name = "secure_mem.so"
    secure_mem_lib_dir = "penguin"
if secure_mem_lib_dir and secure_mem_lib_name:
    try:
        project_relative_path = os.path.join("c", secure_mem_lib_dir, secure_mem_lib_name)
        lib_path = get_resource_path(project_relative_path)
        _secure_mem_lib = ctypes.CDLL(lib_path)
        _secure_mem_lib.zero_memory.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _secure_mem_lib.zero_memory.restype = None
        print(Fore.GREEN + f"[DEV PRINT] Loaded secure memory library '{secure_mem_lib_name}'; zero'd" + Style.RESET_ALL)
    except (OSError, AttributeError) as e:
        _secure_mem_lib = None
        print(Fore.RED + f"[DEV PRINT] Could not load secure memory library '{secure_mem_lib_name}'.\n\ne: {e}")
        print("[DEV PRINT] Secure password clearing will be disabled." + Style.RESET_ALL)
_aes_ni_lib = None
aes_ni_lib_name = None
aes_ni_lib_dir = None
if sys.platform == "win32":
    aes_ni_lib_name = "chc_aes_ni.dll"
    aes_ni_lib_dir = "win32"
elif sys.platform.startswith("linux"):
    aes_ni_lib_name = "chc_aes_ni.so"
    aes_ni_lib_dir = "penguin"
if aes_ni_lib_dir and aes_ni_lib_name:
    try:
        project_relative_path = os.path.join("c", aes_ni_lib_dir, aes_ni_lib_name)
        lib_path = get_resource_path(project_relative_path)
        _aes_ni_lib = ctypes.CDLL(lib_path)
        _aes_ni_lib.has_aes_ni.argtypes = []
        _aes_ni_lib.has_aes_ni.restype = ctypes.c_int
        print(Fore.GREEN + f"[DEV PRINT] Loaded AES-NI check library '{aes_ni_lib_name}'" + Style.RESET_ALL)
    except (OSError, AttributeError) as e:
        _aes_ni_lib = None
        print(Fore.RED + f"[DEV PRINT] Could not load AES-NI check library '{aes_ni_lib_name}'.\n\ne: {e}")
        print("[DEV PRINT] AES-NI check will be disabled." + Style.RESET_ALL)

def clear_buffer(buffer):
    try:
        is_ctypes_array = isinstance(buffer, ctypes.Array) and getattr(buffer, "_type_", None) is ctypes.c_char
    except Exception:
        is_ctypes_array = False

    if is_ctypes_array:
        if _secure_mem_lib:
            buf_ptr = ctypes.cast(buffer, ctypes.c_void_p)
            _secure_mem_lib.zero_memory(buf_ptr, len(buffer))
        else:
            try:
                cleared = (b"\x00" * len(buffer))
                mv = memoryview(buffer)
                mv[:] = cleared
            except Exception:
                try:
                    for i in range(len(buffer)):
                        buffer[i] = b"\x00"
                except Exception:
                    pass
    else:
        if isinstance(buffer, bytearray):
            for i in range(len(buffer)):
                buffer[i] = 0
        elif isinstance(buffer, memoryview) and buffer.readonly is False:
            buffer[:] = b"\x00" * len(buffer)
        else:
            raise TypeError("clear_buffer expects a writable ctypes.c_char array or bytearray / mutable memoryview; unexpected")

def isca():
    return _secure_mem_lib is not None

def check_aes_ni():
    if aes_ni_aval():
        try:
            return _aes_ni_lib.has_aes_ni() == 1 
        except Exception:
            return False
    return False

def aes_ni_aval():
    return _aes_ni_lib is not None

## end