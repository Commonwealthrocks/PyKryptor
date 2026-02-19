## c_base.py
## last updated: 19/02/2025 <d/m/y>
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
        try:
            this_file = os.path.abspath(__file__)
            first_seg = relative_path.split(os.sep)[0]
            search = os.path.dirname(this_file)
            for _ in range(5):  ## max 5 levels up
                if os.path.exists(os.path.join(search, first_seg)):
                    candidates.insert(0, search)
                    break
                parent = os.path.dirname(search)
                if parent == search:
                    break
                search = parent
        except Exception:
            pass
        nuitka_temp = os.environ.get("NUITKA_ONEFILE_TEMP")
        if nuitka_temp:
            candidates.append(nuitka_temp)
        try:
            candidates.append(os.path.dirname(os.path.abspath(sys.executable)))
        except Exception:
            pass
        try:
            candidates.append(os.path.dirname(os.path.abspath(sys.argv[0])))
        except Exception:
            pass
    try:
        candidates.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    except Exception:
        pass
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
            target = os.path.join(match, *relative_path.split(os.sep)[1:]) if os.sep in relative_path else match
            tried.append(target)
            if os.path.exists(target):
                return target
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
        print(Fore.RED + f"[DEV PRINT] Could not load secure memory library '{secure_mem_lib_name}'.\n\ne: {e}\n")
        print("[DEV PRINT] Secure password clearing will be disabled." + Style.RESET_ALL)
_aes_ni_support = None

def _detect_aes_ni():
    global _aes_ni_support
    if _aes_ni_support is not None:
        return _aes_ni_support
    try:
        import cpuinfo
        cpu_flags = cpuinfo.get_cpu_info().get("flags", [])
        _aes_ni_support = "aes" in cpu_flags
        return _aes_ni_support
    except ImportError:
        pass
    try:
        if sys.platform == "win32":
            import platform
            if platform.machine().endswith("64"):
                class CPUID_RESULT(ctypes.Structure):
                    _fields_ = [("eax", ctypes.c_uint32), ("ebx", ctypes.c_uint32), ("ecx", ctypes.c_uint32), ("edx", ctypes.c_uint32)]
                _aes_ni_support = True
            else:
                _aes_ni_support = False
        elif sys.platform.startswith("linux"):
            try:
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo_content = f.read().lower()
                    _aes_ni_support = "aes" in cpuinfo_content ## i sometimes consider switching to linux...
            except Exception:
                _aes_ni_support = False
        else:
            _aes_ni_support = False
        print(Fore.GREEN + f"[DEV PRINT] AES-NI detection via system: {_aes_ni_support}" + Style.RESET_ALL)
        return _aes_ni_support
    except Exception as e:
        print(Fore.YELLOW + f"[DEV PRINT] AES-NI detection failed.\n\ne: {e}\n" + Style.RESET_ALL)
        _aes_ni_support = False
        return False
_cmp_check_lib = None
cmp_check_lib_name = None
cmp_check_lib_dir = None

if sys.platform == "win32":
    cmp_check_lib_name = "chc_cmp.dll"
    cmp_check_lib_dir = "win32"
elif sys.platform.startswith("linux"):
    cmp_check_lib_name = "chc_cmp.so"
    cmp_check_lib_dir = "penguin"

if cmp_check_lib_dir and cmp_check_lib_name:
    try:
        project_relative_path = os.path.join("c", cmp_check_lib_dir, cmp_check_lib_name)
        lib_path = get_resource_path(project_relative_path)
        _cmp_check_lib = ctypes.CDLL(lib_path)
        _cmp_check_lib.should_skip_compression.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_double]
        _cmp_check_lib.should_skip_compression.restype = ctypes.c_int
        print(Fore.GREEN + f"[DEV PRINT] Loaded compression check library '{cmp_check_lib_name}'" + Style.RESET_ALL)
    except (OSError, AttributeError, FileNotFoundError) as e:
        _cmp_check_lib = None
        print(Fore.YELLOW + f"[DEV PRINT] Could not load compression check library '{cmp_check_lib_name}'.\n\ne: {e}\n")
        print("[DEV PRINT] Compression check will use fallback method." + Style.RESET_ALL)

def cmp_check_available():
    return _cmp_check_lib is not None

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
            raise TypeError("clear_buffer expects a writable ctypes.c_char array or bytearray / mutable memoryview; unexpected.")

def isca():
    return _secure_mem_lib is not None

def check_aes_ni():
    return _detect_aes_ni()

def aes_ni_aval():
    return True

## end