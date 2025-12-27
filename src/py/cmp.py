# cmp.py
## last updated: 21/12/2025 <d/m/y>
## p-y-k-x
import os
import sys
import zlib
import zstandard as zstd
import lzma
import threading
import ctypes
from colorama import Fore, Style

COMPRESSION_NONE = 0
COMPRESSION_ZLIB = 1
COMPRESSION_ZSTD_NORMAL = 2
COMPRESSION_ZSTD_BEST = 3
COMPRESSION_LZMA_ULTRAKILL = 4
_thread_local = threading.local()

def _get_zstd_compressor_normal():
    if not hasattr(_thread_local, "zstd_normal"):
        _thread_local.zstd_normal = zstd.ZstdCompressor(level=3)
    return _thread_local.zstd_normal

def _get_zstd_compressor_best():
    if not hasattr(_thread_local, "zstd_best"):
        _thread_local.zstd_best = zstd.ZstdCompressor(level=22)
    return _thread_local.zstd_best

def _get_zstd_decompressor():
    if not hasattr(_thread_local, "zstd_decomp"):
        _thread_local.zstd_decomp = zstd.ZstdDecompressor()
    return _thread_local.zstd_decomp

COMPRESSION_MODES = {
    "none": {"id": COMPRESSION_NONE},
    "normal": {"id": COMPRESSION_ZLIB, "func": zlib.compress},
    "best": {"id": COMPRESSION_ZSTD_NORMAL, "func": lambda d: _get_zstd_compressor_normal().compress(d)},
    "ultrakill": {"id": COMPRESSION_ZSTD_BEST, "func": lambda d: _get_zstd_compressor_best().compress(d)},
    "[L] ultrakill": {"id": COMPRESSION_LZMA_ULTRAKILL, "func": lambda d: lzma.compress(d, preset=9)},}

DECOMPRESSION_FUNCS = {
    COMPRESSION_NONE: lambda d: d,
    COMPRESSION_ZLIB: zlib.decompress,
    COMPRESSION_ZSTD_NORMAL: lambda d: _get_zstd_decompressor().decompress(d),
    COMPRESSION_ZSTD_BEST: lambda d: _get_zstd_decompressor().decompress(d),
    COMPRESSION_LZMA_ULTRAKILL: lzma.decompress,}

def get_resource_path(relative_path):
    import tempfile
    import glob
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
        _cmp_check_lib.check_extension.argtypes = [ctypes.c_char_p]
        _cmp_check_lib.check_extension.restype = ctypes.c_int
        _cmp_check_lib.check_magic_bytes.argtypes = [ctypes.c_char_p]
        _cmp_check_lib.check_magic_bytes.restype = ctypes.c_int
        _cmp_check_lib.check_entropy.argtypes = [ctypes.c_char_p, ctypes.c_double]
        _cmp_check_lib.check_entropy.restype = ctypes.c_int
        print(Fore.GREEN + f"[DEV PRINT] Loaded compression check library '{cmp_check_lib_name}'" + Style.RESET_ALL)
    except (OSError, AttributeError) as e:
        _cmp_check_lib = None
        print(Fore.RED + f"[DEV PRINT] Could not load compression check library '{cmp_check_lib_name}'.\n\ne: {e}")
        print("[DEV PRINT] Falling back to Python extension checking." + Style.RESET_ALL)
SKIP_COMPRESSION_EXTS = {
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".lzma", ".jar", ".apk", ".whl",
    ".flac", ".ogg", ".mp3", ".aac", ".opus", ".wma",
    ".mp4", ".mkv", ".avi", ".mov", ".webm",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp",
    ".exe", ".dll", ".so", ".dylib",
    ".iso", ".img", ".dmg",
    ".dat", ".pdf", ".cab"}

def _should_skip_compression_fallback(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if not ext:
        return False
    return ext in SKIP_COMPRESSION_EXTS

def should_skip_compression(file_path, detection_mode="legacy", entropy_threshold=7.5):
    if not os.path.exists(file_path):
        return False
    if _cmp_check_lib is not None:
        mode_map = {
            "legacy": 0,
            "magic": 1,
            "entropy": 2,
            "magic+entropy": 3}
        mode = mode_map.get(detection_mode, 0)
        try:
            file_path_bytes = file_path.encode("utf-8")
            result = _cmp_check_lib.should_skip_compression(file_path_bytes, mode, ctypes.c_double(entropy_threshold))
            return result == 1
        except Exception as e:
            print(Fore.YELLOW + f"[DEV PRINT] C library call failed, using fallback: {e}")
            print("[>>>] This function is not located in c_base.py since it will become needed for future PyKryptor versions now." + Style.RESET_ALL)
            return _should_skip_compression_fallback(file_path)
    else:
        return _should_skip_compression_fallback(file_path)

def compress_chunk(data, level="none"):
    if level not in COMPRESSION_MODES:
        raise ValueError(f"Unknown compression level: {level}")    
    mode = COMPRESSION_MODES[level]
    compression_id = mode["id"]    
    if compression_id == COMPRESSION_NONE:
        return data, compression_id        
    compressed_data = mode["func"](data)
    if len(compressed_data) >= len(data):
        return data, COMPRESSION_NONE
    return compressed_data, compression_id

def decompress_chunk(data, compression_id):
    if compression_id not in DECOMPRESSION_FUNCS:
        raise ValueError(f"Unknown compression ID: {compression_id}")
    return DECOMPRESSION_FUNCS[compression_id](data)

def cmp_check_available():
    return _cmp_check_lib is not None

## end