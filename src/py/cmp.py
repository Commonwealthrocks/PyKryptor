# cmp.py
## last updated: 10/02/2026 <d/m/y>
## p-y-k-x
import os
import sys
import zlib
import zstandard as zstd
import lzma
import threading
import ctypes
from colorama import Fore, Style
from c_base import _cmp_check_lib, cmp_check_available

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
    if detection_mode == "none":
        return False

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

## end