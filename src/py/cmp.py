# cmp.py
## last updated: 21/10/2025 <d/m/y>
## p-y-k-x
import os
import sys
import zlib
import zstandard as zstd
import lzma
import threading

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
    "[L] ultrakill": {"id": COMPRESSION_LZMA_ULTRAKILL, "func": lambda d: lzma.compress(d, preset=9)},
}
DECOMPRESSION_FUNCS = {
    COMPRESSION_NONE: lambda d: d,
    COMPRESSION_ZLIB: zlib.decompress,
    COMPRESSION_ZSTD_NORMAL: lambda d: _get_zstd_decompressor().decompress(d),
    COMPRESSION_ZSTD_BEST: lambda d: _get_zstd_decompressor().decompress(d),
    COMPRESSION_LZMA_ULTRAKILL: lzma.decompress,
}
SKIP_COMPRESSION_EXTS = {
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".lzma", ".jar", ".apk", ".whl",
    ".flac", ".ogg", ".mp3", ".aac", ".opus", ".wma",
    ".mp4", ".mkv", ".avi", ".mov", ".webm",
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".exe", ".dll", ".so", ".dylib",
    ".iso", ".img", ".dmg",
    ".dat"}

def should_skip_compression(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if not ext:
        return False
    return ext in SKIP_COMPRESSION_EXTS

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