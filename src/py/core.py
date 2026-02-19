## core.py
## last updated: 18/02/2026 <d/m/y>
## p-y-k-x
import os
import io
import gc
import stat as _stat
import struct
import ctypes
import hashlib
import reedsolo
import mmap
import base64
import tempfile
import threading
from PySide6.QtCore import QThread
from PySide6.QtCore import Signal as pyqtSignal
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from multiprocessing import Pool, cpu_count
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, HashingError
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

from c_base import clear_buffer
from cmp import compress_chunk, decompress_chunk, should_skip_compression, COMPRESSION_NONE, COMPRESSION_MODES
from usb_codec import KEYFILE_SIZE

_PAGE_SIZE = mmap.PAGESIZE
_BATCH_PROGRESS_INTERVAL = 50 ## "think like a C++ dev" no i hate you
_GC_CHUNK_INTERVAL = 64

def _madvise_sequential(mm):
    try:
        mm.madvise(mmap.MADV_SEQUENTIAL)  ## type: ignore[attr-defined]
    except AttributeError:
        pass

CHUNK_SIZE = 3 * 1024 * 1024
FORMAT_VERSION = 10
ALGORITHM_ID_AES_GCM = 1
ALGORITHM_ID_CHACHA = 2
KDF_ID_PBKDF2 = 1
KDF_ID_ARGON2 = 2
HASH_ID_SHA256 = 1
HASH_ID_SHA512 = 2
SALT_SIZE = 16
NONCE_SIZE = 12
MAGIC_NUMBER = b"PYKX\x00"
MAGIC_NUMBER_LEGACY = b"PYLI\x00"
MAX_EXT_LEN = 256
TAG_SIZE = 16
ECC_BYTES = 32
MAX_ARCHIVE_FILES = 10_000_000
FLAG_RECOVERY_DATA = 0x01
FLAG_ARCHIVE_MODE = 0x02
FLAG_USB_KEY = 0x04
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4

def compress_chunk_threaded(chunk_data, compression_level):
    return compress_chunk(chunk_data, compression_level)

def create_archive(file_paths, progress_callback=None):
    if progress_callback:
        progress_callback(0.0)
    common_base = os.path.commonpath(file_paths) if len(file_paths) > 1 else os.path.dirname(file_paths[0])
    n_paths = len(file_paths)
    file_info = []
    total_size = 0
    header_entries = bytearray()
    for idx, file_path in enumerate(file_paths):
        try:
            st = os.stat(file_path)
        except OSError:
            continue
        if not _stat.S_ISREG(st.st_mode):
            continue
        size = st.st_size
        rel_path = os.path.relpath(file_path, common_base)
        rel_path_bytes = rel_path.encode("utf-8")
        file_info.append((file_path, rel_path, size))
        total_size += size
        header_entries.extend(struct.pack("!I", len(rel_path_bytes)))
        header_entries.extend(rel_path_bytes)
        header_entries.extend(struct.pack("!Q", size))
        if progress_callback and (idx % _BATCH_PROGRESS_INTERVAL == 0):
            progress_callback(min(49.9, (idx / max(1, n_paths)) * 50.0))
    if not file_info:
        raise ValueError("No valid files found to archive.")
    archive_header = bytearray()
    archive_header.extend(struct.pack("!I", len(file_info)))
    archive_header.extend(header_entries)
    if progress_callback:
        progress_callback(50.0)
    return bytes(archive_header), file_info, total_size

def extract_archive(archive_data, output_dir, progress_callback=None):
    offset = 0
    if len(archive_data) < 4:
        raise ValueError("Invalid archive: too short")
    num_files = struct.unpack("!I", archive_data[offset:offset+4])[0]
    offset += 4
    if num_files > MAX_ARCHIVE_FILES:
        raise ValueError(f"Invalid archive: file count {num_files} exceeds limit {MAX_ARCHIVE_FILES}")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    files_info = []
    for i in range(num_files):
        if offset + 4 > len(archive_data):
            raise ValueError(f"Invalid archive: unexpected end while reading path length for file {i}")
        path_len = struct.unpack("!I", archive_data[offset:offset+4])[0]
        offset += 4
        if path_len == 0 or path_len > (1024 * 4):
            raise ValueError(f"Invalid archive: invalid path length {path_len} for file {i}")
        if offset + path_len > len(archive_data):
            raise ValueError(f"Invalid archive: unexpected end while reading path for file {i}")
        rel_path = archive_data[offset:offset+path_len].decode("utf-8")
        offset += path_len
        if offset + 8 > len(archive_data):
            raise ValueError(f"Invalid archive: unexpected end while reading file size for file {i}")
        file_size = struct.unpack("!Q", archive_data[offset:offset+8])[0]
        offset += 8
        files_info.append((rel_path, file_size))
    data_offset = offset
    total_size = len(archive_data)
    safe_output_dir = os.path.realpath(output_dir)
    for rel_path, file_size in files_info:
        if progress_callback:
            progress_callback((data_offset / total_size) * 100)
        if data_offset + file_size > len(archive_data):
            raise ValueError(f"Invalid archive: unexpected end while reading file data for {rel_path}")
        file_data = archive_data[data_offset:data_offset+file_size]
        data_offset += file_size
        output_path_joined = os.path.join(safe_output_dir, rel_path)
        output_path = os.path.realpath(output_path_joined)
        if not output_path.startswith(safe_output_dir):
            raise ValueError(f"Invalid archive: path traversal attempt in {rel_path}")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(file_data)
    if progress_callback:
        progress_callback(100.0)

def extract_archive_streaming(source_path, output_dir, progress_callback=None):
    safe_output_dir = os.path.realpath(output_dir)
    if not os.path.exists(safe_output_dir):
        os.makedirs(safe_output_dir)

    total_size = os.path.getsize(source_path)

    with open(source_path, "rb") as src:
        raw = src.read(4)
        if len(raw) < 4:
            raise ValueError("Invalid archive: too short")
        num_files = struct.unpack("!I", raw)[0]
        if num_files > MAX_ARCHIVE_FILES:
            raise ValueError(f"Invalid archive: file count {num_files} exceeds limit {MAX_ARCHIVE_FILES} (how do you even reach this)?")
        files_info = []
        for i in range(num_files):
            raw = src.read(4)
            if len(raw) < 4:
                raise ValueError(f"Invalid archive: unexpected end reading path length for file {i}")
            path_len = struct.unpack("!I", raw)[0]
            if path_len == 0 or path_len > (1024 * 4):
                raise ValueError(f"Invalid archive: invalid path length {path_len} for file {i}")
            raw = src.read(path_len)
            if len(raw) != path_len:
                raise ValueError(f"Invalid archive: unexpected end reading path for file {i}")
            rel_path = raw.decode("utf-8")
            raw = src.read(8)
            if len(raw) < 8:
                raise ValueError(f"Invalid archive: unexpected end reading file size for file {i}")
            file_size = struct.unpack("!Q", raw)[0]
            files_info.append((rel_path, file_size))
        bytes_read = src.tell()
        for rel_path, file_size in files_info:
            if progress_callback:
                progress_callback(min(99.9, (bytes_read / max(1, total_size)) * 100))
            out_joined = os.path.join(safe_output_dir, rel_path)
            out_path = os.path.realpath(out_joined)
            if not (out_path == safe_output_dir or out_path.startswith(safe_output_dir + os.sep)):
                raise ValueError(f"Invalid archive: path traversal attempt in {rel_path}")
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            remaining = file_size
            with open(out_path, "wb") as dst:
                while remaining > 0:
                    to_read = min(CHUNK_SIZE, remaining)
                    buf = src.read(to_read)
                    if len(buf) != to_read:
                        raise ValueError(f"Invalid archive: unexpected end reading data for {rel_path}")
                    dst.write(buf)
                    remaining -= len(buf)
                    bytes_read += len(buf)
                    del buf
    if progress_callback:
        progress_callback(100.0)

class CryptoWorker:
    def __init__(self, operation, in_path, out_path, password, custom_ext=None, new_name_type=None, output_dir=None, chunk_size=CHUNK_SIZE, kdf_iterations=1000000, secure_clear=False, add_recovery_data=False, compression_level="none", archive_mode=False, use_argon2=False, argon2_time_cost=ARGON2_TIME_COST, argon2_memory_cost=ARGON2_MEMORY_COST, argon2_parallelism=ARGON2_PARALLELISM, aead_algorithm="aes-gcm", pbkdf2_hash="sha256", usb_key_path=None, keyfile_path=None, progress_callback=None, compression_detection_mode="legacy", entropy_threshold=7.5, parent=None):
        self.operation = operation
        self.in_path = in_path
        self.out_path = out_path
        self.password = password
        self.custom_ext = custom_ext
        self.new_name_type = new_name_type
        self.output_dir = output_dir
        self.chunk_size = chunk_size
        self.kdf_iterations = kdf_iterations
        self.secure_clear = secure_clear
        self.add_recovery_data = add_recovery_data
        self.compression_level = compression_level
        self.archive_mode = archive_mode
        self.use_argon2 = use_argon2 and ARGON2_AVAILABLE
        self.argon2_time_cost = argon2_time_cost
        self.argon2_memory_cost = argon2_memory_cost
        self.argon2_parallelism = argon2_parallelism
        self.aead_algorithm = aead_algorithm
        self.pbkdf2_hash = pbkdf2_hash
        self.usb_key_path = usb_key_path
        self.keyfile_path = keyfile_path
        self.progress_callback = progress_callback
        self.compression_detection_mode = compression_detection_mode
        self.entropy_threshold = entropy_threshold
        self.is_canceled = False
        self.max_workers = min(8, os.cpu_count() or 1)

    def _get_combined_password(self):
        pwd_bytes = self.password.encode("utf-8") if self.password else b""
        key_data = b""

        if self.usb_key_path:
            try:
                from usb_codec import get_usb_key
                usb_key, _ = get_usb_key(self.usb_key_path)
                key_data = usb_key
            except Exception as e:
                raise ValueError(f"Failed to read USB key: {str(e)}")
        elif self.keyfile_path:
            try:
                if not os.path.exists(self.keyfile_path):
                     raise ValueError(f"Keyfile not found: {self.keyfile_path}")
                with open(self.keyfile_path, "rb") as f:
                    key_data = f.read(KEYFILE_SIZE)
                if len(key_data) == 0:
                    raise ValueError("Keyfile is empty.")
            except Exception as e:
                raise ValueError(f"Failed to read keyfile: {str(e)}")
        if not pwd_bytes and not key_data:
            raise ValueError("No password and no keyfile provided.")
        if key_data:
            combined = hashlib.sha256(pwd_bytes + key_data).digest()
            return combined
        return pwd_bytes
    
    def _derive_key_pbkdf2(self, salt, iterations=None, hash_algorithm=None):
        if iterations is None:
            iterations = self.kdf_iterations
        if hash_algorithm is None:
            hash_algorithm = hashes.SHA256()
        pwd_data = self._get_combined_password()
        if isinstance(pwd_data, bytes):
             pass
        else:
             raise ValueError("Password derivation internal error; not bytes")
        pwd_buffer = ctypes.create_string_buffer(len(pwd_data))
        pwd_buffer.raw = pwd_data
        kdf = PBKDF2HMAC(
            algorithm=hash_algorithm,
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend())
        key = kdf.derive(pwd_buffer.value)
        if self.secure_clear:
            clear_buffer(pwd_buffer)
        return key

    def _derive_key_argon2(self, salt):
        try:
            pwd_data = self._get_combined_password()
            key = hash_secret_raw(
                secret=pwd_data,
                salt=salt,
                time_cost=self.argon2_time_cost,
                memory_cost=self.argon2_memory_cost,
                parallelism=self.argon2_parallelism,
                hash_len=32,
                type=Type.ID)
            return key
        except HashingError as e:
            raise ValueError(f"Argon2 key derivation failed: {str(e)}")

    def _derive_key(self, salt, iterations=None, kdf_type=None, pbkdf2_hash_id=None):
        if kdf_type is None:
            kdf_type = KDF_ID_ARGON2 if self.use_argon2 else KDF_ID_PBKDF2
        if kdf_type == KDF_ID_ARGON2 and ARGON2_AVAILABLE:
            return self._derive_key_argon2(salt)
        else:
            hash_algo = hashes.SHA512() if pbkdf2_hash_id == HASH_ID_SHA512 else hashes.SHA256()
            return self._derive_key_pbkdf2(salt, iterations, hash_algo)

    def encrypt_file(self):
        if not self.archive_mode or not hasattr(self, "_file_list") or len(self._file_list) <= 1:
            return self._encrypt_single_file()
        else:
            return self._encrypt_archive()

    def _encrypt_single_file(self):
        with open(self.in_path, "rb") as f:
            magic_check = f.read(len(MAGIC_NUMBER))
            if magic_check == MAGIC_NUMBER or magic_check == MAGIC_NUMBER_LEGACY:
                raise ValueError("This file appears to be already encrypted with PyKryptor. Aborting to prevent corruption.")
        effective_compression_level = self.compression_level
        if should_skip_compression(self.in_path, self.compression_detection_mode, self.entropy_threshold):
            effective_compression_level = "none"
        first_chunk = True
        final_compression_id = COMPRESSION_NONE
        salt = os.urandom(SALT_SIZE)
        if self.aead_algorithm == "chacha20-poly1305":
            aead_id = ALGORITHM_ID_CHACHA
        else:
            aead_id = ALGORITHM_ID_AES_GCM
        kdf_type = KDF_ID_ARGON2 if self.use_argon2 else KDF_ID_PBKDF2
        pbkdf2_hash_id = HASH_ID_SHA512 if self.pbkdf2_hash == "sha512" else HASH_ID_SHA256
        key = self._derive_key(salt, kdf_type=kdf_type, pbkdf2_hash_id=pbkdf2_hash_id)
        cipher = ChaCha20Poly1305(key) if aead_id == ALGORITHM_ID_CHACHA else AESGCM(key)
        original_ext = os.path.splitext(self.in_path)[1].lstrip(".").encode("utf-8")
        if len(original_ext) > MAX_EXT_LEN:
            raise ValueError(f"File extension exceeds maximum length of {MAX_EXT_LEN} bytes.")
        ext_nonce = os.urandom(NONCE_SIZE)
        encrypted_ext = cipher.encrypt(ext_nonce, original_ext, None)
        if self.new_name_type == "hash":
            hasher = hashlib.sha256()
            with open(self.in_path, "rb") as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk: break
                    hasher.update(chunk)
            out_filename = f"{hasher.hexdigest()}.{self.custom_ext}"
            self.out_path = os.path.join(os.path.dirname(self.out_path), out_filename)
        elif self.new_name_type == "base64":
            original_name = os.path.basename(self.in_path)
            base64_bytes = base64.urlsafe_b64encode(original_name.encode("utf-8"))
            base64_name = base64_bytes.decode("utf-8").rstrip("=")[:96]
            out_filename = f"{base64_name}.{self.custom_ext}"
            self.out_path = os.path.join(os.path.dirname(self.out_path), out_filename)
        else:
            self.out_path = f"{os.path.splitext(self.out_path)[0]}.{self.custom_ext}"
        if os.path.exists(self.out_path) and not os.path.samefile(self.in_path, self.out_path):
            raise IOError(f"Output file '{os.path.basename(self.out_path)}' already exists.")
        total_size = os.path.getsize(self.in_path)
        rs_codec = reedsolo.RSCodec(ECC_BYTES) if self.add_recovery_data else None
        with open(self.in_path, "rb") as infile, open(self.out_path, "wb") as outfile:
            final_compression_id_to_write = COMPRESSION_MODES.get(effective_compression_level, {"id": COMPRESSION_NONE})["id"]
            header_buffer = io.BytesIO()
            header_buffer.write(MAGIC_NUMBER)
            header_buffer.write(struct.pack("!B", FORMAT_VERSION))
            header_buffer.write(struct.pack("!B", aead_id))
            flags = FLAG_RECOVERY_DATA if self.add_recovery_data else 0
            if self.usb_key_path or self.keyfile_path:
                flags |= FLAG_USB_KEY
            header_buffer.write(struct.pack("!B", flags))
            header_buffer.write(struct.pack("!B", kdf_type))
            header_buffer.write(struct.pack("!B", final_compression_id_to_write))
            if self.add_recovery_data:
                header_buffer.write(struct.pack("!B", ECC_BYTES))
            if kdf_type == KDF_ID_ARGON2:
                header_buffer.write(struct.pack("!I", self.argon2_time_cost))
                header_buffer.write(struct.pack("!I", self.argon2_memory_cost))
                header_buffer.write(struct.pack("!I", self.argon2_parallelism))
            else:
                header_buffer.write(struct.pack("!B", pbkdf2_hash_id))
                header_buffer.write(struct.pack("!I", self.kdf_iterations))
            header_buffer.write(salt)
            header_buffer.write(ext_nonce)
            header_buffer.write(struct.pack("!I", len(encrypted_ext)))
            header_buffer.write(encrypted_ext)
            header_bytes = header_buffer.getvalue()
            outfile.write(header_bytes)
            processed_size = 0
            chunk_count = 0
            max_in_flight = self.max_workers * 2
            use_mmap = total_size > 0
            if use_mmap:
                try:
                    with mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        _madvise_sequential(mm)
                        mv = memoryview(mm)
                        if effective_compression_level != "none":
                            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                                offset = 0
                                pending_futures = []
                                while offset < total_size or pending_futures:
                                    while len(pending_futures) < max_in_flight and offset < total_size:
                                        if self.is_canceled:
                                            raise Exception("Operation canceled by user.")
                                        chunk_len = min(self.chunk_size, total_size - offset)
                                        chunk_data = bytes(mv[offset:offset + chunk_len])
                                        future = executor.submit(compress_chunk_threaded, chunk_data, effective_compression_level)
                                        pending_futures.append((future, offset, chunk_len))
                                        offset += chunk_len
                                    if pending_futures:
                                        future, chunk_offset, chunk_len = pending_futures.pop(0)
                                        compressed_chunk, compression_id = future.result()
                                        if first_chunk:
                                            final_compression_id = compression_id
                                            first_chunk = False
                                        if final_compression_id == COMPRESSION_NONE:
                                            compressed_chunk = bytes(mv[chunk_offset:chunk_offset + chunk_len])
                                        elif compression_id == COMPRESSION_NONE:
                                            mode = COMPRESSION_MODES[effective_compression_level]
                                            compressed_chunk = mode["func"](bytes(mv[chunk_offset:chunk_offset + chunk_len]))
                                        chunk_nonce = os.urandom(NONCE_SIZE)
                                        encrypted_chunk = cipher.encrypt(chunk_nonce, compressed_chunk, associated_data=header_bytes)
                                        outfile.write(chunk_nonce)
                                        outfile.write(struct.pack("!I", len(encrypted_chunk)))
                                        outfile.write(encrypted_chunk)
                                        if rs_codec:
                                            parity = rs_codec.encode(encrypted_chunk)[-ECC_BYTES:]
                                            outfile.write(parity)
                                        processed_size += chunk_len
                                        chunk_count += 1
                                        del compressed_chunk, encrypted_chunk
                                        if chunk_count % _GC_CHUNK_INTERVAL == 0:
                                            gc.collect()
                                        if self.progress_callback:
                                            self.progress_callback(processed_size / total_size * 100)
                        else:
                            offset = 0
                            while offset < total_size:
                                if self.is_canceled:
                                    raise Exception("Operation canceled by user.")
                                chunk_len = min(self.chunk_size, total_size - offset)
                                chunk_nonce = os.urandom(NONCE_SIZE)
                                encrypted_chunk = cipher.encrypt(chunk_nonce, bytes(mv[offset:offset + chunk_len]), associated_data=header_bytes)
                                outfile.write(chunk_nonce)
                                outfile.write(struct.pack("!I", len(encrypted_chunk)))
                                outfile.write(encrypted_chunk)
                                if rs_codec:
                                    parity = rs_codec.encode(encrypted_chunk)[-ECC_BYTES:]
                                    outfile.write(parity)
                                processed_size += chunk_len
                                offset += chunk_len
                                chunk_count += 1
                                del encrypted_chunk
                                if chunk_count % _GC_CHUNK_INTERVAL == 0:
                                    gc.collect()
                                if self.progress_callback:
                                    self.progress_callback(processed_size / total_size * 100)
                        del mv
                except (OSError, ValueError):
                    use_mmap = False

            if not use_mmap: ## fallback or smth i guess
                infile.seek(0)
                while True:
                    if self.is_canceled:
                        raise Exception("Operation canceled by user.")
                    chunk = infile.read(self.chunk_size)
                    if not chunk:
                        break
                    compressed_chunk, compression_id = compress_chunk(chunk, effective_compression_level)
                    if first_chunk:
                        final_compression_id = compression_id
                        first_chunk = False
                    if final_compression_id == COMPRESSION_NONE:
                        compressed_chunk = chunk
                    elif compression_id == COMPRESSION_NONE:
                        mode = COMPRESSION_MODES[effective_compression_level]
                        compressed_chunk = mode["func"](chunk)
                    chunk_nonce = os.urandom(NONCE_SIZE)
                    encrypted_chunk = cipher.encrypt(chunk_nonce, compressed_chunk, associated_data=header_bytes)
                    outfile.write(chunk_nonce)
                    outfile.write(struct.pack("!I", len(encrypted_chunk)))
                    outfile.write(encrypted_chunk)
                    if rs_codec:
                        parity = rs_codec.encode(encrypted_chunk)[-ECC_BYTES:]
                        outfile.write(parity)
                    processed_size += len(chunk)
                    chunk_count += 1
                    del chunk, compressed_chunk, encrypted_chunk
                    if chunk_count % _GC_CHUNK_INTERVAL == 0:
                        gc.collect()
                    if self.progress_callback:
                        self.progress_callback(processed_size / total_size * 100)
        if self.progress_callback: self.progress_callback(100.0)

    def _encrypt_archive(self):
        def archive_progress_callback(progress):
            if self.progress_callback:
                self.progress_callback(progress)
        archive_header, file_info, total_source_size = create_archive(self._file_list, progress_callback=archive_progress_callback)
        effective_compression_level = self.compression_level
        for file_path, _, _ in file_info:
            if should_skip_compression(file_path, self.compression_detection_mode, self.entropy_threshold):
                effective_compression_level = "none"
                break
        salt = os.urandom(SALT_SIZE)
        if self.aead_algorithm == "chacha20-poly1305":
            aead_id = ALGORITHM_ID_CHACHA
        else:
            aead_id = ALGORITHM_ID_AES_GCM
        kdf_type = KDF_ID_ARGON2 if self.use_argon2 else KDF_ID_PBKDF2
        pbkdf2_hash_id = HASH_ID_SHA512 if self.pbkdf2_hash == "sha512" else HASH_ID_SHA256
        key = self._derive_key(salt, kdf_type=kdf_type, pbkdf2_hash_id=pbkdf2_hash_id)
        cipher = ChaCha20Poly1305(key) if aead_id == ALGORITHM_ID_CHACHA else AESGCM(key)
        original_ext = "archive".encode("utf-8")
        ext_nonce = os.urandom(NONCE_SIZE)
        encrypted_ext = cipher.encrypt(ext_nonce, original_ext, None)
        if self.new_name_type == "hash":
            hasher = hashlib.sha256()
            hasher.update(archive_header)
            for file_path, _, _ in file_info:
                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(self.chunk_size)
                        if not chunk: break
                        hasher.update(chunk)
            out_filename = f"{hasher.hexdigest()}.{self.custom_ext}"
            self.out_path = os.path.join(os.path.dirname(self.out_path), out_filename)
        elif self.new_name_type == "base64":
            original_name = f"archive_{len(self._file_list)}_files"
            base64_bytes = base64.urlsafe_b64encode(original_name.encode("utf-8"))
            base64_name = base64_bytes.decode("utf-8").rstrip("=")[:96]
            out_filename = f"{base64_name}.{self.custom_ext}"
            self.out_path = os.path.join(os.path.dirname(self.out_path), out_filename)
        if os.path.exists(self.out_path):
            raise IOError(f"Output file '{os.path.basename(self.out_path)}' already exists.")
        final_compression_id_to_write = COMPRESSION_MODES.get(effective_compression_level, {"id": COMPRESSION_NONE})["id"]
        header_buffer = io.BytesIO()
        header_buffer.write(MAGIC_NUMBER)
        header_buffer.write(struct.pack("!B", FORMAT_VERSION))
        header_buffer.write(struct.pack("!B", aead_id))
        flags = FLAG_RECOVERY_DATA if self.add_recovery_data else 0
        flags |= FLAG_ARCHIVE_MODE
        if self.usb_key_path or self.keyfile_path:
            flags |= FLAG_USB_KEY
        header_buffer.write(struct.pack("!B", flags))
        header_buffer.write(struct.pack("!B", kdf_type))
        header_buffer.write(struct.pack("!B", final_compression_id_to_write))
        if self.add_recovery_data:
            header_buffer.write(struct.pack("!B", ECC_BYTES))
        if kdf_type == KDF_ID_ARGON2:
            header_buffer.write(struct.pack("!I", self.argon2_time_cost))
            header_buffer.write(struct.pack("!I", self.argon2_memory_cost))
            header_buffer.write(struct.pack("!I", self.argon2_parallelism))
        else:
            header_buffer.write(struct.pack("!B", pbkdf2_hash_id))
            header_buffer.write(struct.pack("!I", self.kdf_iterations))
        header_buffer.write(salt)
        header_buffer.write(ext_nonce)
        header_buffer.write(struct.pack("!I", len(encrypted_ext)))
        header_buffer.write(encrypted_ext)
        header_bytes = header_buffer.getvalue()
        rs_codec = reedsolo.RSCodec(ECC_BYTES) if self.add_recovery_data else None
        with open(self.out_path, "wb") as outfile:
            outfile.write(header_bytes)
            first_chunk = True
            final_compression_id = COMPRESSION_NONE
            processed_size = 0
            max_in_flight = self.max_workers * 2
            
            def data_stream():
                yield archive_header
                for file_path, _, _ in file_info:
                    if self.is_canceled:
                        raise Exception("Operation canceled by user.")
                    with open(file_path, "rb") as f:
                        while True:
                            chunk = f.read(self.chunk_size)
                            if not chunk:
                                break
                            yield chunk
            if effective_compression_level != "none":
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    pending_futures = []
                    data_iterator = data_stream()
                    exhausted = False
                    while not exhausted or pending_futures:
                        while len(pending_futures) < max_in_flight and not exhausted:
                            if self.is_canceled:
                                raise Exception("Operation canceled by user.")
                            try:
                                chunk_data = next(data_iterator)
                                future = executor.submit(compress_chunk_threaded, chunk_data, effective_compression_level)
                                pending_futures.append((future, len(chunk_data)))
                            except StopIteration:
                                exhausted = True
                                break
                        if pending_futures:
                            future, original_len = pending_futures.pop(0)
                            compressed_chunk, compression_id = future.result()
                            if first_chunk:
                                final_compression_id = compression_id
                                first_chunk = False
                            if final_compression_id == COMPRESSION_NONE and compression_id != COMPRESSION_NONE:
                                compressed_chunk = decompress_chunk(compressed_chunk, compression_id)
                            elif final_compression_id != COMPRESSION_NONE and compression_id == COMPRESSION_NONE:
                                mode = COMPRESSION_MODES[effective_compression_level]
                                compressed_chunk = mode["func"](compressed_chunk)
                            chunk_nonce = os.urandom(NONCE_SIZE)
                            encrypted_chunk = cipher.encrypt(chunk_nonce, compressed_chunk, associated_data=header_bytes)
                            outfile.write(chunk_nonce)
                            outfile.write(struct.pack("!I", len(encrypted_chunk)))
                            outfile.write(encrypted_chunk)
                            if rs_codec:
                                parity = rs_codec.encode(encrypted_chunk)[-ECC_BYTES:]
                                outfile.write(parity)
                            processed_size += original_len
                            if self.progress_callback:
                                progress = 50.0 + (processed_size / (len(archive_header) + total_source_size)) * 50.0
                                self.progress_callback(min(100.0, progress))
            else:
                for chunk in data_stream():
                    if self.is_canceled:
                        raise Exception("Operation canceled by user.")
                    compressed_chunk, compression_id = compress_chunk(chunk, effective_compression_level)
                    if first_chunk:
                        final_compression_id = compression_id
                        first_chunk = False
                    if final_compression_id == COMPRESSION_NONE:
                        compressed_chunk = chunk
                    elif compression_id == COMPRESSION_NONE:
                        mode = COMPRESSION_MODES[effective_compression_level]
                        compressed_chunk = mode["func"](chunk)
                    chunk_nonce = os.urandom(NONCE_SIZE)
                    encrypted_chunk = cipher.encrypt(chunk_nonce, compressed_chunk, associated_data=header_bytes)
                    outfile.write(chunk_nonce)
                    outfile.write(struct.pack("!I", len(encrypted_chunk)))
                    outfile.write(encrypted_chunk)
                    if rs_codec:
                        parity = rs_codec.encode(encrypted_chunk)[-ECC_BYTES:]
                        outfile.write(parity)
                    processed_size += len(chunk)
                    if self.progress_callback:
                        progress = 50.0 + (processed_size / (len(archive_header) + total_source_size)) * 50.0
                        self.progress_callback(min(100.0, progress))
        if self.progress_callback:
            self.progress_callback(100.0)

    def decrypt_file(self):
        with open(self.in_path, "rb") as infile:
            magic = infile.read(len(MAGIC_NUMBER))
            if magic != MAGIC_NUMBER and magic != MAGIC_NUMBER_LEGACY:
                raise ValueError("Not a valid PyKryptor encrypted file.")
            infile.seek(len(MAGIC_NUMBER))
            version = struct.unpack("!B", infile.read(1))[0]
            if version < 9:
                return self._decrypt_legacy_file(version)
            infile.seek(0)
            magic = infile.read(len(MAGIC_NUMBER))
            version = struct.unpack("!B", infile.read(1))[0]
            aead_id = struct.unpack("!B", infile.read(1))[0]
            flags = struct.unpack("!B", infile.read(1))[0]
            recovery_enabled = (flags & FLAG_RECOVERY_DATA) != 0
            is_archive = (flags & FLAG_ARCHIVE_MODE) != 0
            requires_usb_key = (flags & FLAG_USB_KEY) != 0
            kdf_type = struct.unpack("!B", infile.read(1))[0]
            compression_id = struct.unpack("!B", infile.read(1))[0]
            ecc_bytes = 0
            if recovery_enabled:
                ecc_bytes = struct.unpack("!B", infile.read(1))[0]
            kdf_iterations = None
            pbkdf2_hash_id = None
            if kdf_type == KDF_ID_ARGON2:
                self.argon2_time_cost = struct.unpack("!I", infile.read(4))[0]
                self.argon2_memory_cost = struct.unpack("!I", infile.read(4))[0]
                self.argon2_parallelism = struct.unpack("!I", infile.read(4))[0]
            else:
                pbkdf2_hash_id = struct.unpack("!B", infile.read(1))[0]
                kdf_iterations = struct.unpack("!I", infile.read(4))[0]
                self.argon2_time_cost = self.argon2_memory_cost = self.argon2_parallelism = None
            salt = infile.read(SALT_SIZE)
            ext_nonce = infile.read(NONCE_SIZE)
            ext_len_bytes = infile.read(4)
            if not ext_len_bytes: raise ValueError("Invalid file: unexpected end of header.")
            ext_len = struct.unpack("!I", ext_len_bytes)[0]
            if ext_len > MAX_EXT_LEN:
                raise ValueError(f"Invalid file: extension length {ext_len} exceeds maximum {MAX_EXT_LEN}")
            encrypted_ext = infile.read(ext_len)
            if len(encrypted_ext) != ext_len:
                raise ValueError("Invalid file: unexpected end while reading extension.")
            header_end_pos = infile.tell()
            infile.seek(0)
            header_bytes = infile.read(header_end_pos)
            if requires_usb_key and not self.usb_key_path and not self.keyfile_path:
                 raise ValueError("This file requires a Keyfile or USB Key; please provide one.")
            key = self._derive_key(salt, iterations=kdf_iterations, kdf_type=kdf_type, pbkdf2_hash_id=pbkdf2_hash_id)
            cipher = ChaCha20Poly1305(key) if aead_id == ALGORITHM_ID_CHACHA else AESGCM(key)
            try:
                original_ext = cipher.decrypt(ext_nonce, encrypted_ext, None).decode("utf-8")
            except InvalidTag:
                raise ValueError("Incorrect password / key or corrupt file.")
            total_size = os.path.getsize(self.in_path)
            rs_codec = reedsolo.RSCodec(ecc_bytes) if recovery_enabled else None
            max_sane_chunk_len = self.chunk_size + TAG_SIZE + 1024
            if is_archive and original_ext == "archive":
                out_dir = self.output_dir or os.path.dirname(self.in_path)
                base_filename = os.path.splitext(os.path.basename(self.in_path))[0]
                extract_dir = os.path.join(out_dir, f"{base_filename}_extracted")
                if os.path.exists(extract_dir):
                    counter = 1
                    while os.path.exists(f"{extract_dir}_{counter}"):
                        counter += 1
                    extract_dir = f"{extract_dir}_{counter}"
                _tmp_fd, _tmp_path = tempfile.mkstemp(suffix=".pykx_tmp", dir=out_dir)
                outfile_handle = os.fdopen(_tmp_fd, "wb")
                write_to_file = True
                _is_archive_tmp = True
            else:
                out_dir = self.output_dir or os.path.dirname(self.in_path)
                base_filename = os.path.splitext(os.path.basename(self.in_path))[0]
                out_path = os.path.join(out_dir, f"{base_filename}.{original_ext}")
                if os.path.exists(out_path) and not os.path.samefile(self.in_path, out_path):
                    raise IOError(f"Output file '{os.path.basename(out_path)}' already exists.")
                outfile_handle = open(out_path, "wb")
                write_to_file = True
                _is_archive_tmp = False
            infile.seek(header_end_pos)
            chunk_count = 0
            max_in_flight = self.max_workers * 2

            def read_chunk_header(f):
                chunk_nonce = f.read(NONCE_SIZE)
                if not chunk_nonce or len(chunk_nonce) != NONCE_SIZE:
                    return None
                len_bytes = f.read(4)
                if not len_bytes or len(len_bytes) != 4:
                    raise ValueError("Invalid file: truncated chunk length.")
                encrypted_chunk_len = struct.unpack("!I", len_bytes)[0]
                if encrypted_chunk_len == 0:
                    raise ValueError("Invalid file: 0-length data chunk.")
                if encrypted_chunk_len > max_sane_chunk_len:
                    raise ValueError(f"Invalid file: chunk length {encrypted_chunk_len}b exceeds {max_sane_chunk_len}b.")
                return (chunk_nonce, encrypted_chunk_len)

            def decrypt_chunk_worker(chunk_nonce, encrypted_chunk, parity_data):
                try:
                    if rs_codec and parity_data:
                        try:
                            combined_data = bytearray(encrypted_chunk + parity_data)
                            decrypted_chunk_with_parity, _, _ = rs_codec.decode(combined_data)
                            encrypted_chunk = bytes(decrypted_chunk_with_parity)
                        except reedsolo.ReedSolomonError:
                            raise ValueError("File chunk is corrupt and could not be recovered.")
                    decrypted_chunk = cipher.decrypt(chunk_nonce, encrypted_chunk, associated_data=header_bytes)
                    decompressed_chunk = decompress_chunk(decrypted_chunk, compression_id)
                    return decompressed_chunk
                except InvalidTag:
                    raise ValueError("File appears to be corrupted or password is incorrect (chunk authentication failed).")
            try:
                if compression_id != COMPRESSION_NONE:
                    with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                        pending_futures = []
                        while True:
                            if self.is_canceled:
                                outfile_handle.close()
                                raise Exception("Operation canceled by user.")
                            while len(pending_futures) < max_in_flight:
                                header = read_chunk_header(infile)
                                if header is None:
                                    break
                                chunk_nonce, encrypted_chunk_len = header
                                encrypted_chunk = infile.read(encrypted_chunk_len)
                                if len(encrypted_chunk) != encrypted_chunk_len:
                                    raise ValueError("Invalid file: unexpected end while reading chunk.")
                                parity_data = b""
                                if recovery_enabled:
                                    parity_data = infile.read(ecc_bytes)
                                    if len(parity_data) != ecc_bytes:
                                        raise ValueError("Invalid file: unexpected end while reading recovery data.")
                                future = executor.submit(decrypt_chunk_worker, chunk_nonce, encrypted_chunk, parity_data)
                                pending_futures.append((future, chunk_count))
                                chunk_count += 1
                            if not pending_futures:
                                break
                            future, chunk_idx = pending_futures.pop(0)
                            decompressed_chunk = future.result()
                            outfile_handle.write(decompressed_chunk)
                            del decompressed_chunk
                            if chunk_count % _GC_CHUNK_INTERVAL == 0:
                                gc.collect()
                            if total_size > header_end_pos:
                                progress = min(100.0, (chunk_count / max(1, (total_size - header_end_pos) // (self.chunk_size + 100))) * 70)
                                if self.progress_callback:
                                    self.progress_callback(progress)
                else:
                    while True:
                        if self.is_canceled:
                            outfile_handle.close()
                            raise Exception("Operation canceled by user.")
                        header = read_chunk_header(infile)
                        if header is None:
                            break
                        chunk_nonce, encrypted_chunk_len = header
                        encrypted_chunk = infile.read(encrypted_chunk_len)
                        if len(encrypted_chunk) != encrypted_chunk_len:
                            raise ValueError("Invalid file: unexpected end while reading chunk.")
                        parity_data = b""
                        if recovery_enabled:
                            parity_data = infile.read(ecc_bytes)
                            if len(parity_data) != ecc_bytes:
                                raise ValueError("Invalid file: unexpected end while reading recovery data.")
                        decompressed_chunk = decrypt_chunk_worker(chunk_nonce, encrypted_chunk, parity_data)
                        outfile_handle.write(decompressed_chunk)
                        chunk_count += 1
                        del encrypted_chunk, decompressed_chunk
                        if chunk_count % _GC_CHUNK_INTERVAL == 0:
                            gc.collect()
                        if total_size > header_end_pos:
                            progress = min(100.0, (chunk_count / max(1, (total_size - header_end_pos) // (self.chunk_size + 100))) * 70)
                            if self.progress_callback:
                                self.progress_callback(progress)
                outfile_handle.close()
                if _is_archive_tmp:
                    try:
                        extract_archive_streaming(_tmp_path, extract_dir, lambda p: self.progress_callback(70 + p * 0.3) if self.progress_callback else None)
                    finally:
                        try:
                            os.unlink(_tmp_path)
                        except OSError:
                            pass
            except Exception:
                try:
                    outfile_handle.close()
                except Exception:
                    pass
                if _is_archive_tmp:
                    try:
                        os.unlink(_tmp_path)
                    except OSError:
                        pass
                raise
        if self.progress_callback: self.progress_callback(100.0)

    def _decrypt_legacy_file(self, version):
        with open(self.in_path, "rb") as infile:
            infile.seek(0)
            magic = infile.read(len(MAGIC_NUMBER_LEGACY))
            if magic != MAGIC_NUMBER and magic != MAGIC_NUMBER_LEGACY:
                raise ValueError("Not a valid PyKryptor encrypted file.")
            read_version = struct.unpack("!B", infile.read(1))[0]
            if read_version != version:
                raise ValueError("Internal logic error: version mismatch.")
            if version < 3:
                raise ValueError(f"Unsupported format version: {version}. This version requires format 3 or higher.")
            aead_id = ALGORITHM_ID_AES_GCM
            if version >= 7:
                aead_id = struct.unpack("!B", infile.read(1))[0]
            flags = struct.unpack("!B", infile.read(1))[0]
            recovery_enabled = (flags & FLAG_RECOVERY_DATA) != 0
            is_archive = (flags & FLAG_ARCHIVE_MODE) != 0
            requires_usb_key = (flags & FLAG_USB_KEY) != 0 if version >= 10 else False
            kdf_type = KDF_ID_PBKDF2
            if version >= 6:
                kdf_type = struct.unpack("!B", infile.read(1))[0]
            compression_id = COMPRESSION_NONE
            if version >= 4:
                compression_id = struct.unpack("!B", infile.read(1))[0]
            ecc_bytes = 0
            if recovery_enabled:
                ecc_bytes = struct.unpack("!B", infile.read(1))[0]
            pbkdf2_hash_id = HASH_ID_SHA256
            if kdf_type == KDF_ID_ARGON2:
                argon2_time_cost = struct.unpack("!I", infile.read(4))[0]
                argon2_memory_cost = struct.unpack("!I", infile.read(4))[0]
                argon2_parallelism = struct.unpack("!I", infile.read(4))[0]
                kdf_iterations = None
            else:
                if version >= 8:
                    pbkdf2_hash_id = struct.unpack("!B", infile.read(1))[0]
                    kdf_iterations = struct.unpack("!I", infile.read(4))[0]
                else:
                    kdf_iterations = struct.unpack("!I", infile.read(4))[0]
                argon2_time_cost = argon2_memory_cost = argon2_parallelism = None
            salt = infile.read(SALT_SIZE)
            self.argon2_time_cost = argon2_time_cost
            self.argon2_memory_cost = argon2_memory_cost
            self.argon2_parallelism = argon2_parallelism
            if requires_usb_key and not self.usb_key_path and not self.keyfile_path:
                raise ValueError("This file was encrypted with a USB key. Please provide the USB drive path.")
            key = self._derive_key(salt, iterations=kdf_iterations, kdf_type=kdf_type, pbkdf2_hash_id=pbkdf2_hash_id)
            cipher = ChaCha20Poly1305(key) if aead_id == ALGORITHM_ID_CHACHA else AESGCM(key)
            ext_nonce = infile.read(NONCE_SIZE)
            ext_len_bytes = infile.read(4)
            if not ext_len_bytes: raise ValueError("Invalid file: unexpected end of header.")
            ext_len = struct.unpack("!I", ext_len_bytes)[0]
            if ext_len > MAX_EXT_LEN:
                raise ValueError(f"Invalid file: extension length {ext_len} exceeds maximum {MAX_EXT_LEN}")
            encrypted_ext = infile.read(ext_len)
            if len(encrypted_ext) != ext_len:
                raise ValueError("Invalid file: unexpected end while reading extension.")
            try:
                original_ext = cipher.decrypt(ext_nonce, encrypted_ext, None).decode("utf-8")
            except InvalidTag:
                raise ValueError("Incorrect password or corrupt file extension data.")
            header_size = infile.tell()
            total_size = os.path.getsize(self.in_path)
            rs_codec = reedsolo.RSCodec(ecc_bytes) if recovery_enabled else None
            max_sane_chunk_len = self.chunk_size + TAG_SIZE + 1024
            if is_archive and original_ext == "archive":
                out_dir = self.output_dir or os.path.dirname(self.in_path)
                base_filename = os.path.splitext(os.path.basename(self.in_path))[0]
                extract_dir = os.path.join(out_dir, f"{base_filename}_extracted")
                if os.path.exists(extract_dir):
                    counter = 1
                    while os.path.exists(f"{extract_dir}_{counter}"):
                        counter += 1
                    extract_dir = f"{extract_dir}_{counter}"
                _tmp_fd, _tmp_path = tempfile.mkstemp(suffix=".pykx_tmp", dir=out_dir)
                outfile_handle = os.fdopen(_tmp_fd, "wb")
                write_to_file = True
                _is_archive_tmp = True
            else:
                out_dir = self.output_dir or os.path.dirname(self.in_path)
                base_filename = os.path.splitext(os.path.basename(self.in_path))[0]
                out_path = os.path.join(out_dir, f"{base_filename}.{original_ext}")
                if os.path.exists(out_path) and not os.path.samefile(self.in_path, out_path):
                    raise IOError(f"Output file '{os.path.basename(out_path)}' already exists.")
                outfile_handle = open(out_path, "wb")
                write_to_file = True
                _is_archive_tmp = False
            chunk_count = 0
            max_in_flight = self.max_workers * 2

            def read_chunk_header(f):
                chunk_nonce = f.read(NONCE_SIZE)
                if not chunk_nonce or len(chunk_nonce) != NONCE_SIZE:
                    return None
                len_bytes = f.read(4)
                if not len_bytes or len(len_bytes) != 4:
                    raise ValueError("Invalid file: truncated chunk length.")
                encrypted_chunk_len = struct.unpack("!I", len_bytes)[0]
                if encrypted_chunk_len == 0:
                    raise ValueError("Invalid file: 0-length data chunk.")
                if encrypted_chunk_len > max_sane_chunk_len:
                    raise ValueError(f"Invalid file: chunk length {encrypted_chunk_len}b exceeds {max_sane_chunk_len}b.")
                return (chunk_nonce, encrypted_chunk_len)

            def decrypt_chunk_worker(chunk_nonce, encrypted_chunk, parity_data):
                try:
                    if rs_codec and parity_data:
                        try:
                            combined_data = bytearray(encrypted_chunk + parity_data)
                            decrypted_chunk_with_parity, _, _ = rs_codec.decode(combined_data)
                            encrypted_chunk = bytes(decrypted_chunk_with_parity)
                        except reedsolo.ReedSolomonError:
                            raise ValueError("File chunk is corrupt and could not be recovered.")
                    decrypted_chunk = cipher.decrypt(chunk_nonce, encrypted_chunk, None)
                    decompressed_chunk = decompress_chunk(decrypted_chunk, compression_id)
                    return decompressed_chunk
                except InvalidTag:
                    raise ValueError("File appears to be corrupted or password is incorrect (chunk authentication failed).")
            try:
                if compression_id != COMPRESSION_NONE:
                    with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                        pending_futures = []
                        while True:
                            if self.is_canceled:
                                outfile_handle.close()
                                raise Exception("Operation canceled by user.")
                            while len(pending_futures) < max_in_flight:
                                header = read_chunk_header(infile)
                                if header is None:
                                    break
                                chunk_nonce, encrypted_chunk_len = header
                                encrypted_chunk = infile.read(encrypted_chunk_len)
                                if len(encrypted_chunk) != encrypted_chunk_len:
                                    raise ValueError("Invalid file: unexpected end while reading chunk.")
                                parity_data = b""
                                if recovery_enabled:
                                    parity_data = infile.read(ecc_bytes)
                                    if len(parity_data) != ecc_bytes:
                                        raise ValueError("Invalid file: unexpected end while reading recovery data.")
                                future = executor.submit(decrypt_chunk_worker, chunk_nonce, encrypted_chunk, parity_data)
                                pending_futures.append((future, chunk_count))
                                chunk_count += 1
                            if not pending_futures:
                                break
                            future, chunk_idx = pending_futures.pop(0)
                            decompressed_chunk = future.result()
                            outfile_handle.write(decompressed_chunk)
                            del decompressed_chunk
                            if chunk_count % _GC_CHUNK_INTERVAL == 0:
                                gc.collect()
                            if total_size > header_size:
                                progress = min(100.0, (chunk_count / max(1, (total_size - header_size) // (self.chunk_size + 100))) * 70)
                                if self.progress_callback:
                                    self.progress_callback(progress)
                else:
                    while True:
                        if self.is_canceled:
                            outfile_handle.close()
                            raise Exception("Operation canceled by user.")
                        header = read_chunk_header(infile)
                        if header is None:
                            break
                        chunk_nonce, encrypted_chunk_len = header
                        encrypted_chunk = infile.read(encrypted_chunk_len)
                        if len(encrypted_chunk) != encrypted_chunk_len:
                            raise ValueError("Invalid file: unexpected end while reading chunk.")
                        parity_data = b""
                        if recovery_enabled:
                            parity_data = infile.read(ecc_bytes)
                            if len(parity_data) != ecc_bytes:
                                raise ValueError("Invalid file: unexpected end while reading recovery data.")
                        decompressed_chunk = decrypt_chunk_worker(chunk_nonce, encrypted_chunk, parity_data)
                        outfile_handle.write(decompressed_chunk)
                        chunk_count += 1
                        del encrypted_chunk, decompressed_chunk
                        if chunk_count % _GC_CHUNK_INTERVAL == 0:
                            gc.collect() ## fuck this garbage collector i'd rather write it in rust
                        if total_size > header_size:
                            progress = min(100.0, (chunk_count / max(1, (total_size - header_size) // (self.chunk_size + 100))) * 70)
                            if self.progress_callback:
                                self.progress_callback(progress)
                outfile_handle.close()
                if _is_archive_tmp:
                    try:
                        extract_archive_streaming(_tmp_path, extract_dir, lambda p: self.progress_callback(70 + p * 0.3) if self.progress_callback else None)
                    finally:
                        try:
                            os.unlink(_tmp_path)
                        except OSError:
                            pass

            except Exception:
                try:
                    outfile_handle.close()
                except Exception:
                    pass
                if _is_archive_tmp:
                    try:
                        os.unlink(_tmp_path)
                    except OSError:
                        pass
                raise
        if self.progress_callback: self.progress_callback(100.0)

class BatchProcessorThread(QThread):
    batch_progress_updated = pyqtSignal(int, int)
    status_message = pyqtSignal(str)
    progress_updated = pyqtSignal(float)
    finished = pyqtSignal(list)
    
    def __init__(self, operation, file_paths, password, custom_ext=None, output_dir=None, new_name_type=None, chunk_size=CHUNK_SIZE, kdf_iterations=1000000, secure_clear=False, add_recovery_data=False, compression_level="none", archive_mode=False, use_argon2=False, argon2_time_cost=ARGON2_TIME_COST, argon2_memory_cost=ARGON2_MEMORY_COST, argon2_parallelism=ARGON2_PARALLELISM, aead_algorithm="aes-gcm", pbkdf2_hash="sha256", usb_key_path=None, keyfile_path=None, archive_name=None, compression_detection_mode="legacy", entropy_threshold=7.5, parent=None):
        super().__init__(parent)
        self.operation = operation
        self.file_paths = file_paths
        self.password = password
        self.custom_ext = custom_ext
        self.output_dir = output_dir
        self.new_name_type = new_name_type
        self.chunk_size = chunk_size
        self.kdf_iterations = kdf_iterations
        self.secure_clear = secure_clear
        self.add_recovery_data = add_recovery_data
        self.compression_level = compression_level
        self.archive_mode = archive_mode
        self.use_argon2 = use_argon2
        self.argon2_time_cost = argon2_time_cost
        self.argon2_memory_cost = argon2_memory_cost
        self.argon2_parallelism = argon2_parallelism
        self.aead_algorithm = aead_algorithm
        self.pbkdf2_hash = pbkdf2_hash
        self.usb_key_path = usb_key_path
        self.keyfile_path = keyfile_path
        self.archive_name = archive_name
        self.compression_detection_mode = compression_detection_mode
        self.entropy_threshold = entropy_threshold
        self.is_canceled = False
        self.errors = []
        self.worker = None

    def run(self):
        if self.operation == "encrypt" and self.archive_mode and len(self.file_paths) > 1:
            self.batch_progress_updated.emit(1, 1)
            self.status_message.emit("Creating archive...")
            try:
                if self.archive_name and self.output_dir:
                    out_path = os.path.join(self.output_dir, self.archive_name)
                else:
                    fallback_dir = self.output_dir or os.path.dirname(self.file_paths[0])
                    fallback_name = f"{os.path.splitext(os.path.basename(self.file_paths[0]))[0]}_archive.{self.custom_ext}"
                    out_path = os.path.join(fallback_dir, fallback_name)
                self.worker = CryptoWorker(operation=self.operation, in_path=self.file_paths[0], out_path=out_path, password=self.password, custom_ext=self.custom_ext, new_name_type=self.new_name_type, output_dir=self.output_dir, chunk_size=self.chunk_size, kdf_iterations=self.kdf_iterations, secure_clear=self.secure_clear, add_recovery_data=self.add_recovery_data, compression_level=self.compression_level, archive_mode=self.archive_mode, use_argon2=self.use_argon2, argon2_time_cost=self.argon2_time_cost, argon2_memory_cost=self.argon2_memory_cost, argon2_parallelism=self.argon2_parallelism, aead_algorithm=self.aead_algorithm, pbkdf2_hash=self.pbkdf2_hash, usb_key_path=self.usb_key_path, keyfile_path=self.keyfile_path, compression_detection_mode=self.compression_detection_mode, entropy_threshold=self.entropy_threshold, progress_callback=lambda p: self.progress_updated.emit(p))
                self.worker._file_list = self.file_paths
                self.worker.encrypt_file()
            except Exception as e:
                self.errors.append(f"Archive creation failed: {str(e)}")
        else:
            total_files = len(self.file_paths)
            _emit_every = _BATCH_PROGRESS_INTERVAL if total_files > _BATCH_PROGRESS_INTERVAL else 1
            for i, file_path in enumerate(self.file_paths):
                if self.is_canceled: break
                if os.path.isdir(file_path):
                    self.errors.append(f"Skipped '{os.path.basename(file_path)}': directories must be added to an archive.")
                    continue
                if not os.path.isfile(file_path):
                    self.errors.append(f"Skipped '{os.path.basename(file_path)}': file not found.")
                    continue
                if i % _emit_every == 0 or i == total_files - 1:
                    self.batch_progress_updated.emit(i + 1, total_files)
                    self.status_message.emit(f"Processing: {os.path.basename(file_path)}")
                try:
                    out_path = file_path
                    if self.output_dir:
                        out_path = os.path.join(self.output_dir, os.path.basename(file_path))
                    self.worker = CryptoWorker(operation=self.operation, in_path=file_path, out_path=out_path, password=self.password, custom_ext=self.custom_ext, new_name_type=self.new_name_type, output_dir=self.output_dir, chunk_size=self.chunk_size, kdf_iterations=self.kdf_iterations, secure_clear=self.secure_clear, add_recovery_data=self.add_recovery_data, compression_level=self.compression_level, archive_mode=self.archive_mode, use_argon2=self.use_argon2, argon2_time_cost=self.argon2_time_cost, argon2_memory_cost=self.argon2_memory_cost, argon2_parallelism=self.argon2_parallelism, aead_algorithm=self.aead_algorithm, pbkdf2_hash=self.pbkdf2_hash, usb_key_path=self.usb_key_path, keyfile_path=self.keyfile_path, compression_detection_mode=self.compression_detection_mode, entropy_threshold=self.entropy_threshold, progress_callback=lambda p: self.progress_updated.emit(p))
                    if self.operation == "encrypt":
                        self.worker.encrypt_file()
                    elif self.operation == "decrypt":
                        self.worker.decrypt_file()
                except Exception as e:
                    self.errors.append(f"File '{os.path.basename(file_path)}' failed: {str(e)}")
        self.password = None
        self.finished.emit(self.errors)

    def cancel(self):
        self.is_canceled = True
        if self.password:
            if self.secure_clear:
                pwd_bytes = self.password.encode("utf-8")
                pwd_buffer = ctypes.create_string_buffer(len(pwd_bytes))
                pwd_buffer.raw = pwd_bytes
                clear_buffer(pwd_buffer)
            self.password = None
        if hasattr(self, "out_path") and self.out_path and os.path.exists(self.out_path):
            try:
                import time
                time.sleep(0.1)
                os.remove(self.out_path)
            except Exception:
                pass

## end