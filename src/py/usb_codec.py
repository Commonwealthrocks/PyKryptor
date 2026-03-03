## usb_codec.py
## last updated: 03/03/2026 <d/m/y>
## p-y-k-x
import os
import sys
import json
import hashlib
import hmac
import string
import time
import ctypes
import shutil
import random
import secrets
import struct
import base64
from colorama import Fore, Style
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEYFILE_SIZE = 512 
HIDDEN_DIR_NAME = ".pykx_usb_codec_data"
DATA_FILE_MARKER = b"\x89\x50\x4B\x58"
LEGACY_KEYFILE_NAME = ".pykryptor_keyfile"
LEGACY_METADATA_NAME = ".pykryptor_usb_key"
FAKE_EXTENSIONS = [".dat", ".tmp", ".sys", ".cab", ".log", ".old", ".bak", ".bin", ".chk", ".dmp", ".cache", ".idx", ".db", ".lock", ".pid", ".swp", ".swo"]
FAKE_NAMES = ["cache", "config", "driver", "system", "temp", "update", "recovery", "data", "index", "metadata", "usr", "var", "password", "winlog", "setup", "installer", "diagnostic", "keyfile", "sync", "backup", "restore", "plain"]

def _get_usb_fingerprint(usb_path):
    fingerprint = {}
    try:
        if sys.platform == "win32":
            import win32api
            import win32file
            try:
                volume_info = win32api.GetVolumeInformation(usb_path)
                fingerprint["volume_name"] = volume_info[0] or ""
                fingerprint["serial_number"] = str(volume_info[1])
                fingerprint["filesystem"] = volume_info[4] or ""
            except:
                pass
            try:
                import wmi
                c = wmi.WMI()
                drive_letter = usb_path.rstrip("\\")
                for disk in c.Win32_DiskDrive():
                    for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                        for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                            if logical_disk.DeviceID == drive_letter:
                                fingerprint["disk_serial"] = disk.SerialNumber or ""
                                fingerprint["disk_model"] = disk.Model or ""
                                fingerprint["disk_size"] = str(disk.Size or 0)
                                fingerprint["media_type"] = disk.MediaType or ""
                                break
            except:
                pass
            try:
                handle = win32file.CreateFile(
                    usb_path,
                    win32file.GENERIC_READ,
                    win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                    None,
                    win32file.OPEN_EXISTING,
                    win32file.FILE_FLAG_BACKUP_SEMANTICS,
                    None)
                creation_time = win32file.GetFileTime(handle)[0]
                win32file.CloseHandle(handle)
                fingerprint["volume_creation"] = str(int(creation_time))
            except:
                pass
        elif sys.platform.startswith("linux"):
            import subprocess
            try:
                result = subprocess.run(
                    ["blkid", "-s", "UUID", "-o", "value", usb_path],
                    capture_output=True,
                    text=True,
                    timeout=5)
                if result.returncode == 0:
                    fingerprint["uuid"] = result.stdout.strip()
            except:
                pass
            try:
                result = subprocess.run(["blkid", "-s", "TYPE", "-o", "value", usb_path], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    fingerprint["filesystem"] = result.stdout.strip()
            except:
                pass
            try:
                result = subprocess.run(["blkid", "-s", "PARTUUID", "-o", "value", usb_path], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    fingerprint["partuuid"] = result.stdout.strip()
            except:
                pass
            try:
                result = subprocess.run(["udevadm", "info", "--query=property", "--name=" + usb_path], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if line.startswith("ID_SERIAL="):
                            fingerprint["device_serial"] = line.split("=", 1)[1]
                        elif line.startswith("ID_MODEL="):
                            fingerprint["device_model"] = line.split("=", 1)[1]
            except:
                pass
        else:
            fingerprint["path_hash"] = hashlib.sha256(usb_path.encode()).hexdigest()[:32]
    except Exception as e:
        pass
    if not fingerprint:
        fingerprint["mount_point"] = usb_path
    return fingerprint

def _fingerprint_match(stored_fp, current_fp, threshold=0.7):
    critical_keys = ["serial_number", "uuid", "disk_serial", "path_hash", "device_serial"]
    keys_present = [k for k in critical_keys if k in stored_fp or k in current_fp]
    if not keys_present:
        return stored_fp == current_fp
    matches = sum(1 for k in keys_present if stored_fp.get(k) == current_fp.get(k) and stored_fp.get(k))
    return (matches / len(keys_present)) >= threshold

def _fingerprint_to_key_material(fingerprint, salt):
    if salt is None or len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes now.")
    sorted_items = sorted(fingerprint.items())
    combined = ""
    for key, value in sorted_items:
        combined += f"{key}:{value}|"
    combined_bytes = combined.encode("utf-8")
    try:
        from argon2.low_level import hash_secret_raw, Type
        secondary_hash = hash_secret_raw(
            secret=combined_bytes,
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=64,
            type=Type.ID)
        return secondary_hash
    except ImportError:
        primary_hash = hashlib.sha512(combined_bytes).digest()
        secondary_input = primary_hash + combined_bytes + salt
        secondary_hash = hashlib.sha512(secondary_input).digest()
        if len(secondary_hash) < 64:
             secondary_hash += hashlib.sha512(secondary_hash).digest()
        return secondary_hash[:64]

def _generate_decoy_filename():
    base = random.choice(FAKE_NAMES)
    if random.random() > 0.5:
        base += hex(random.getrandbits(32))[2:]
    ext = random.choice(FAKE_EXTENSIONS)
    return f"{base}{ext}"
def _generate_realistic_decoy_content(size):
    content = bytearray()
    if random.random() > 0.5:
        header = struct.pack("<4sIIII", random.choice([b"CFG\x00", b"DAT\x00", b"IDX\x00", b"LOG\x00"]), random.randint(1, 100), random.randint(0, 0xFFFFFFFF), size, random.randint(0, 0xFF)) ## i'll prob never touch this line again anyways
        content.extend(header)
    remaining = size - len(content)
    while len(content) < size:
        chunk_type = random.choice(["random", "zeros", "pattern", "repeat"])
        chunk_size = min(random.randint(16, 256), remaining)
        if chunk_type == "random":
            content.extend(os.urandom(chunk_size))
        elif chunk_type == "zeros":
            content.extend(b"\x00" * chunk_size)
        elif chunk_type == "pattern":
            pattern = bytes([random.randint(0, 255)] * 4)
            content.extend(pattern * (chunk_size // 4))
        elif chunk_type == "repeat":
            byte_val = random.randint(0, 255)
            content.extend(bytes([byte_val] * chunk_size))
        remaining = size - len(content)
    return bytes(content[:size])

def _create_hidden_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)
        if sys.platform == "win32":
            try:
                ctypes.windll.kernel32.SetFileAttributesW(path, 2)
            except:
                pass

def _set_file_hidden(filepath):
    if sys.platform == "win32":
        try:
            ctypes.windll.kernel32.SetFileAttributesW(filepath, 2)
        except:
            pass
        
_APP_SECRET = b"pykryptor_vWHATEVER_meta_derive_or_something_do_not_change_ts"

def _derive_meta_filenames(fingerprint, salt):
    fp_bytes = json.dumps(fingerprint, sort_keys=True).encode("utf-8")
    meta_name = hashlib.sha256(_APP_SECRET + b":meta:" + salt + fp_bytes).hexdigest()[:20] + ".dat"
    key_name  = hashlib.sha256(_APP_SECRET + b":key:"  + salt + fp_bytes).hexdigest()[:20] + ".dat"
    return meta_name, key_name

def setup_usb_key(usb_path):
    try:
        fingerprint = _get_usb_fingerprint(usb_path)
        if not fingerprint:
            raise ValueError("Could not read any USB hardware identifiers.")
        usb_uuid = fingerprint.get("serial_number") or \
                   fingerprint.get("uuid") or \
                   fingerprint.get("disk_serial") or \
                   fingerprint.get("path_hash") or \
                   hashlib.sha256(usb_path.encode()).hexdigest()[:16]
        legacy_meta = os.path.join(usb_path, LEGACY_METADATA_NAME)
        legacy_key = os.path.join(usb_path, LEGACY_KEYFILE_NAME)
        if os.path.exists(legacy_meta):
            os.remove(legacy_meta)
        if os.path.exists(legacy_key):
            os.remove(legacy_key)
        data_dir = os.path.join(usb_path, HIDDEN_DIR_NAME)
        _create_hidden_directory(data_dir)
        random_key_data = os.urandom(KEYFILE_SIZE)
        random_salt = os.urandom(16)
        encryption_key_material = _fingerprint_to_key_material(fingerprint, salt=random_salt)
        encryption_key = encryption_key_material[:32]
        hmac_key = encryption_key_material[32:64]
        aesgcm = AESGCM(encryption_key)
        key_nonce = os.urandom(12)
        aad = json.dumps(fingerprint, sort_keys=True).encode("utf-8")
        key_ciphertext = aesgcm.encrypt(key_nonce, random_key_data, aad)
        key_package = DATA_FILE_MARKER + key_nonce + key_ciphertext
        key_mac = hmac.new(hmac_key, key_package, hashlib.sha512).digest()[:32]
        meta_payload = json.dumps({
            "version": 3,
            "salt": base64.b64encode(random_salt).decode("utf-8"),
            "created": time.time()
        }).encode("utf-8")
        meta_nonce = os.urandom(12)
        meta_key_material = _fingerprint_to_key_material(fingerprint, salt=random_salt + b":meta")
        meta_enc_key = meta_key_material[:32]
        meta_hmac_key = meta_key_material[32:64]
        meta_aesgcm = AESGCM(meta_enc_key)
        meta_ciphertext = meta_aesgcm.encrypt(meta_nonce, meta_payload, aad)
        meta_package = DATA_FILE_MARKER + meta_nonce + meta_ciphertext
        meta_mac = hmac.new(meta_hmac_key, meta_package, hashlib.sha512).digest()[:32]
        meta_filename, key_filename = _derive_meta_filenames(fingerprint, random_salt)
        key_file_path = os.path.join(data_dir, key_filename)
        with open(key_file_path, "wb") as f:
            f.write(DATA_FILE_MARKER)
            f.write(key_mac)
            f.write(key_nonce)
            f.write(key_ciphertext)
        _set_file_hidden(key_file_path)
        fp_json_bytes = json.dumps(fingerprint, sort_keys=True).encode("utf-8")
        meta_prefix = struct.pack("!I", 4) + struct.pack("!H", len(random_salt)) + random_salt + struct.pack("!H", len(fp_json_bytes)) + fp_json_bytes
        meta_file_path = os.path.join(data_dir, meta_filename)
        with open(meta_file_path, "wb") as f:
            f.write(DATA_FILE_MARKER)
            f.write(meta_prefix)
            f.write(meta_mac)
            f.write(meta_nonce)
            f.write(meta_ciphertext)
        _set_file_hidden(meta_file_path)
        try:
            num_decoys = random.randint(15, 25)
            existing = {key_filename, meta_filename}
            for _ in range(num_decoys):
                decoy_filename = _generate_decoy_filename()
                if decoy_filename in existing:
                    continue
                decoy_path = os.path.join(data_dir, decoy_filename)
                size = random.randint(128, 8192)
                content = _generate_realistic_decoy_content(size)
                with open(decoy_path, "wb") as f:
                    f.write(content)
                _set_file_hidden(decoy_path)
        except Exception:
            pass
        return random_key_data, usb_uuid
    except Exception as e:
        raise ValueError(f"Failed to setup USB key: {str(e)}")

def get_usb_key(usb_path):
    try:
        data_dir = os.path.join(usb_path, HIDDEN_DIR_NAME)
        if not os.path.exists(data_dir):
            raise ValueError("USB key data not found (not initialized or corrupted).")
        current_fingerprint = _get_usb_fingerprint(usb_path)
        if not current_fingerprint:
            raise ValueError("Could not read USB hardware identifiers.")
        random_salt = None
        meta_filename_found = None
        stored_fp = None
        meta_blob = None
        for fname in os.listdir(data_dir):
            fpath = os.path.join(data_dir, fname)
            try:
                with open(fpath, "rb") as f:
                    raw = f.read()
                if not raw.startswith(DATA_FILE_MARKER):
                    continue
                if len(raw) > 8:
                    try:
                        version = struct.unpack("!I", raw[4:8])[0]
                        if version == 4:
                            salt_len = struct.unpack("!H", raw[8:10])[0]
                            offset = 10
                            candidate_salt = raw[offset:offset+salt_len]
                            offset += salt_len
                            fp_len = struct.unpack("!H", raw[offset:offset+2])[0]
                            offset += 2
                            stored_fp_text = raw[offset:offset+fp_len].decode("utf-8")
                            stored_fp = json.loads(stored_fp_text)
                            offset += fp_len
                            random_salt = candidate_salt
                            meta_filename_found = fname
                            meta_blob = raw[:4] + raw[offset:]
                            break
                    except Exception:
                        pass
                sep = b":SALT:"
                idx = raw.rfind(sep)
                if idx != -1:
                    candidate_salt = raw[idx + len(sep):]
                    if len(candidate_salt) == 16:
                        random_salt = candidate_salt
                        meta_filename_found = fname
                        meta_blob = raw[:idx]
                        break
            except Exception:
                continue
        if random_salt is None:
            raise ValueError("USB key data not found (metadata blob missing or corrupted).")
        if stored_fp is not None:
            if not _fingerprint_match(stored_fp, current_fingerprint):
                 raise ValueError("Hardware fingerprint mismatch (fuzzy match failed).")
            effective_fingerprint = stored_fp
        else:
            effective_fingerprint = current_fingerprint
        meta_filename, key_filename = _derive_meta_filenames(effective_fingerprint, random_salt)
        if meta_filename_found != meta_filename:
            raise ValueError("Hardware fingerprint mismatch; this USB-codec does not belong to this specific drive.")
        meta_key_material = _fingerprint_to_key_material(effective_fingerprint, salt=random_salt + b":meta")
        meta_enc_key = meta_key_material[:32]
        meta_hmac_key = meta_key_material[32:64]
        aad = json.dumps(effective_fingerprint, sort_keys=True).encode("utf-8")
        marker = meta_blob[:4]
        if marker != DATA_FILE_MARKER:
            raise ValueError("Invalid metadata file format.")
        stored_meta_mac = meta_blob[4:36]
        meta_nonce = meta_blob[36:48]
        meta_ciphertext = meta_blob[48:]
        meta_package = DATA_FILE_MARKER + meta_nonce + meta_ciphertext
        computed_meta_mac = hmac.new(meta_hmac_key, meta_package, hashlib.sha512).digest()[:32]
        if not hmac.compare_digest(stored_meta_mac, computed_meta_mac):
            raise ValueError("Metadata integrity check failed; possible tampering or wrong drive.")
        meta_aesgcm = AESGCM(meta_enc_key)
        try:
            meta_payload = json.loads(meta_aesgcm.decrypt(meta_nonce, meta_ciphertext, aad).decode("utf-8"))
        except Exception:
            raise ValueError("Metadata decryption failed; hardware fingerprint mismatch or corrupt.")
        key_file_path = os.path.join(data_dir, key_filename)
        if not os.path.exists(key_file_path):
            raise ValueError("USB key file not found (may have been deleted).")
        encryption_key_material = _fingerprint_to_key_material(effective_fingerprint, salt=random_salt)
        encryption_key = encryption_key_material[:32]
        hmac_key = encryption_key_material[32:64]
        with open(key_file_path, "rb") as f:
            key_marker = f.read(4)
            if key_marker != DATA_FILE_MARKER:
                raise ValueError("Invalid key file format.")
            stored_mac = f.read(32)
            key_nonce = f.read(12)
            key_ciphertext = f.read()
        key_package = DATA_FILE_MARKER + key_nonce + key_ciphertext
        computed_mac = hmac.new(hmac_key, key_package, hashlib.sha512).digest()[:32]
        if not hmac.compare_digest(stored_mac, computed_mac):
            raise ValueError("Key file integrity check failed; possible tampering detected.")
        aesgcm = AESGCM(encryption_key)
        try:
            raw_key_data = aesgcm.decrypt(key_nonce, key_ciphertext, aad)
        except Exception:
            raise ValueError("Decryption failed; hardware fingerprint mismatch or corrupt cipher.")
        if len(raw_key_data) != KEYFILE_SIZE:
            raise ValueError("Decrypted keyfile has incorrect size.")
        usb_uuid = current_fingerprint.get("serial_number") or \
                   current_fingerprint.get("uuid") or \
                   current_fingerprint.get("disk_serial") or \
                   current_fingerprint.get("path_hash") or \
                   hashlib.sha256(usb_path.encode()).hexdigest()[:16]
        return raw_key_data, usb_uuid
    except FileNotFoundError:
        raise ValueError("USB key data not found")
    except json.JSONDecodeError:
        raise ValueError("USB key metadata corrupted")
    except Exception as e:
        raise ValueError(f"Failed to read USB key: {str(e)}")

def list_usb_drives():
    usb_drives = []
    try:
        if sys.platform == "win32":
            from ctypes import windll
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                drive_type = windll.kernel32.GetDriveTypeW(drive)
                if drive_type == 2:
                    if os.path.exists(drive):
                        usb_drives.append(drive)
        elif sys.platform.startswith("linux"):
            media_paths = ["/media", "/mnt"]
            for media in media_paths:
                if os.path.exists(media):
                    for user_dir in os.listdir(media):
                        user_path = os.path.join(media, user_dir)
                        if os.path.isdir(user_path):
                            for drive in os.listdir(user_path):
                                drive_path = os.path.join(user_path, drive)
                                if os.path.ismount(drive_path):
                                    usb_drives.append(drive_path)
        else:
            volumes_path = "/Volumes"
            if os.path.exists(volumes_path):
                for volume in os.listdir(volumes_path):
                    volume_path = os.path.join(volumes_path, volume)
                    if os.path.ismount(volume_path):
                        usb_drives.append(volume_path)
    except Exception:
        pass
    return usb_drives

def is_usb_key_initialized(usb_path):
    data_dir = os.path.join(usb_path, HIDDEN_DIR_NAME)
    if not os.path.exists(data_dir):
        return False
    try:
        for fname in os.listdir(data_dir):
            fpath = os.path.join(data_dir, fname)
            try:
                with open(fpath, "rb") as f:
                    raw = f.read()
                if raw[:4] == DATA_FILE_MARKER:
                    if len(raw) > 8 and struct.unpack("!I", raw[4:8])[0] == 4:
                        return True
                    if b":SALT:" in raw[-22:]:
                        return True
            except Exception:
                continue
    except Exception:
        pass
    return False

def get_usb_key_info(usb_path):
    try:
        raw_key, usb_uuid = get_usb_key(usb_path)
        data_dir = os.path.join(usb_path, HIDDEN_DIR_NAME)
        current_fingerprint = _get_usb_fingerprint(usb_path)
        created_time = "Unknown"
        for fname in os.listdir(data_dir):
            fpath = os.path.join(data_dir, fname)
            try:
                with open(fpath, "rb") as f:
                    raw = f.read()
                if not raw.startswith(DATA_FILE_MARKER):
                    continue
                effective_fingerprint = current_fingerprint
                meta_blob = None
                if len(raw) > 8:
                    try:
                        version = struct.unpack("!I", raw[4:8])[0]
                        if version == 4:
                            salt_len = struct.unpack("!H", raw[8:10])[0]
                            offset = 10
                            candidate_salt = raw[offset:offset+salt_len]
                            offset += salt_len
                            fp_len = struct.unpack("!H", raw[offset:offset+2])[0]
                            offset += 2
                            stored_fp_text = raw[offset:offset+fp_len].decode("utf-8")
                            effective_fingerprint = json.loads(stored_fp_text)
                            offset += fp_len
                            meta_blob = raw[:4] + raw[offset:]
                    except Exception:
                        pass
                if meta_blob is None:
                    sep = b":SALT:"
                    idx = raw.rfind(sep)
                    if idx == -1: continue
                    candidate_salt = raw[idx + len(sep):]
                    if len(candidate_salt) != 16: continue
                    meta_blob = raw[:idx]
                meta_filename, _ = _derive_meta_filenames(effective_fingerprint, candidate_salt)
                if fname != meta_filename:
                    continue
                meta_key_material = _fingerprint_to_key_material(effective_fingerprint, salt=candidate_salt + b":meta")
                meta_enc_key = meta_key_material[:32]
                meta_aesgcm = AESGCM(meta_enc_key)
                aad = json.dumps(effective_fingerprint, sort_keys=True).encode("utf-8")
                meta_nonce = meta_blob[36:48]
                meta_ciphertext = meta_blob[48:]
                meta_payload = json.loads(meta_aesgcm.decrypt(meta_nonce, meta_ciphertext, aad).decode("utf-8"))
                ts = meta_payload.get("created", 0)
                created_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                break
            except Exception:
                continue
        return {
            "uuid": usb_uuid,
            "version": 3,
            "keyfile_size": KEYFILE_SIZE,
            "created": created_time,
            "hardware_bindings": len(current_fingerprint)}
    except Exception:
        return None
    
def bait():
    return 0

## end