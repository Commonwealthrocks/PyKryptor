## usb_codec.py
## last updated: 10/02/2026 <d/m/y>
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
from colorama import Fore, Style
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEYFILE_SIZE = 512 
HIDDEN_DIR_NAME = ".pykx_usb_codec_data"
DATA_FILE_MARKER = b"\x89\x50\x4B\x58"
LEGACY_KEYFILE_NAME = ".pykryptor_keyfile"
LEGACY_METADATA_NAME = ".pykryptor_usb_key"
FAKE_EXTENSIONS = [".dat", ".tmp", ".sys", ".cab", ".log", ".old", ".bak", ".bin", ".chk", ".dmp", ".cache", ".idx", ".db", ".lock", ".pid", ".swp", ".swo"]
FAKE_NAMES = ["cache", "config", "driver", "system", "temp", "update", "recovery", "data", "index", "metadata", "usr", "var", "spool", "winlog", "setup", "installer", "diagnostic", "telemetry", "sync", "backup", "restore", "journal"]

def _get_comprehensive_usb_fingerprint(usb_path):
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
                            fingerprint["device_serial"] = line.split('=', 1)[1]
                        elif line.startswith("ID_MODEL="):
                            fingerprint["device_model"] = line.split('=', 1)[1]
            except:
                pass
            
        else:
            fingerprint["path_hash"] = hashlib.sha256(usb_path.encode()).hexdigest()[:32]
    except Exception as e:
        pass
    if not fingerprint:
        fingerprint["mount_point"] = usb_path
    return fingerprint

def _fingerprint_to_key_material(fingerprint):
    sorted_items = sorted(fingerprint.items())
    combined = ""
    for key, value in sorted_items:
        combined += f"{key}:{value}|"
    primary_hash = hashlib.sha512(combined.encode("utf-8")).digest()
    secondary_input = primary_hash + combined.encode("utf-8")
    secondary_hash = hashlib.sha512(secondary_input).digest()
    return secondary_hash

def _generate_decoy_filename():
    base = random.choice(FAKE_NAMES)
    if random.random() > 0.5:
        base += hex(random.getrandbits(32))[2:]
    ext = random.choice(FAKE_EXTENSIONS)
    return f"{base}{ext}"
def _generate_realistic_decoy_content(size):
    content = bytearray()
    if random.random() > 0.5:
        header = struct.pack("<4sIIII", 
                           random.choice([b"CFG\x00", b"DAT\x00", b"IDX\x00", b"LOG\x00"]),
                           random.randint(1, 100),
                           random.randint(0, 0xFFFFFFFF),
                           size,
                           random.randint(0, 0xFF))
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

def setup_usb_key(usb_path):
    try:
        fingerprint = _get_comprehensive_usb_fingerprint(usb_path)
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
        encryption_key_material = _fingerprint_to_key_material(fingerprint)
        encryption_key = encryption_key_material[:32]
        hmac_key = encryption_key_material[32:64]
        aesgcm = AESGCM(encryption_key)
        nonce = os.urandom(12)
        aad = json.dumps(fingerprint, sort_keys=True).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, random_key_data, aad)
        package = DATA_FILE_MARKER + nonce + ciphertext
        mac = hmac.new(hmac_key, package, hashlib.sha512).digest()[:32]
        real_filename = _generate_decoy_filename()
        real_file_path = os.path.join(data_dir, real_filename)
        with open(real_file_path, "wb") as f:
            f.write(DATA_FILE_MARKER)
            f.write(mac)
            f.write(nonce)
            f.write(ciphertext)
        _set_file_hidden(real_file_path)
        metadata = {
            "version": 2,
            "real_file": real_filename,
            "fingerprint": fingerprint,
            "created": time.time()}
        metadata_path = os.path.join(data_dir, "metadata.dat")
        with open(metadata_path, "w") as f:
            json.dump(metadata, f)
        _set_file_hidden(metadata_path)
        try:
            num_decoys = random.randint(15, 25)
            for _ in range(num_decoys):
                decoy_filename = _generate_decoy_filename()
                if decoy_filename == real_filename:
                    continue
                decoy_path = os.path.join(data_dir, decoy_filename)
                size = random.randint(128, 8192)
                content = _generate_realistic_decoy_content(size)
                with open(decoy_path, "wb") as f:
                    f.write(content)
                _set_file_hidden(decoy_path)
        except Exception:
            pass
        usb_key_hash = hashlib.sha256(random_key_data).digest()
        return usb_key_hash, usb_uuid
    except Exception as e:
        raise ValueError(f"Failed to setup USB key: {str(e)}")

def get_usb_key(usb_path):
    try:
        data_dir = os.path.join(usb_path, HIDDEN_DIR_NAME)
        metadata_path = os.path.join(data_dir, "metadata.dat")
        if not os.path.exists(metadata_path):
            raise ValueError("USB key data not found (not initialized or corrupted).")
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        real_filename = metadata.get("real_file")
        stored_fingerprint = metadata.get("fingerprint", {})
        if not real_filename:
            raise ValueError("USB key metadata corrupted.")
        real_file_path = os.path.join(data_dir, real_filename)
        if not os.path.exists(real_file_path):
            raise ValueError("USB key file not found (may have been deleted).")
        current_fingerprint = _get_comprehensive_usb_fingerprint(usb_path)
        if not current_fingerprint:
            raise ValueError("Could not read USB hardware identifiers.")
        matching_fields = 0
        total_fields = 0
        for key in stored_fingerprint:
            if key in current_fingerprint:
                total_fields += 1
                if stored_fingerprint[key] == current_fingerprint[key]:
                    matching_fields += 1
        if total_fields == 0 or (matching_fields / total_fields) < 0.75:
            raise ValueError("Hardware fingerprint mismatch; this USB-codec does not belong to this specific drive.")
        encryption_key_material = _fingerprint_to_key_material(stored_fingerprint)
        encryption_key = encryption_key_material[:32]
        hmac_key = encryption_key_material[32:64]
        with open(real_file_path, "rb") as f:
            marker = f.read(4)
            if marker != DATA_FILE_MARKER:
                raise ValueError("Invalid key file format.")
            stored_mac = f.read(32)
            nonce = f.read(12)
            ciphertext = f.read()
        package = marker + nonce + ciphertext
        computed_mac = hmac.new(hmac_key, package, hashlib.sha512).digest()[:32]
        if not hmac.compare_digest(stored_mac, computed_mac):
            raise ValueError("Key file integrity check failed; possible tampering detected.")
        aesgcm = AESGCM(encryption_key)
        aad = json.dumps(stored_fingerprint, sort_keys=True).encode("utf-8")
        try:
            raw_key_data = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception:
            raise ValueError("Decryption failed; hardware fingerprint mismatch.")
        
        if len(raw_key_data) != KEYFILE_SIZE:
            raise ValueError("Decrypted keyfile has incorrect size.")
        usb_uuid = stored_fingerprint.get("serial_number") or \
                   stored_fingerprint.get("uuid") or \
                   stored_fingerprint.get("disk_serial") or \
                   stored_fingerprint.get("path_hash") or \
                   hashlib.sha256(usb_path.encode()).hexdigest()[:16]
        usb_key_hash = hashlib.sha256(raw_key_data).digest()
        return usb_key_hash, usb_uuid
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
    metadata_path = os.path.join(usb_path, HIDDEN_DIR_NAME, "metadata.dat")
    return os.path.exists(metadata_path)

def get_usb_key_info(usb_path):
    try:
        metadata_path = os.path.join(usb_path, HIDDEN_DIR_NAME, "metadata.dat")
        if not os.path.exists(metadata_path):
            return None
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        fingerprint = metadata.get("fingerprint", {})
        created_timestamp = metadata.get("created", 0)
        usb_uuid = fingerprint.get("serial_number") or \
                   fingerprint.get("uuid") or \
                   fingerprint.get("disk_serial") or \
                   "Unknown"
        created_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created_timestamp))
        return {
            "uuid": usb_uuid,
            "version": metadata.get("version", 2),
            "keyfile_size": KEYFILE_SIZE,
            "created": created_time,
            "hardware_bindings": len(fingerprint)}
    except:
        return None

## end