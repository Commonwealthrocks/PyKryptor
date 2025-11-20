## usb_codec.py
## last updated: 19/11/2025 <d/m/y>
## p-y-k-x
import os
import sys
import json
import hashlib
import string
import time
import ctypes
from colorama import Fore, Style

KEYFILE_SIZE = 256
KEYFILE_NAME = ".pykryptor_keyfile"
METADATA_NAME = ".pykryptor_usb_key"

def get_usb_uuid(usb_path):
    try:
        if sys.platform == "win32":
            import win32api
            volume_info = win32api.GetVolumeInformation(usb_path)
            usb_serial = volume_info[1]
            return str(usb_serial)
        elif sys.platform.startswith("linux"):
            import subprocess
            result = subprocess.run(
                ["blkid", "-s", "UUID", "-o", "value", usb_path],
                capture_output=True,
                text=True)
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        else:
            return hashlib.sha256(usb_path.encode()).hexdigest()[:16]
    except Exception as e:
        print(Fore.RED + f"[DEV PRINT] Failed to get USB UUID: {e}" + Style.RESET_ALL)
        return None

def setup_usb_key(usb_path, keyfile_size=KEYFILE_SIZE):
    try:
        usb_uuid = get_usb_uuid(usb_path)
        if not usb_uuid:
            raise ValueError("Could not read USB hardware UUID")
        random_keyfile = os.urandom(keyfile_size)
        usb_key_data = {
            "pykryptor_usb_key": True,
            "version": 2,
            "usb_uuid": usb_uuid,
            "keyfile_size": keyfile_size,
            "created": time.time()}
        metadata_path = os.path.join(usb_path, METADATA_NAME)
        keyfile_path = os.path.join(usb_path, KEYFILE_NAME)
        with open(metadata_path, "w") as f:
            json.dump(usb_key_data, f, indent=2)
        with open(keyfile_path, "wb") as f:
            f.write(random_keyfile)
        if sys.platform == "win32":
            try:
                ctypes.windll.kernel32.SetFileAttributesW(metadata_path, 2)
                ctypes.windll.kernel32.SetFileAttributesW(keyfile_path, 2)
            except:
                pass
        usb_key = hashlib.sha256(random_keyfile).digest()
        print(Fore.GREEN + f"[DEV PRINT] USB key initialized successfully" + Style.RESET_ALL)
        print(Fore.GREEN + f"[DEV PRINT] UUID: {usb_uuid}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[DEV PRINT] Keyfile size: {keyfile_size} bytes" + Style.RESET_ALL)
        return usb_key, usb_uuid
    except Exception as e:
        raise ValueError(f"Failed to setup USB key: {str(e)}")

def get_usb_key(usb_path):
    try:
        metadata_path = os.path.join(usb_path, METADATA_NAME)
        keyfile_path = os.path.join(usb_path, KEYFILE_NAME)
        if not os.path.exists(metadata_path):
            raise ValueError("This USB is not initialized as a PyKryptor key device")
        if not os.path.exists(keyfile_path):
            raise ValueError("USB keyfile is missing")
        with open(metadata_path, "r") as f:
            data = json.load(f)
        if not data.get("pykryptor_usb_key"):
            raise ValueError("Invalid PyKryptor USB key file")
        current_uuid = get_usb_uuid(usb_path)
        if not current_uuid:
            raise ValueError("Could not read USB UUID")
        if current_uuid != data["usb_uuid"]:
            raise ValueError("Wrong USB! This is not the original key USB.\n"
                           f"Expected UUID: {data['usb_uuid']}\n"
                           f"Found UUID: {current_uuid}")
        keyfile_size = data.get("keyfile_size", KEYFILE_SIZE)
        with open(keyfile_path, "rb") as f:
            keyfile_data = f.read()
        if len(keyfile_data) != keyfile_size:
            raise ValueError(f"Keyfile size mismatch: expected {keyfile_size}, got {len(keyfile_data)}")
        usb_key = hashlib.sha256(keyfile_data).digest()
        return usb_key, data["usb_uuid"]
    except FileNotFoundError:
        raise ValueError("This USB is not initialized as a PyKryptor key device")
    except json.JSONDecodeError:
        raise ValueError("USB key file is corrupted")
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
    except Exception as e:
        print(Fore.RED + f"[DEV PRINT] Error listing USB drives: {e}" + Style.RESET_ALL)

    return usb_drives

def is_usb_key_initialized(usb_path):
    metadata_path = os.path.join(usb_path, METADATA_NAME)
    keyfile_path = os.path.join(usb_path, KEYFILE_NAME)
    return os.path.exists(metadata_path) and os.path.exists(keyfile_path)

def get_usb_key_info(usb_path):
    try:
        metadata_path = os.path.join(usb_path, METADATA_NAME)
        keyfile_path = os.path.join(usb_path, KEYFILE_NAME)
        if not os.path.exists(metadata_path):
            return None
        with open(metadata_path, "r") as f:
            data = json.load(f)
        created_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data.get("created", 0)))
        keyfile_size = os.path.getsize(keyfile_path) if os.path.exists(keyfile_path) else 0
        return {
            "uuid": data.get("usb_uuid", "Unknown"),
            "version": data.get("version", 1),
            "keyfile_size": keyfile_size,
            "created": created_time}
    except:
        return None

## end