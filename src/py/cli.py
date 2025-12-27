## cli.py
## last updated: 27/12/2025 <d/m/y>
## p-y-k-x
import os
import sys
import json
import argparse
import struct
from pathlib import Path
from core import CryptoWorker, BatchProcessorThread, CHUNK_SIZE
from core import ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM, MAGIC_NUMBER, FLAG_USB_KEY
from colorama import Fore, Style
try:
    from argon2 import PasswordHasher
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
try:
    from usb_codec import list_usb_drives, setup_usb_key, is_usb_key_initialized, get_usb_key_info, get_usb_key
    USB_CODEC_AVAILABLE = True
except ImportError:
    USB_CODEC_AVAILABLE = False

class CLIState:
    def __init__(self):
        self.operation = None
        self.files = []
        self.password = None
        self.custom_ext = "dat"
        self.output_dir = ""
        self.new_name_type = "keep"
        self.chunk_size_mb = 3
        self.kdf_iterations = 1000000
        self.pbkdf2_hash = "sha256"
        self.secure_clear = False
        self.add_recovery_data = False
        self.compression_level = "none"
        self.archive_mode = False
        self.aead_algorithm = "aes-gcm"
        self.use_argon2 = False
        self.argon2_time_cost = ARGON2_TIME_COST
        self.argon2_memory_cost = ARGON2_MEMORY_COST
        self.argon2_parallelism = ARGON2_PARALLELISM
        self.usb_key_path = None
        self.archive_name = None
        self.compression_detection_mode = "legacy"
        self.entropy_threshold = 7.5

    def save_to_file(self, filepath):
        config = {
            "custom_ext": self.custom_ext,
            "output_dir": self.output_dir,
            "new_name_type": self.new_name_type,
            "chunk_size_mb": self.chunk_size_mb,
            "kdf_iterations": self.kdf_iterations,
            "pbkdf2_hash": self.pbkdf2_hash,
            "secure_clear": self.secure_clear,
            "add_recovery_data": self.add_recovery_data,
            "compression_level": self.compression_level,
            "archive_mode": self.archive_mode,
            "aead_algorithm": self.aead_algorithm,
            "use_argon2": self.use_argon2,
            "argon2_time_cost": self.argon2_time_cost,
            "argon2_memory_cost": self.argon2_memory_cost,
            "argon2_parallelism": self.argon2_parallelism,
            "archive_name": self.archive_name,
            "compression_detection": self.compression_detection_mode,
            "entropy_threshold": self.entropy_threshold}
        try:
            with open(filepath, "w") as f:
                json.dump(config, f, indent=4)
            print(f"{Fore.GREEN}[OK] State saved to '{filepath}'{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to save state: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def load_from_file(self, filepath):
        try:
            with open(filepath, "r") as f:
                config = json.load(f)
                self.custom_ext = config.get("custom_ext", "dat")
                self.output_dir = config.get("output_dir", "")
                self.new_name_type = config.get("new_name_type", "keep")
                self.chunk_size_mb = config.get("chunk_size_mb", 3)
                self.kdf_iterations = config.get("kdf_iterations", 1000000)
                self.pbkdf2_hash = config.get("pbkdf2_hash", "sha256")
                self.secure_clear = config.get("secure_clear", False)
                self.add_recovery_data = config.get("add_recovery_data", False)
                self.compression_level = config.get("compression_level", "none")
                self.archive_mode = config.get("archive_mode", False)
                self.aead_algorithm = config.get("aead_algorithm", "aes-gcm")
                self.use_argon2 = config.get("use_argon2", False)
                self.argon2_time_cost = config.get("argon2_time_cost", ARGON2_TIME_COST)
                self.argon2_memory_cost = config.get("argon2_memory_cost", ARGON2_MEMORY_COST)
                self.argon2_parallelism = config.get("argon2_parallelism", ARGON2_PARALLELISM)
                self.archive_name = config.get("archive_name", None)
                self.compression_detection_mode = config.get("compression_detection", "legacy")
                self.entropy_threshold = config.get("entropy_threshold", 7.5)
            print(f"{Fore.GREEN}[OK] State loaded from '{filepath}'{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to load state: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def resolve_file_path(self, filepath):
        if filepath.startswith("."):
            return os.path.join(os.getcwd(), filepath.lstrip(".").lstrip("/\\"))
        return filepath

class PyKryptorCLI:
    def __init__(self):
        self.state = CLIState()
        self.worker = None

    def parse_args(self):
        parser = argparse.ArgumentParser(
            description="PyKryptor - CLI mode",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  pykryptor -d -p "password" -f ./encrypted.dat
  pykryptor -ss state.json -e -p "test" --compression best --archive
  pykryptor -ls state.json -d -p "test" -f ./file.dat
  pykryptor -e -p "pass" -f ./a.txt ./b.txt -o ./output/
  pykryptor -e -p "pass" -f ./file.txt --usb-key E:\\
  pykryptor --usb-list
  pykryptor --usb-setup E:\\
  pykryptor -e -p "pass" -f ./a.txt ./b.txt --archive --archive-name myarchive.dat
            """)
        op_group = parser.add_mutually_exclusive_group(required=False)
        op_group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt files")
        op_group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt files")
        parser.add_argument("-p", "--password", help="Encryption/decryption password")
        parser.add_argument("-f", "--files", nargs="+", help="File(s) to process (use . prefix for relative paths)")
        parser.add_argument("-o", "--output", default="", help="Output directory")
        parser.add_argument("--ext", default="dat", help="Custom file extension (default: dat)")
        parser.add_argument("--name-type", choices=["keep", "hash", "base64"], default="keep", help="Output filename type (default: keep)")
        parser.add_argument("--compression", choices=["none", "normal", "best", "ultrakill", "[L] ultrakill"], default="none", help="Compression level (default: none)")
        parser.add_argument("--aead", choices=["aes-gcm", "chacha20-poly1305"], default="aes-gcm", help="AEAD algorithm (default: aes-gcm)")
        parser.add_argument("--use-argon2", action="store_true", help="Use Argon2ID instead of PBKDF2")
        parser.add_argument("--kdf-iterations", type=int, default=1000000, help="PBKDF2 iterations (default: 1000000)")
        parser.add_argument("--pbkdf2-hash", choices=["sha256", "sha512"], default="sha256", help="PBKDF2 hash type (default: sha256)")
        parser.add_argument("--argon2-time", type=int, default=ARGON2_TIME_COST, help=f"Argon2 time cost (default: {ARGON2_TIME_COST})")
        parser.add_argument("--argon2-memory", type=int, default=ARGON2_MEMORY_COST, help=f"Argon2 memory cost in KB (default: {ARGON2_MEMORY_COST})")
        parser.add_argument("--argon2-parallelism", type=int, default=ARGON2_PARALLELISM, help=f"Argon2 parallelism (default: {ARGON2_PARALLELISM})")
        parser.add_argument("--secure-clear", action="store_true", help="Securely clear password from memory")
        parser.add_argument("--recovery", action="store_true", help="Add recovery data (Reedsolo)")
        parser.add_argument("--archive", action="store_true", help="Archive mode for multiple files")
        parser.add_argument("--archive-name", help="Archive filename (default: archive.{ext})")
        parser.add_argument("--chunk-size", type=int, default=3, help="Chunk size in MB (default: 3)")
        parser.add_argument("--detection-mode", choices=["legacy", "magic", "entropy", "magic+entropy"], default="legacy", help="Compression detection mode (default: legacy)")
        parser.add_argument("--entropy-threshold", type=float, default=7.5, help="Entropy threshold for compression detection (default: 7.5, range: 6.0-8.0)")
        parser.add_argument("--usb-key", help="USB drive path for USB-codec (e.g., E:\\)")
        parser.add_argument("--usb-list", action="store_true", help="List available USB drives")
        parser.add_argument("--usb-setup", help="Setup USB drive as USB-codec key (e.g., --usb-setup E:\\)")
        parser.add_argument("-ss", "--save-state", help="Save current settings to state file")
        parser.add_argument("-ls", "--load-state", help="Load settings from state file")
        return parser.parse_args()

    def apply_args(self, args):
        if args.load_state:
            self.state.load_from_file(args.load_state)
        if args.encrypt or args.decrypt:
            self.state.operation = "encrypt" if args.encrypt else "decrypt"
        self.state.password = args.password
        self.state.files = [self.state.resolve_file_path(f) for f in args.files] if args.files else []
        self.state.output_dir = args.output
        self.state.custom_ext = args.ext
        self.state.new_name_type = args.name_type
        self.state.compression_level = args.compression
        self.state.aead_algorithm = args.aead
        self.state.use_argon2 = args.use_argon2 and ARGON2_AVAILABLE
        self.state.kdf_iterations = args.kdf_iterations
        self.state.pbkdf2_hash = args.pbkdf2_hash
        self.state.argon2_time_cost = args.argon2_time
        self.state.argon2_memory_cost = args.argon2_memory
        self.state.argon2_parallelism = args.argon2_parallelism
        self.state.secure_clear = args.secure_clear
        self.state.add_recovery_data = args.recovery
        self.state.archive_mode = args.archive
        self.state.chunk_size_mb = args.chunk_size
        self.state.compression_detection_mode = args.detection_mode
        self.state.entropy_threshold = max(6.0, min(8.0, args.entropy_threshold))
        self.state.usb_key_path = args.usb_key
        self.state.archive_name = args.archive_name
        if args.save_state:
            self.state.save_to_file(args.save_state)

    def check_usb_requirement(self, file_path):
        try:
            with open(file_path, "rb") as f:
                magic = f.read(len(MAGIC_NUMBER))
                if magic == MAGIC_NUMBER or magic == b"PYLI\x00":
                    f.seek(len(MAGIC_NUMBER) + 2)
                    flags = struct.unpack("!B", f.read(1))[0]
                    if (flags & FLAG_USB_KEY) != 0:
                        if not self.state.usb_key_path:
                            print(f"{Fore.YELLOW}[WARN] This file requires a USB-codec key.{Style.RESET_ALL}")
                            if not USB_CODEC_AVAILABLE:
                                print(f"{Fore.RED}[ERROR] USB-codec not available. Install required dependencies.{Style.RESET_ALL}")
                                sys.exit(1)
                            print(f"{Fore.CYAN}Available USB drives:{Style.RESET_ALL}")
                            try:
                                drives = list_usb_drives()
                                initialized_drives = []
                                for drive in drives:
                                    initialized = is_usb_key_initialized(drive)
                                    status = "✓ Initialized" if initialized else "  Not initialized"
                                    print(f"  {drive} - {status}")
                                    if initialized:
                                        initialized_drives.append(drive)
                                if not initialized_drives:
                                    print(f"{Fore.RED}[ERROR] No initialized USB-codec keys found. Please setup a USB key first.{Style.RESET_ALL}")
                                    sys.exit(1)
                                if len(initialized_drives) == 1:
                                    self.state.usb_key_path = initialized_drives[0]
                                    print(f"{Fore.GREEN}[OK] Auto-selected USB: {initialized_drives[0]}{Style.RESET_ALL}")
                                else:
                                    print(f"{Fore.YELLOW}[WARN] Multiple USB keys found. Please specify with --usb-key{Style.RESET_ALL}")
                                    sys.exit(1)
                            except Exception as e:
                                print(f"{Fore.RED}[ERROR] Failed to list USB drives: {e}{Style.RESET_ALL}")
                                sys.exit(1)
                        else:
                            if not is_usb_key_initialized(self.state.usb_key_path):
                                print(f"{Fore.RED}[ERROR] USB drive at {self.state.usb_key_path} is not initialized as USB-codec.{Style.RESET_ALL}")
                                sys.exit(1)
        except Exception:
            pass

    def validate_args(self):
        if not self.state.files:
            print(f"{Fore.RED}[ERROR] No files specified{Style.RESET_ALL}")
            sys.exit(1)
        if not self.state.password:
            print(f"{Fore.RED}[ERROR] No password specified{Style.RESET_ALL}")
            sys.exit(1)
        if not self.state.operation:
            print(f"{Fore.RED}[ERROR] No operation specified (use -e or -d){Style.RESET_ALL}")
            sys.exit(1)
        for file_path in self.state.files:
            if not os.path.exists(file_path):
                print(f"{Fore.RED}[ERROR] File not found: {file_path}{Style.RESET_ALL}")
                sys.exit(1)
        if self.state.output_dir and not os.path.exists(self.state.output_dir):
            print(f"{Fore.YELLOW}[WARN] Output directory doesn't exist, creating: {self.state.output_dir}{Style.RESET_ALL}")
            try:
                os.makedirs(self.state.output_dir, exist_ok=True)
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to create output directory: {e}{Style.RESET_ALL}")
                sys.exit(1)
        if self.state.operation == "decrypt" and self.state.files:
            self.check_usb_requirement(self.state.files[0])
        if self.state.usb_key_path:
            if not os.path.exists(self.state.usb_key_path):
                print(f"{Fore.RED}[ERROR] USB drive path does not exist: {self.state.usb_key_path}{Style.RESET_ALL}")
                sys.exit(1)
            if not is_usb_key_initialized(self.state.usb_key_path):
                print(f"{Fore.RED}[ERROR] USB drive at {self.state.usb_key_path} is not initialized as USB-codec.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Use --usb-setup {self.state.usb_key_path} to initialize it.{Style.RESET_ALL}")
                sys.exit(1)

    def progress_callback(self, progress):
        bar_length = 40
        filled = int(bar_length * progress / 100)
        bar = "█" * filled + "░" * (bar_length - filled)
        print(f"\r[{bar}] {progress:.1f}%", end="", flush=True)

    def process_files(self):
        if self.state.archive_mode and len(self.state.files) > 1:
            print(f"{Fore.CYAN}[INFO] Processing archive with {len(self.state.files)} files...{Style.RESET_ALL}")
            try:
                out_path = None
                if self.state.output_dir:
                    archive_name = self.state.archive_name or f"archive.{self.state.custom_ext}"
                    out_path = os.path.join(self.state.output_dir, archive_name)
                else:
                    archive_name = self.state.archive_name or f"archive.{self.state.custom_ext}"
                    out_path = os.path.join(os.path.dirname(self.state.files[0]), archive_name)
                def progress_callback(progress):
                    bar_length = 40
                    filled = int(bar_length * progress / 100)
                    bar = "█" * filled + "░" * (bar_length - filled)
                    print(f"\r[{bar}] {progress:.1f}%", end="", flush=True)
                worker = CryptoWorker(
                    operation=self.state.operation,
                    in_path=self.state.files[0] if self.state.operation == "decrypt" else None,
                    out_path=out_path,
                    password=self.state.password,
                    custom_ext=self.state.custom_ext,
                    new_name_type=self.state.new_name_type,
                    output_dir=self.state.output_dir,
                    chunk_size=self.state.chunk_size_mb * 1024 * 1024,
                    kdf_iterations=self.state.kdf_iterations,
                    secure_clear=self.state.secure_clear,
                    add_recovery_data=self.state.add_recovery_data,
                    compression_level=self.state.compression_level,
                    archive_mode=True,
                    use_argon2=self.state.use_argon2,
                    argon2_time_cost=self.state.argon2_time_cost,
                    argon2_memory_cost=self.state.argon2_memory_cost,
                    argon2_parallelism=self.state.argon2_parallelism,
                    aead_algorithm=self.state.aead_algorithm,
                    pbkdf2_hash=self.state.pbkdf2_hash,
                    usb_key_path=self.state.usb_key_path,
                    compression_detection_mode=self.state.compression_detection_mode,
                    entropy_threshold=self.state.entropy_threshold,
                    progress_callback=progress_callback)
                if self.state.operation == "encrypt":
                    worker._file_list = self.state.files
                    worker.encrypt_file()
                else:
                    worker.decrypt_file()
                print(f"\n{Fore.GREEN}[OK] Archive processed successfully!{Style.RESET_ALL}")
            except Exception as e:
                print(f"\n{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}")
                sys.exit(1)
        else:
            total = len(self.state.files)
            for i, file_path in enumerate(self.state.files):
                print(f"\n{Fore.CYAN}[{i+1}/{total}] Processing: {os.path.basename(file_path)}{Style.RESET_ALL}")
                try:
                    out_path = file_path
                    if self.state.output_dir:
                        out_path = os.path.join(self.state.output_dir, os.path.basename(file_path))
                    worker = CryptoWorker(
                        operation=self.state.operation,
                        in_path=file_path,
                        out_path=out_path,
                        password=self.state.password,
                        custom_ext=self.state.custom_ext,
                        new_name_type=self.state.new_name_type,
                        output_dir=self.state.output_dir,
                        chunk_size=self.state.chunk_size_mb * 1024 * 1024,
                        kdf_iterations=self.state.kdf_iterations,
                        secure_clear=self.state.secure_clear,
                        add_recovery_data=self.state.add_recovery_data,
                        compression_level=self.state.compression_level,
                        archive_mode=False,
                        use_argon2=self.state.use_argon2,
                        argon2_time_cost=self.state.argon2_time_cost,
                        argon2_memory_cost=self.state.argon2_memory_cost,
                        argon2_parallelism=self.state.argon2_parallelism,
                        aead_algorithm=self.state.aead_algorithm,
                        pbkdf2_hash=self.state.pbkdf2_hash,
                        usb_key_path=self.state.usb_key_path,
                        compression_detection_mode=self.state.compression_detection_mode,
                        entropy_threshold=self.state.entropy_threshold,
                        progress_callback=self.progress_callback)
                    if self.state.operation == "encrypt":
                        worker.encrypt_file()
                    else:
                        worker.decrypt_file()
                    print(f"\n{Fore.GREEN}[OK] Completed: {os.path.basename(file_path)}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"\n{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}")
                    sys.exit(1)
            print(f"\n{Fore.GREEN}[OK] All files processed successfully!{Style.RESET_ALL}")

    def handle_usb_operations(self, args):
        if args.usb_list:
            if not USB_CODEC_AVAILABLE:
                print(f"{Fore.RED}[ERROR] USB-codec not available. Install required dependencies.{Style.RESET_ALL}")
                sys.exit(1)
            print(f"{Fore.CYAN}Available USB drives:{Style.RESET_ALL}")
            try:
                drives = list_usb_drives()
                if not drives:
                    print(f"{Fore.YELLOW}No USB drives detected.{Style.RESET_ALL}")
                    return
                for drive in drives:
                    initialized = is_usb_key_initialized(drive)
                    if initialized:
                        try:
                            info = get_usb_key_info(drive)
                            print(f"  {drive} - {Fore.GREEN}✓ Initialized{Style.RESET_ALL} (UUID: {info['uuid'][:12]}...)")
                        except:
                            print(f"  {drive} - {Fore.GREEN}✓ Initialized{Style.RESET_ALL}")
                    else:
                        print(f"  {drive} - {Fore.YELLOW}Not initialized{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to list USB drives: {e}{Style.RESET_ALL}")
                sys.exit(1)
            return True
        
        if args.usb_setup:
            if not USB_CODEC_AVAILABLE:
                print(f"{Fore.RED}[ERROR] USB-codec not available. Install required dependencies.{Style.RESET_ALL}")
                sys.exit(1)
            usb_path = args.usb_setup
            if not os.path.exists(usb_path):
                print(f"{Fore.RED}[ERROR] USB drive path does not exist: {usb_path}{Style.RESET_ALL}")
                sys.exit(1)
            if is_usb_key_initialized(usb_path):
                print(f"{Fore.YELLOW}[WARN] USB drive at {usb_path} is already initialized.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}If you want to reinitialize, manually delete the key files first.{Style.RESET_ALL}")
                sys.exit(1)
            try:
                print(f"{Fore.CYAN}Setting up USB-codec on {usb_path}...{Style.RESET_ALL}")
                usb_key, uuid = setup_usb_key(usb_path)
                print(f"{Fore.GREEN}[OK] USB-codec initialized successfully!{Style.RESET_ALL}")
                print(f"{Fore.CYAN}UUID: {uuid}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Keep this USB safe; you'll need it to decrypt files encrypted with it.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to setup USB-codec: {e}{Style.RESET_ALL}")
                sys.exit(1)
            return True
        
        return False

    def run(self):
        try:
            args = self.parse_args()
            if self.handle_usb_operations(args):
                return
            if not args.encrypt and not args.decrypt:
                print(f"{Fore.RED}[ERROR] Must specify either -e/--encrypt or -d/--decrypt{Style.RESET_ALL}")
                sys.exit(1)
            if not args.password:
                print(f"{Fore.RED}[ERROR] Password required (use -p/--password){Style.RESET_ALL}")
                sys.exit(1)
            if not args.files:
                print(f"{Fore.RED}[ERROR] Files required (use -f/--files){Style.RESET_ALL}")
                sys.exit(1)
            self.apply_args(args)
            self.validate_args()
            self.process_files()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[CANCEL] Operation interrupted by user{Style.RESET_ALL}")
            sys.exit(130)
        except Exception as e:
            print(f"{Fore.RED}[FATAL] {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

def main():
    cli = PyKryptorCLI()
    cli.run()

if __name__ == "__main__":
    main()

## end