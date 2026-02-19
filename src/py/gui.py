## gui.py
## last updated: 19/02/2026 <d/m/y>
## p-y-k-x
import sys
import os
import ctypes
import shutil
import glob
import tempfile
import json
import struct
import time
import importlib
import contextlib
import io
from colorama import *

if sys.platform == "win32":
    try:
        ctypes.windll.kernel32.FreeConsole()
        ctypes.windll.kernel32.AllocConsole()
        sys.stdout = open("CONOUT$", "w")
        sys.stderr = open("CONOUT$", "w")
        ctypes.windll.kernel32.SetConsoleTitleW("PyKryptor splash screen thingy whatever")
    except Exception:
        pass
init(autoreset=True)
print(Fore.CYAN + Style.BRIGHT + r"""
  ____        _  __                  _
 |  _ \ _   _| |/ /_ __ _   _ _ __  | |_ ___  _ __
 | |_) | | | | ' /| '__| | | | '_ \ | __/ _ \| '__|
 |  __/| |_| | . \| |  | |_| | |_) || || (_) | |
 |_|    \__, |_|\_\_|   \__, | .__/  \__\___/|_|
        |___/           |___/|_|
""" + Style.RESET_ALL)
print(Fore.GREEN + "[INFO] Initializing PyKryptor...")
print(Fore.GREEN + "[INFO] This MIGHT (will) take a bit...\n" + Style.RESET_ALL)

class ImportAss:
    def __enter__(self):
        self._stdout = sys.stdout
        self._stderr = sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout = self._stdout
        sys.stderr = self._stderr

def draw_progress(current, total, label=""):
    width = 40
    percent = int((current / total) * 100)
    filled = int(width * current / total)
    bar = "#" * filled + " " * (width - filled)
    sys.stdout.write(f"\r{Fore.YELLOW}{label:<35} " f"[{bar}] {percent}%")
sys.stdout.flush()

def smooth_advance(start, end, total, label):
    i2 = 10
    for i in range(i2):
        interpolated = start + (end - start) * (i + 1) / i2
        draw_progress(interpolated, total, label)
        time.sleep(0.03)

stages = [
    ("Loading Qtcore...", lambda: importlib.import_module("PySide6.QtCore")),
    ("Loading Qtwidgets...", lambda: importlib.import_module("PySide6.QtWidgets")),
    ("Loading QtGUI...", lambda: importlib.import_module("PySide6.QtGui")),
    ("Loading cryptowork...", lambda: importlib.import_module("core")),
    ("Loading external GUI...", lambda: importlib.import_module("outs")),
    ("Loading stylez...", lambda: importlib.import_module("stylez")),
    ("Loading sound effects...", lambda: importlib.import_module("sfx")),
    ("Loading C libraries...", lambda: importlib.import_module("c_base")),
    ("Checking Argon2ID...", lambda: importlib.import_module("argon2")),
    ("Checking password strenght meter...", lambda: importlib.import_module("zxcvbn")),]
total_stages = len(stages)
for index, (label, loader) in enumerate(stages, start=1):
    try:
        with ImportAss():
            loader()
    except ImportError:
        pass
    smooth_advance(index - 1, index, total_stages, label)
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *
from PySide6.QtCore import Signal as pyqtSignal
try:
    from argon2 import PasswordHasher
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

from core import BatchProcessorThread
from stylez import STYLE_SHEET
from outs import ProgressDialog, CustomDialog, ErrorExportDialog, DebugConsole, CustomArgon2Dialog, ArchiveCreationDialog, USBSetupDialog, USBSelectionDialog, enable_win_dark_mode, KeyfileGeneratorDialog
from sfx import SoundManager
from c_base import isca, check_aes_ni, aes_ni_aval, get_resource_path

print(Fore.CYAN + "\nQuick, wasn't it?\n" + Style.RESET_ALL)

def rm_pycache():
    cache_dirs = glob.glob(os.path.join("**", "__pycache__"), recursive=True)
    direct_cache = get_resource_path(os.path.join("__pycache__"))
    if os.path.isdir(direct_cache):
        cache_dirs.append(direct_cache)
    if not cache_dirs:
        return
    for cache_path in set(cache_dirs):
        try:
            if os.path.exists(cache_path) and os.path.isdir(cache_path):
                shutil.rmtree(cache_path)
        except PermissionError as e:
            print(Fore.RED + f"[DEV PRINT] Cannot remove __pycache__ directory from '{cache_path}'.\n\ne: {e}\n" + Style.RESET_ALL)
        except OSError as e:
            print(Fore.RED + f"[DEV PRINT] Failed to remove __pycache__ from '{cache_path}'.\n\ne: {e}\n" + Style.RESET_ALL)

def is_admin():
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

class QtStream(QObject):
    text_written = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self._buffer = []
        self._target_connected = False

    def write(self, text):
        if not self._target_connected:
            self._buffer.append(text)
        else:
            self.text_written.emit(str(text))

    def flush(self):
        pass

    def connect_target(self, target_slot):
        self.text_written.connect(target_slot)
        self._target_connected = True
        if self._buffer:
            buffered_text = "".join(self._buffer)
            self.text_written.emit(buffered_text)
            self._buffer = []

class PyKryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyKryptor")
        self.setGeometry(100, 100, 500, 420) 
        self.setFixedSize(500, 450)
        self.setStyleSheet(STYLE_SHEET)
        self.setAcceptDrops(True)
        enable_win_dark_mode(self)
        self.files_to_process = []
        self.custom_ext = "dat"
        self.output_dir = ""
        self.new_name_type = "keep"
        self.mute_sfx = False
        self.sfx_volume = 1.0
        self.chunk_size_mb = 3
        self.kdf_iterations = 1000000
        self.pbkdf2_hash = "sha-256"
        self.secure_clear = False
        self.add_recovery_data = False
        self.compression_level = "none"
        self.archive_mode = False
        self.aead_algorithm = "aes-gcm"
        self.use_argon2 = True
        self.argon2_time_cost = 3
        self.argon2_memory_cost = 65536
        self.argon2_parallelism = 4
        self.compression_detection = "legacy"
        self.entropy_threshold = 7.5
        self.batch_processor = None
        self.progress_dialog = None
        self.keyfile_path = None
        self.config_path = self.get_config_path()
        self.sound_manager = SoundManager()
        self.load_settings()
        self.validate_output_dir()
        self.sound_manager.list_available_sounds()
        self.sound_manager.load_sound("success.wav")
        self.sound_manager.load_sound("error.wav")
        self.sound_manager.load_sound("info.wav")
        self.sound_manager.set_volume(self.sfx_volume)
        self.has_aes_ni = check_aes_ni()
        self.is_admin = is_admin()
        self.debug_console = None
        self.init_debug_console()
        main_layout = QVBoxLayout(self)
        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(self.create_main_tab(), "Main")
        self.tab_widget.addTab(self.create_settings_tab(), "Settings")
        self.tab_widget.addTab(self.create_about_tab(), "About")
        main_layout.addWidget(self.tab_widget)
        self.setLayout(main_layout)
        if self.is_admin:
            dialog = CustomDialog("Warning", "You are running PyKryptor with Administrator privileges, due to this some feature's like drag n' drop for Windows will be disabled.\n\nWhy? Yeah I got no fucking clue too.", self)
            dialog.exec() ## can't run sfx here fuck my chud life

    def init_debug_console(self):
        if self.is_admin:
            VER = "1.6"
            self.debug_console = DebugConsole(parent=self)
            print("--- PyKryptor debug console initialized (Administrator) ---")
            print(f"--- Version: {VER} ---")
            print(f"--- Argon2ID available: {ARGON2_AVAILABLE} ---")
            print(f"--- Secure memory C lib loaded: {isca} ---")
            print(f"--- AES-NI C lib loaded: {aes_ni_aval()} ---")
            print(f"--- CPU supports AES-NI: {self.has_aes_ni} ---")

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_0 and event.modifiers() == Qt.AltModifier:
            if self.is_admin and self.debug_console:
                if self.debug_console.isVisible():
                    self.debug_console.hide()
                else:
                    self.debug_console.show()
                event.accept()
                return
        elif event.key() == Qt.Key_K and event.modifiers() == (Qt.ControlModifier | Qt.ShiftModifier):
            self.toggle_authentication_mode()
            event.accept()
            return
        super().keyPressEvent(event)

    def get_config_path(self):
        if sys.platform == "win32":
            return os.path.join(os.environ["APPDATA"], "PyKryptor", "config.json")
        else:
            return os.path.join(os.path.expanduser("~"), ".pykryptor", "config.json")

    def validate_output_dir(self):
        if self.output_dir and not os.path.exists(self.output_dir):
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            if not os.path.exists(desktop_path):
                desktop_path = os.path.expanduser("~")
            self.output_dir = desktop_path
            self.save_settings()
            self.play_warning_sound()
            dialog = CustomDialog("Output directory fix", f"Your output directory was invalid and has been changed to:\n{desktop_path}\n\nThank me later :3", self)
            dialog.exec()

    def load_settings(self):
        try:
            with open(self.config_path, "r") as f:
                config = json.load(f)
                self.custom_ext = config.get("custom_ext", "dat")
                self.output_dir = config.get("output_dir", "")
                self.new_name_type = config.get("new_name_type", "keep")
                self.mute_sfx = config.get("mute_sfx", False)
                self.sfx_volume = config.get("sfx_volume", 1.0)
                self.chunk_size_mb = config.get("chunk_size_mb", 3)
                self.kdf_iterations = config.get("kdf_iterations", 1000000)
                self.pbkdf2_hash = config.get("pbkdf2_hash", "sha-256")
                self.secure_clear = config.get("secure_clear", False)
                self.add_recovery_data = config.get("add_recovery_data", False)
                self.compression_level = config.get("compression_level", "none")
                self.archive_mode = config.get("archive_mode", False)
                self.aead_algorithm = config.get("aead_algorithm", "aes-gcm")
                self.use_argon2 = config.get("use_argon2", False)
                self.argon2_time_cost = config.get("argon2_time_cost", 3)
                self.argon2_memory_cost = config.get("argon2_memory_cost", 65536)
                self.argon2_parallelism = config.get("argon2_parallelism", 4)
                self.compression_detection = config.get("compression_detection", "legacy")
                self.entropy_threshold = config.get("entropy_threshold", 7.5)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        except Exception as e:
            if hasattr(self, "sound_manager"):
                self.sound_manager.play_sound("error.wav")
            dialog = CustomDialog("Oi blyat...", f"Failed to load settings.\n\ne:{e}\n", self)
            dialog.exec()

    def save_settings(self):
        config_dir = os.path.dirname(self.config_path)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        config = {
            "custom_ext": self.custom_ext,
            "output_dir": self.output_dir,
            "new_name_type": self.new_name_type,
            "mute_sfx": self.mute_sfx,
            "sfx_volume": self.sfx_volume,
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
            "compression_detection": self.compression_detection,
            "entropy_threshold": self.entropy_threshold}
        with open(self.config_path, "w") as f:
            json.dump(config, f, indent=4)

    def select_files(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        if file_dialog.exec():
            self.input_path_field.setText("; ".join(file_dialog.selectedFiles()))
            self.files_to_process = file_dialog.selectedFiles()
    
    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            urls = [url.toLocalFile() for url in event.mimeData().urls()]
            valid_files = []
            for path in urls:
                if os.path.isfile(path) or os.path.isdir(path):
                    valid_files.append(path)
            if valid_files:
                self.input_path_field.setText("; ".join(valid_files))
                self.files_to_process = valid_files
            event.acceptProposedAction()
        else:
            super().dropEvent(event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def toggle_password_visibility(self, checked):
        if checked:
            self.password_field.setEchoMode(QLineEdit.Normal)
            icon_path = get_resource_path(os.path.join("img", "hide_pass_img.png"))
            self.peek_button.setIcon(QIcon(icon_path))
        else:
            self.password_field.setEchoMode(QLineEdit.Password)
            icon_path = get_resource_path(os.path.join("img", "show_pass_img.png"))
            self.peek_button.setIcon(QIcon(icon_path))

    def update_password_strength(self, password):
        if not ZXCVBN_AVAILABLE or not self.strength_bar:
            return
        if not password:
            self.strength_bar.setValue(0)
            self.strength_label.setText("Password strength: X")
            self.strength_label.setStyleSheet("color: #888888; font-size: 9pt; margin-top: 2px;")
            return
        if len(password) > 72:
            self.strength_bar.setValue(4)
            self.strength_label.setText("Password strength: Strong")
            self.strength_label.setStyleSheet("color: #44DD44; font-size: 9pt; margin-top: 2px;")
            return
        result = zxcvbn(password)
        score = result["score"]
        colors = ["#FF4444", "#FF8844", "#FFAA44", "#88DD44", "#44DD44"]
        labels = ["Really?", "Weak", "Fair", "Good", "Strong"]
        self.strength_bar.setValue(score)
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #5A5A5A;
                background-color: #3C3C3C;
                border-radius: 3px;
                margin-top: 2px;
            }}
            QProgressBar::chunk {{
                background-color: {colors[score] if score < len(colors) else colors[-1]};
                border-radius: 2px;
            }}""")
        self.strength_label.setText(f"Password strength: {labels[score] if score < len(labels) else labels[-1]}")
        self.strength_label.setStyleSheet(f"color: {colors[score] if score < len(colors) else colors[-1]}; font-size: 9pt; margin-top: 2px;")

    def browse_keyfile(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select keyfile", "", "PyKryptor keyfiles (*.pykx);;All files (*)")
        if file:
            self.keyfile_path = file
            self.keyfile_label.setText(f"Keyfile: {os.path.basename(file)}")
            self.keyfile_label.setToolTip(file)
        else:
            self.keyfile_path = None
            self.keyfile_label.setText("No Keyfile selected")

    def create_main_tab(self):
        main_tab = QWidget()
        main_layout = QVBoxLayout(main_tab)
        input_group = QGroupBox("Select file(s) or folder (drag n' drop)")
        input_layout = QVBoxLayout()
        self.input_path_field = QLineEdit()
        self.input_path_field.setReadOnly(True)
        self.input_path_field.setPlaceholderText("Drag and drop file(s) or folder here...")
        button_row = QHBoxLayout()
        self.browse_button = QPushButton("Browse")
        icon_path = get_resource_path(os.path.join("img", "browse_img.png"))
        self.browse_button.setIcon(QIcon(icon_path))
        self.browse_button.setIconSize(QSize(20, 20))
        self.browse_button.clicked.connect(self.select_files)
        self.create_archive_button = QPushButton("Create archive")
        icon_path = get_resource_path(os.path.join("img", "create_archive_img.png"))
        self.create_archive_button.setIcon(QIcon(icon_path))
        self.create_archive_button.setIconSize(QSize(20, 20))
        self.create_archive_button.clicked.connect(self.open_archive_creation_dialog)
        button_row.addWidget(self.browse_button)
        button_row.addWidget(self.create_archive_button)
        input_layout.addWidget(self.input_path_field)
        input_layout.addLayout(button_row)
        input_group.setLayout(input_layout)
        password_group = QGroupBox("Encryption / decryption password")
        password_layout = QVBoxLayout()
        password_field_layout = QHBoxLayout()
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.Password)
        self.password_field.setPlaceholderText("Enter password")
        self.peek_button = QPushButton()
        icon_path = get_resource_path(os.path.join("img", "show_pass_img.png"))
        self.peek_button.setIcon(QIcon(icon_path))
        self.peek_button.setIconSize(QSize(32, 32))
        self.peek_button.setFixedSize(50, 25)
        self.peek_button.setCheckable(True)
        self.peek_button.setToolTip("Show / hide password")
        self.peek_button.toggled.connect(self.toggle_password_visibility)
        self.peek_button.setStyleSheet("""
            QPushButton {
                background-color: #4A4A4A;
                border: 1px solid #757575;
                color: #E0E0E0;
                font-size: 9pt;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #555555;
            }
            QPushButton:checked {
                background-color: #3D3D3D;
                border: 1px solid #666666;
            }""")
        password_field_layout.addWidget(self.password_field)
        password_field_layout.addWidget(self.peek_button)
        password_layout.addLayout(password_field_layout)
        if ZXCVBN_AVAILABLE:
            self.strength_bar = QProgressBar()
            self.strength_bar.setRange(0, 4)
            self.strength_bar.setValue(0)
            self.strength_bar.setTextVisible(False)
            self.strength_bar.setFixedHeight(10)
            self.strength_bar.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #5A5A5A;
                    background-color: #3C3C3C;
                    border-radius: 3px;
                    margin-top: 2px;
                }
                QProgressBar::chunk {
                    background-color: #FF4444;
                    border-radius: 2px;
                }""")
            self.strength_label = QLabel("Password strength: N/A")
            self.strength_label.setStyleSheet("color: #888888; font-size: 9pt; margin-top: 2px;")
            self.strength_label.setWordWrap(True)
            password_layout.addWidget(self.strength_bar)
            password_layout.addWidget(self.strength_label)
            self.password_field.textChanged.connect(self.update_password_strength)
        else:
            self.strength_bar = None
            self.strength_label = None
        password_group.setLayout(password_layout)
        self.password_group = password_group
        keyfile_group = QGroupBox("Keyfile selection")
        keyfile_layout = QVBoxLayout()
        keyfile_input_layout = QHBoxLayout()
        self.main_keyfile_path_field = QLineEdit()
        self.main_keyfile_path_field.setPlaceholderText("Select or generate a keyfile...")
        self.main_keyfile_path_field.setReadOnly(True)
        self.main_browse_keyfile_button = QPushButton("Browse")
        self.main_browse_keyfile_button.clicked.connect(self.browse_main_keyfile)
        self.main_generate_keyfile_button = QPushButton("Generate")
        self.main_generate_keyfile_button.clicked.connect(self.generate_main_keyfile)
        keyfile_input_layout.addWidget(self.main_keyfile_path_field)
        keyfile_input_layout.addWidget(self.main_browse_keyfile_button)
        keyfile_input_layout.addWidget(self.main_generate_keyfile_button)
        keyfile_layout.addLayout(keyfile_input_layout)
        keyfile_group.setLayout(keyfile_layout)
        self.keyfile_group = keyfile_group
        self.keyfile_group.setVisible(False)
        self.auth_mode_hint = QLabel("Press CTRL + SHIFT + K to switch to keyfile mode")
        self.auth_mode_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.auth_mode_hint.setStyleSheet("color: #888888; font-size: 8pt; margin-top: 5px;")
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt")
        icon_path = get_resource_path(os.path.join("img", "encrypt_img.png"))
        self.encrypt_button.setIcon(QIcon(icon_path))
        self.encrypt_button.setIconSize(QSize(20, 20))
        self.encrypt_button.clicked.connect(lambda: self.start_operation("encrypt"))
        self.decrypt_button = QPushButton("Decrypt")
        icon_path = get_resource_path(os.path.join("img", "decrypt_img.png"))
        self.decrypt_button.setIcon(QIcon(icon_path))
        self.decrypt_button.setIconSize(QSize(20, 20))
        self.decrypt_button.clicked.connect(lambda: self.start_operation("decrypt"))
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        self.status_label = QLabel("[INFO] Ready.")
        self.status_label.setStyleSheet("color: #7FFF00;")
        main_layout.addWidget(input_group)
        main_layout.addWidget(self.password_group)
        main_layout.addWidget(self.keyfile_group)
        main_layout.addWidget(self.auth_mode_hint)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.status_label)
        main_layout.addStretch()
        return main_tab

    def open_archive_creation_dialog(self):
        current_settings = {
            "archive_name": f"archive.{self.custom_ext}",
            "output_dir": self.output_dir or os.path.join(os.path.expanduser("~"), "Desktop"),
            "aead_algorithm": self.aead_algorithm,
            "use_argon2": self.use_argon2,
            "pbkdf2_hash": self.pbkdf2_hash,
            "kdf_iterations": self.kdf_iterations,
            "argon2_time_cost": self.argon2_time_cost,
            "argon2_memory_cost": self.argon2_memory_cost,
            "argon2_parallelism": self.argon2_parallelism,
            "compression_level": self.compression_level,
            "compression_detection": self.compression_detection,
            "entropy_threshold": self.entropy_threshold,
            "secure_clear": self.secure_clear,
            "add_recovery_data": self.add_recovery_data,
            "chunk_size_mb": self.chunk_size_mb,
            "use_usb_key": False}
        dialog = ArchiveCreationDialog(parent=self, current_settings=current_settings)
        if dialog.exec() == QDialog.Accepted:
            archive_data = dialog.archive_data
            if archive_data:
                self.start_archive_creation(archive_data)

    def start_operation(self, operation):
        files = self.files_to_process
        if not files:
            text = self.input_path_field.text()
            if text:
                files = [f.strip() for f in text.split(";")]
        
        if not files:
            if not self.mute_sfx:
                self.sound_manager.play_sound("error.wav")
            dialog = CustomDialog("Error", "Please select at least one file or folder.", self)
            dialog.exec()
            return
            
        keyfile_path = None
        if self.keyfile_group.isVisible():
            keyfile_path = self.main_keyfile_path_field.text()
            if not keyfile_path or not os.path.exists(keyfile_path):
                self.play_warning_sound()
                dialog = CustomDialog("Warning", "Yo, tis not a vaid keyfile.", self)
                dialog.exec()
                return
            password = ""
        else:
            password = self.password_field.text()
            if not password and operation == "encrypt":
                 self.play_warning_sound()
                 dialog = CustomDialog("Warning", "Please enter a password.", self)
                 dialog.exec()
                 return
            if not password and operation == "decrypt":
                 self.play_warning_sound()
                 dialog = CustomDialog("Warning", "Please enter a password.", self)
                 dialog.exec()
                 return
        usb_key_path = None
        if operation == "decrypt":
            try:
                with open(files[0], "rb") as f:
                    from core import MAGIC_NUMBER, FLAG_USB_KEY
                    magic = f.read(len(MAGIC_NUMBER))
                    if magic == MAGIC_NUMBER or magic == b"PYLI\x00":
                        f.seek(len(MAGIC_NUMBER) + 2)
                        flags = struct.unpack("!B", f.read(1))[0]
                        if (flags & FLAG_USB_KEY) != 0:
                            dialog = USBSelectionDialog(self)
                            if dialog.exec() != QDialog.Accepted or not dialog.usb_path:
                                self.play_warning_sound()
                                self.status_label.setText("[ERROR] USB-codec required but not selected.")
                                return
                            usb_key_path = dialog.usb_path
            except Exception as e:
                pass
        self.status_label.setText(f"[INFO] Starting {operation}...")
        self.encrypt_button.setEnabled(False)
        self.decrypt_button.setEnabled(False)
        self.create_archive_button.setEnabled(False)
        total_bytes = 0
        for file_path in files:
            if os.path.isfile(file_path):
                total_bytes += os.path.getsize(file_path)
        self.progress_dialog = ProgressDialog(f"{operation.capitalize()}ing...", self)
        self.progress_dialog.set_total_bytes(total_bytes)
        self.progress_dialog.canceled.connect(self.cancel_operation)
        self.progress_dialog.show()
        self.batch_processor = BatchProcessorThread(
            operation=operation,
            file_paths=files,
            password=password,
            custom_ext=self.custom_ext,
            output_dir=self.output_dir,
            new_name_type=self.new_name_type,
            chunk_size=self.chunk_size_mb * 1024 * 1024,
            kdf_iterations=self.kdf_iterations,
            secure_clear=self.secure_clear,
            add_recovery_data=self.add_recovery_data,
            compression_level=self.compression_level,
            archive_mode=(self.archive_mode and operation == "encrypt" and len(files) > 1),
            use_argon2=self.use_argon2,
            argon2_time_cost=self.argon2_time_cost,
            argon2_memory_cost=self.argon2_memory_cost,
            argon2_parallelism=self.argon2_parallelism,
            aead_algorithm=self.aead_algorithm,
            pbkdf2_hash=self.pbkdf2_hash,
            compression_detection_mode=self.compression_detection,
            entropy_threshold=self.entropy_threshold,
            keyfile_path=keyfile_path,
            usb_key_path=usb_key_path, 
            parent=self)
        self._current_file_sizes = [os.path.getsize(f) for f in files if os.path.isfile(f)]
        self._current_file_index = 0
        self._bytes_processed_so_far = 0
        
        def update_progress(progress):
            if self._current_file_index < len(self._current_file_sizes):
                current_file_bytes = int((progress / 100.0) * self._current_file_sizes[self._current_file_index])
                total_bytes_processed = self._bytes_processed_so_far + current_file_bytes
                self.progress_dialog.update_bytes_processed(total_bytes_processed)
            self.progress_dialog.update_file_progress(progress)
        
        def update_batch(current, total):
            self._current_file_index = current - 1
            # sum([:0]) == 0, so no special-case needed for the first file
            self._bytes_processed_so_far = sum(self._current_file_sizes[:self._current_file_index])
            self.progress_dialog.update_batch_progress(current, total)
        
        self.batch_processor.batch_progress_updated.connect(update_batch)
        self.batch_processor.status_message.connect(lambda msg: self.progress_dialog.update_file_progress(self.progress_dialog.file_progress_bar.value(), msg.replace("Processing: ", "")))
        self.batch_processor.progress_updated.connect(update_progress)
        self.batch_processor.finished.connect(self.on_archive_creation_finished) 
        self.batch_processor.start()

    def toggle_authentication_mode(self):
        if self.password_group.isVisible():
            self.password_group.setVisible(False)
            self.keyfile_group.setVisible(True)
            self.password_field.clear()
            self.auth_mode_hint.setText("Press CTRL + SHIFT + K to switch to password mode")
            if not self.mute_sfx: self.sound_manager.play_sound("info.wav")
        else:
            self.keyfile_group.setVisible(False)
            self.password_group.setVisible(True)
            self.main_keyfile_path_field.clear()
            self.auth_mode_hint.setText("Press CTRL + SHIFT + K to switch to keyfile mode")
            if not self.mute_sfx: self.sound_manager.play_sound("info.wav")

    def browse_main_keyfile(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select keyfile", "", "PyKryptor keyfiles (*.pykx);;All files (*)")
        if file:
            self.main_keyfile_path_field.setText(file)

    def generate_main_keyfile(self):
        dialog = KeyfileGeneratorDialog(self)
        dialog.exec()


    def cancel_operation(self):
        if self.batch_processor:
            self.batch_processor.cancel()
            self.status_label.setText("[INFO] Canceling operation...")

    def start_archive_creation(self, archive_data): ## ¯\_(ツ)_/¯
        self.status_label.setText("[INFO] Creating archive...")
        self.encrypt_button.setEnabled(False)
        self.decrypt_button.setEnabled(False)
        self.create_archive_button.setEnabled(False)
        total_bytes = 0
        file_sizes = []
        for file_path in archive_data["files"]:
            if os.path.isfile(file_path):
                size = os.path.getsize(file_path)
                total_bytes += size
                file_sizes.append(size)
        self.progress_dialog = ProgressDialog("Creating archive...", self)
        self.progress_dialog.set_total_bytes(total_bytes)
        self.progress_dialog.canceled.connect(self.cancel_operation)
        self.progress_dialog.show()
        output_path = os.path.join(archive_data["output_dir"], archive_data["archive_name"])
        self._archive_file_sizes = file_sizes
        self._archive_file_index = 0
        self._archive_bytes_so_far = 0
        
        def update_archive_progress(progress):
            if total_bytes > 0:
                total_processed = int((progress / 100.0) * total_bytes)
                self.progress_dialog.update_bytes_processed(total_processed)
            self.progress_dialog.update_file_progress(progress)
        
        def update_archive_batch(current, total):
            self._archive_file_index = current - 1
            self._archive_bytes_so_far = sum(self._archive_file_sizes[:self._archive_file_index])
            self.progress_dialog.update_batch_progress(current, total)
        
        self.batch_processor = BatchProcessorThread(
            operation="encrypt",
            file_paths=archive_data["files"],
            password=archive_data["password"],
            custom_ext=os.path.splitext(archive_data["archive_name"])[1].lstrip(".") or self.custom_ext,
            output_dir=archive_data["output_dir"],
            new_name_type="keep",
            chunk_size=archive_data["chunk_size_mb"] * 1024 * 1024,
            kdf_iterations=archive_data["kdf_iterations"],
            secure_clear=archive_data["secure_clear"],
            add_recovery_data=archive_data["add_recovery_data"],
            compression_level=archive_data["compression_level"],
            archive_mode=True,
            use_argon2=archive_data["use_argon2"],
            argon2_time_cost=archive_data["argon2_time_cost"],
            argon2_memory_cost=archive_data["argon2_memory_cost"],
            argon2_parallelism=archive_data["argon2_parallelism"],
            aead_algorithm=archive_data["aead_algorithm"],
            pbkdf2_hash=archive_data["pbkdf2_hash"],
            usb_key_path=archive_data.get("usb_key_path"),
            keyfile_path=archive_data.get("keyfile_path"),
            archive_name=archive_data["archive_name"],
            compression_detection_mode=archive_data.get("compression_detection", "legacy"),
            entropy_threshold=archive_data.get("entropy_threshold", 7.5),
            parent=self)
        self.batch_processor.batch_progress_updated.connect(update_archive_batch)
        self.batch_processor.status_message.connect(lambda msg: self.progress_dialog.update_file_progress(self.progress_dialog.file_progress_bar.value(), msg.replace("Processing: ", "").replace("Creating archive...", "Preparing...")))
        self.batch_processor.progress_updated.connect(update_archive_progress)
        self.batch_processor.finished.connect(self.on_archive_creation_finished)
        self.batch_processor.start()

    def on_archive_creation_finished(self, errors):
        if self.progress_dialog:
            self.progress_dialog.close()
        self.encrypt_button.setEnabled(True)
        self.decrypt_button.setEnabled(True)
        self.create_archive_button.setEnabled(True)
        if errors:
            if not self.mute_sfx:
                self.sound_manager.play_sound("error.wav")
            error_message = "Operation failed:\n" + "\n".join(errors)
            self.status_label.setText("[ERROR] Operation failed.")
            dialog = ErrorExportDialog("Operation failed", error_message, errors, self)
            dialog.exec()
        else:
            if not self.mute_sfx:
                self.sound_manager.play_sound("success.wav")
            self.status_label.setText("[INFO] Operation successful.")
            dialog = CustomDialog("Success", "Operation completed successfully; no errors caught.", self)
            dialog.exec()

    def create_settings_general_tab(self):
        general_tab = QWidget()
        layout = QVBoxLayout(general_tab)
        output_group = QGroupBox("Output settings")
        output_layout = QFormLayout()
        self.custom_ext_field = QLineEdit(self.custom_ext)
        output_layout.addRow("Custom extension:", self.custom_ext_field)  
        output_dir_layout = QHBoxLayout()
        self.output_dir_field = QLineEdit(self.output_dir)
        self.output_dir_field.setReadOnly(True)
        self.output_dir_browse_button = QPushButton("Browse")
        self.output_dir_browse_button.clicked.connect(self.select_output_dir)
        output_dir_layout.addWidget(self.output_dir_field)
        output_dir_layout.addWidget(self.output_dir_browse_button)
        output_layout.addRow("Output directory:", output_dir_layout)  
        self.new_name_type_combo = QComboBox()
        self.new_name_type_combo.addItems(["keep", "hash", "base64"])
        self.new_name_type_combo.setCurrentText(self.new_name_type)
        output_layout.addRow("New name type:", self.new_name_type_combo)
        self.archive_mode_checkbox = QCheckBox()
        self.archive_mode_checkbox.setChecked(self.archive_mode)
        output_layout.addRow("Archive mode:", self.archive_mode_checkbox)
        self.archive_mode_checkbox.setToolTip("Archive mode\n\nKnock off .zip file. Combines all files during encryption\ninto a single file; highly recommended.")
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        layout.addStretch()
        return general_tab
    
    def select_output_dir(self):
        dir_dialog = QFileDialog()
        dir_dialog.setFileMode(QFileDialog.Directory)
        if dir_dialog.exec():
            selected_dir = dir_dialog.selectedFiles()[0]
            self.output_dir_field.setText(selected_dir)
            self.output_dir = selected_dir

    def create_settings_audio_tab(self):
        audio_tab = QWidget()
        layout = QVBoxLayout(audio_tab)
        audio_group = QGroupBox("Audio settings")
        audio_layout = QFormLayout()
        self.mute_sfx_checkbox = QCheckBox()
        self.mute_sfx_checkbox.setChecked(self.mute_sfx)
        audio_layout.addRow("Mute SFX:", self.mute_sfx_checkbox)
        self.mute_sfx_checkbox.setToolTip("Mute sfx\n\nMute all sound effects in PyKryptor.")
        volume_layout = QHBoxLayout()
        self.volume_slider = QSlider(Qt.Horizontal)
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(int(self.sfx_volume * 100))
        self.volume_slider.valueChanged.connect(self.update_volume)
        self.volume_label = QLabel(f"{int(self.sfx_volume * 100)}%")
        volume_layout.addWidget(self.volume_slider)
        volume_layout.addWidget(self.volume_label)
        audio_layout.addRow("SFX volume:", volume_layout)
        self.volume_slider.setToolTip("SFX volume\n\nAdjust how loud these annoying ass sound effects are.")
        audio_group.setLayout(audio_layout)
        layout.addWidget(audio_group)
        layout.addStretch()
        return audio_tab
    
    def update_volume(self, value):
        self.sfx_volume = value / 100.0
        self.volume_label.setText(f"{value}%")
        self.sound_manager.set_volume(self.sfx_volume)

    def update_settings(self):
        self.custom_ext = self.custom_ext_field.text()
        self.output_dir = self.output_dir_field.text()
        self.new_name_type = self.new_name_type_combo.currentText()
        self.mute_sfx = self.mute_sfx_checkbox.isChecked()
        self.archive_mode = self.archive_mode_checkbox.isChecked()
        self.aead_algorithm = self.aead_map_rev.get(self.aead_combo.currentText(), "aes-gcm")
        self.use_argon2 = self.use_argon2_checkbox.isChecked()
        self.kdf_iterations = self.kdf_iterations_spinbox.value()
        self.pbkdf2_hash = self.pbkdf2_hash_combo.currentText()
        self.argon2_time_cost = self.argon2_time_spinbox.value()
        self.argon2_memory_cost = self.argon2_memory_spinbox.value()
        self.argon2_parallelism = self.argon2_parallelism_spinbox.value()
        self.compression_level = self.compression_mapping[self.compression_combo.currentText()]
        self.compression_detection = self.detection_map_rev.get(self.detection_mode_combo.currentText(), "legacy")
        self.entropy_threshold = self.entropy_threshold_spinbox.value()
        self.secure_clear = self.secure_clear_checkbox.isChecked()
        self.add_recovery_data = self.recovery_checkbox.isChecked()
        self.chunk_size_mb = self.chunk_size_spinbox.value()
        self.save_settings()
        if not self.mute_sfx:
             self.sound_manager.play_sound("success.wav")
        dialog = CustomDialog("Settings saved", "Your settings have been saved successfully.", self)
        dialog.exec()

    def handle_warning_checkbox(self, state, checkbox, title, message):
        if state:
            self.play_warning_sound()
            dialog = CustomDialog(title, message, self)
            if dialog.exec() != QDialog.Accepted:
                checkbox.setChecked(False)

    def play_warning_sound(self):
        if not self.mute_sfx:
            self.sound_manager.play_sound("info.wav")

    def handle_argon2_checkbox(self, state):
        if state and not ARGON2_AVAILABLE:
            self.play_warning_sound()
            dialog = CustomDialog("Argon2ID not available", "Argon2ID library is not installed. Please install it with:\npip install argon2-cffi\n\nUsing PBKDF2 as fallback.", self)
            dialog.exec()
            self.use_argon2_checkbox.setChecked(False)
        elif state:
            self.play_warning_sound()
            dialog = CustomDialog("Argon2ID info", "Argon2ID is the modern standard for password hashing and offers better security than PBKDF2.\n\nIt may be slightly slower but provides better protection against GPU attacks.", self)
            dialog.exec()

    def create_settings_advanced_tab(self):
        advanced_tab = QWidget()
        main_layout = QVBoxLayout(advanced_tab)
        main_layout.setContentsMargins(0, 0, 0, 0)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("""
            QScrollArea { border: none; }
            QGroupBox { margin-bottom: 10px; }""")
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        encryption_group = QGroupBox("Encryption")
        encryption_layout = QFormLayout()
        self.aead_combo = QComboBox()
        self.aead_combo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        aead_map = {"aes-gcm": "AES-256-GCM", "chacha20-poly1305": "ChaCha20-Poly1305"}
        self.aead_map_rev = {v: k for k, v in aead_map.items()}
        self.aead_combo.setCurrentText(aead_map.get(self.aead_algorithm, "AES-256-GCM"))
        self.aead_combo.setToolTip("AEAD algorithm\n\nChoose between AES-256-GCM or\nChaCha20-Poly1305 for your encryption algorithm.")
        self.aead_combo.currentTextChanged.connect(self.update_aead_warning)
        encryption_layout.addRow("AEAD algorithm:", self.aead_combo)
        self.aes_ni_warning_label = QLabel("Warning: your CPU supports AES-NI, making AES-GCM significantly faster.")
        self.aes_ni_warning_label.setStyleSheet("color: #FFA500; font-size: 8pt;")
        self.aes_ni_warning_label.setWordWrap(True)
        encryption_layout.addRow(self.aes_ni_warning_label)
        encryption_group.setLayout(encryption_layout)
        kdf_group = QGroupBox("Key derivation function (KDF)")
        kdf_layout = QFormLayout()
        self.use_argon2_checkbox = QCheckBox()
        self.use_argon2_checkbox.setChecked(self.use_argon2 and ARGON2_AVAILABLE)
        self.use_argon2_checkbox.stateChanged.connect(self.handle_argon2_checkbox)
        if not ARGON2_AVAILABLE:
            self.use_argon2_checkbox.setEnabled(False)
            self.use_argon2_checkbox.setToolTip("Use Argon2ID\n\nLibrary not installed.\nInstall with: pip install argon2-cffi")
        else:
            self.use_argon2_checkbox.setToolTip("Use Argon2ID\n\nArgon2ID a more modern and secure\nalternative to PBKDF2 for KDF.")
        kdf_layout.addRow("Use Argon2ID:", self.use_argon2_checkbox)
        self.kdf_iterations_spinbox = QSpinBox()
        self.kdf_iterations_spinbox.setRange(100000, 5000000)
        self.kdf_iterations_spinbox.setSingleStep(100000)
        self.kdf_iterations_spinbox.setValue(self.kdf_iterations)
        self.kdf_iterations_spinbox.setGroupSeparatorShown(True)
        self.kdf_iterations_spinbox.setToolTip("PBKDF2 iterations (if Argon2ID is False)\n\nNumber of KDF deriviations used by PBKDF2;\nhigher is more secure but slower.")
        self.pbkdf2_hash_combo = QComboBox()
        self.pbkdf2_hash_combo.addItems(["sha-256", "sha-512"])
        self.pbkdf2_hash_combo.setCurrentText(self.pbkdf2_hash)
        kdf_layout.addRow("PBKDF2 hash type:", self.pbkdf2_hash_combo)
        self.pbkdf2_hash_combo.setToolTip("PBKDF2 hash type\n\nChoose if PBKDF2 will use\nSHA-256 or SHA-512 for key hashing.")
        kdf_layout.addRow("PBKDF2 iterations:", self.kdf_iterations_spinbox)
        self.argon2_time_spinbox = QSpinBox()
        self.argon2_time_spinbox.setRange(1, 20)
        self.argon2_time_spinbox.setValue(self.argon2_time_cost)
        self.argon2_time_spinbox.setToolTip("Argon2ID time cost (iterations)\n\nTime amout for cracking / decryping Argon2ID,\nthe higher the stronger and slower it is.")
        kdf_layout.addRow("Argon2 time cost:", self.argon2_time_spinbox)
        self.argon2_memory_spinbox = QSpinBox()
        self.argon2_memory_spinbox.setRange(1024, 1048576)
        self.argon2_memory_spinbox.setSingleStep(1024)
        self.argon2_memory_spinbox.setValue(self.argon2_memory_cost)
        self.argon2_memory_spinbox.setGroupSeparatorShown(True)
        self.argon2_memory_spinbox.setSuffix(" KB")
        self.argon2_memory_cost_preset = QPushButton("Presets")
        self.argon2_memory_cost_preset.clicked.connect(self.show_argon2_presets)
        argon2_memory_layout = QHBoxLayout()
        argon2_memory_layout.addWidget(self.argon2_memory_spinbox)
        argon2_memory_layout.addWidget(self.argon2_memory_cost_preset)
        self.argon2_memory_spinbox.setToolTip("Argon2ID memory usage in KB\n\nHigher usage is more secure and makes\nbruteforcing harder at the cost of RAM itself\nwhile encrypting / decrypting.")
        kdf_layout.addRow("Argon2ID memory cost:", argon2_memory_layout)
        self.argon2_parallelism_spinbox = QSpinBox()
        self.argon2_parallelism_spinbox.setRange(1, 16)
        self.argon2_parallelism_spinbox.setValue(self.argon2_parallelism)
        self.argon2_parallelism_spinbox.setToolTip("ArgonID2 parallelism (threads)\n\nAmout of cores Argon2ID will use,\nrecommended to match CPU cores.")
        kdf_layout.addRow("Argon2ID parallelism:", self.argon2_parallelism_spinbox)       
        kdf_group.setLayout(kdf_layout)
        compression_group = QGroupBox("Compression")
        compression_layout = QFormLayout()
        self.compression_combo = QComboBox()
        self.compression_combo.addItems(["None", "Normal (fast)", "Best (slow-er)", "ULTRAKILL (probably slow)", "[L] ULTRAKILL (???)"])
        self.compression_mapping = {"None": "none", "Normal (fast)": "normal", "Best (slow-er)": "best", "ULTRAKILL (probably slow)": "ultrakill", "[L] ULTRAKILL (???)": "[L] ultrakill"}
        current_text = [k for k, v in self.compression_mapping.items() if v == self.compression_level][0]
        self.compression_combo.setCurrentText(current_text)
        self.compression_combo.setToolTip("Compression level\n\nCompression makes (or tries) to make files smaller,\nif you want speed it is NOT recommended\nto use compression at all.")
        compression_layout.addRow("Compression level:", self.compression_combo)
        self.detection_mode_combo = QComboBox()
        self.detection_mode_combo.addItems(["None (attempt all)", "Legacy (extension)", "Magic bytes", "Entropy heuristic", "Magic bytes + Entropy"])
        self.detection_map = {
            "none": "None (attempt all)",
            "legacy": "Legacy (extension)",
            "magic": "Magic bytes",
            "entropy": "Entropy heuristic",
            "magic+entropy": "Magic bytes + Entropy"}
        self.detection_map_rev = {v: k for k, v in self.detection_map.items()}
        self.detection_mode_combo.setCurrentText(self.detection_map.get(self.compression_detection, "Legacy (extension)"))
        self.detection_mode_combo.setToolTip("Detection mode\n\nWe use the detection mode to check for already compressed\nfiles with PyKryptor. Each one written in C has it's own\nlittle quirks...\n\nLegacy - only checks for certain file extensions and skips\nthose when compressing.\n\nMagic bytes - we use said signatures; as used;\nto check if the file has compressed data or markings too.\n\nEntropy heuristic - samples around 8KB of a non-determined file to see if\nthe compression ratio is worth, or not.\n\nMagic bytes + Entropy - combines 2nd and 3rd methods into one, most accurate.\n\nNone - disables skipping entirely; always attempts compression.")
        compression_layout.addRow("Detection mode:", self.detection_mode_combo)
        self.entropy_threshold_spinbox = QDoubleSpinBox()
        self.entropy_threshold_spinbox.setRange(6.0, 8.0)
        self.entropy_threshold_spinbox.setSingleStep(0.1)
        self.entropy_threshold_spinbox.setDecimals(1)
        self.entropy_threshold_spinbox.setValue(self.entropy_threshold)
        self.entropy_threshold_spinbox.setToolTip("Entropy threshold\n\nThe higher an entropy value is the less likely it\nis to detect compression. Range is from 6.0-8.0;\ndefault is 7.5, and this setting only applies to\nmethods that include entropy.")
        compression_layout.addRow("Entropy threshold:", self.entropy_threshold_spinbox)
        try:
             from cmp import cmp_check_available
             if not cmp_check_available():
                status_label = QLabel("Warning: the C library for compression detection could\nnot be loaded, the legacy Python based\n(extensions) is in use.")
                status_label.setStyleSheet("color: #FFA500; font-size: 8pt;")
                status_label.setWordWrap(True)
                compression_layout.addWidget(status_label) 
        except ImportError:
            pass
        compression_group.setLayout(compression_layout)
        security_group = QGroupBox("Security / data integrity")
        security_layout = QFormLayout()
        self.secure_clear_checkbox = QCheckBox()
        self.secure_clear_checkbox.setChecked(self.secure_clear)
        if not isca():
            self.secure_clear_checkbox.setEnabled(False)
            self.secure_clear_checkbox.setToolTip("Disabled: C library for secure memory wiping could not be loaded.\nOh well!")
        else:
            self.secure_clear_checkbox.stateChanged.connect(lambda state: self.handle_warning_checkbox(state, self.secure_clear_checkbox, "Warning", "This enables a feature to overwrite the password in memory after use.\n\nThis relies on a compiled C library, the logic behind it is great itself; but always use with caution if you're unsure."))
        security_layout.addRow("Securely clear password from memory:", self.secure_clear_checkbox)
        self.recovery_checkbox = QCheckBox()
        self.recovery_checkbox.setChecked(self.add_recovery_data)
        self.recovery_checkbox.stateChanged.connect(lambda state: self.handle_warning_checkbox(state, self.recovery_checkbox, "Warning", "This adds Reedsolo recovery data to each chunk.\n\nThis can help repair files from minor corruption (bit rot) but will increase file size and processing time. It does not protect against malicious tampering if you might be wondering.\n\nThis feature is SO slow in fact that I do not even test it myself :)"))
        security_layout.addRow("Add partial data recovery info:", self.recovery_checkbox)
        security_group.setLayout(security_layout)
        performance_group = QGroupBox("Performance")
        performance_layout = QFormLayout()
        self.chunk_size_spinbox = QSpinBox()
        self.chunk_size_spinbox.setRange(1, 128)
        self.chunk_size_spinbox.setValue(self.chunk_size_mb)
        self.chunk_size_spinbox.setSuffix(" MB")
        performance_layout.addRow("Chunk size:", self.chunk_size_spinbox)
        self.chunk_size_spinbox.setToolTip("Chunk size\n\nHow many MBs will be used per chunk per processing;\nUSE THIS WITH CAUTION.")
        performance_group.setLayout(performance_layout)
        layout.addWidget(encryption_group)
        layout.addWidget(kdf_group)
        layout.addWidget(compression_group)
        layout.addWidget(security_group)
        layout.addWidget(performance_group)
        layout.addStretch()
        self.update_aead_warning(self.aead_combo.currentText())
        scroll_area.setWidget(content_widget)
        main_layout.addWidget(scroll_area)
        return advanced_tab

    def update_aead_warning(self, text):
        show_warning = (text == "ChaCha20-Poly1305" and self.has_aes_ni)
        if hasattr(self, "aes_ni_warning_label"):
            self.aes_ni_warning_label.setVisible(show_warning)
            if show_warning and not self.mute_sfx:
                self.sound_manager.play_sound("info.wav")

    def show_argon2_presets(self):
        dialog = CustomArgon2Dialog(self)
        if dialog.exec() == QDialog.Accepted:
            self.argon2_memory_spinbox.setValue(dialog.selected_value)

    def create_settings_usb_tab(self):
        usb_tab = QWidget()
        layout = QVBoxLayout(usb_tab)
        layout.setSpacing(12)
        info_group = QGroupBox("USB-codec")
        info_layout = QVBoxLayout()
        info_label = QLabel("USB-codec add an extra layer of security by requiring both a password and a specific USB drive to decrypt files.\n\nSetup a USB drive as a key device, then use it when creating archives.")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("padding: 8px;")
        info_layout.addWidget(info_label)
        setup_button = QPushButton("Setup USB-codec")
        setup_button.clicked.connect(self.open_usb_setup)
        info_layout.addWidget(setup_button)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        layout.addStretch()
        return usb_tab
    
    def open_usb_setup(self):
        dialog = USBSetupDialog(self)
        if dialog.exec() == QDialog.Accepted:
            if not self.mute_sfx:
                self.sound_manager.play_sound("success.wav")
            self.status_label.setText("[INFO] USB-codec setup completed.")

    def create_settings_tab(self):
        settings_tab = QWidget()
        main_settings_layout = QVBoxLayout(settings_tab)
        sub_tab_widget = QTabWidget()
        general_tab = self.create_settings_general_tab()
        audio_tab = self.create_settings_audio_tab()
        advanced_tab = self.create_settings_advanced_tab()
        usb_tab = self.create_settings_usb_tab()
        sub_tab_widget.addTab(general_tab, "General")
        sub_tab_widget.addTab(audio_tab, "Audio")
        sub_tab_widget.addTab(advanced_tab, "Advanced")
        sub_tab_widget.addTab(usb_tab, "USB-codec")
        save_button = QPushButton("Save settings")
        icon_path = get_resource_path(os.path.join("img", "save_img.png"))
        save_button.setIcon(QIcon(icon_path))
        save_button.clicked.connect(self.update_settings)
        main_settings_layout.addWidget(sub_tab_widget)
        main_settings_layout.addWidget(save_button)
        return settings_tab

    def create_about_tab(self):
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        self.about_tab_widget = QTabWidget()
        disclaimer_tab = self.create_disclaimer_tab()
        self.about_tab_widget.addTab(disclaimer_tab, "Legal stuff")
        info_tab = self.create_info_tab()
        self.about_tab_widget.addTab(info_tab, "Nerd info")
        changelog_tab = self.create_log_tab()
        self.about_tab_widget.addTab(changelog_tab, "Changelogs")
        about_layout.addWidget(self.about_tab_widget)
        return about_tab

    def create_disclaimer_tab(self):
        disclaimer_widget = QWidget()
        disclaimer_layout = QVBoxLayout(disclaimer_widget)
        info_label = QLabel("PyKryptor")
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_label.setStyleSheet("font-size: 16pt; font-weight: bold; margin-bottom: 10px;")
        subtitle_label = QLabel("Who even reads this?")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet("font-size: 12pt; font-style: italic; margin-bottom: 20px;")
        disclaimer_text = self.load_disclaimer()
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        disclaimer_label = QLabel(disclaimer_text)
        disclaimer_label.setWordWrap(True)
        disclaimer_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        disclaimer_label.setStyleSheet("font-size: 9pt; padding: 15px; border: 1px solid #666; background-color: #2A2A2A; border-radius: 0px; line-height: 1.4;")
        scroll_area.setWidget(disclaimer_label)
        disclaimer_layout.addWidget(info_label)
        disclaimer_layout.addWidget(subtitle_label)
        disclaimer_layout.addWidget(scroll_area)
        return disclaimer_widget

    def create_info_tab(self):
        info_widget = QWidget()
        info_layout = QVBoxLayout(info_widget)
        title_label = QLabel("Technical information")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 14pt; font-weight: bold; margin-bottom: 20px;")
        info_text = self.load_info()
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        info_label = QLabel(info_text)
        info_label.setWordWrap(True)
        info_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        info_label.setStyleSheet("font-size: 9pt; padding: 15px; border: 1px solid #666; background-color: #2A2A2A; border-radius: 0px; line-height: 1.4; font-family: 'Consolas', 'Monaco', monospace;")
        scroll_area.setWidget(info_label)
        info_layout.addWidget(title_label)
        info_layout.addWidget(scroll_area)
        return info_widget

    def create_log_tab(self):
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        title_label = QLabel("Changelogs")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 14pt; font-weight: bold; margin-bottom: 20px;")
        log_text = self.load_log()
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        log_label = QLabel(log_text)
        log_label.setWordWrap(True)
        log_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        log_label.setStyleSheet("font-size: 9pt; padding: 15px; border: 1px solid #666; background-color: #2A2A2A; border-radius: 0px; line-height: 1.4; font-family: 'Consolas', 'Monaco', monospace;")
        scroll_area.setWidget(log_label)
        log_layout.addWidget(title_label)
        log_layout.addWidget(scroll_area)
        return log_widget

    def load_disclaimer(self):
        try:
            with open(get_resource_path(os.path.join("txts", "disclaimer.txt")), "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return "Disclaimer could not be loaded, it's existace still stands though."

    def load_info(self):
        try:
            with open(get_resource_path(os.path.join("txts", "info.txt")), "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return "Technical information could not be loaded."

    def load_log(self):
        try:
            with open(get_resource_path(os.path.join("txts", "changelog.txt")), "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return "Changelogs could not be loaded; find out what's new on your own I guess..."
        
if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        stream_redirect = QtStream()
        if sys.platform == "win32":
            app.setStyle("windowsvista")
        else:
            app.setStyle("Fusion")
        if is_admin():
            sys.stdout = stream_redirect
            sys.stderr = stream_redirect
        window = PyKryptor()
        if sys.platform == "win32":
            try:
                hwnd = ctypes.windll.kernel32.GetConsoleWindow()
                if hwnd:
                    ctypes.windll.user32.ShowWindow(hwnd, 0)
                ctypes.windll.kernel32.FreeConsole()
                sys.stdout = None
                sys.stderr = None
            except Exception:
                pass
        if window.debug_console:
            stream_redirect.connect_target(window.debug_console.append_text)  
        window.show()
        sys.exit(app.exec())
    except Exception:
        import traceback as _tb
        try:
           _tb.print_exc()
        except:
           pass
        try:
            log_base = os.path.dirname(sys.executable)if getattr(sys, "frozen", False) else os.getcwd() ## catch a/e
            logpath = os.path.join(log_base, "pykryptor_startup.txt")
            with open(logpath, "a", encoding="utf-8") as f:
                f.write("Startup exception:\n")
                _tb.print_exc(file=f)
        except Exception:
            pass
        raise

## end