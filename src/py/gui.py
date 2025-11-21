## gui.py
## last updated: 21/11/2025 <d/m/y>
## p-y-k-x
import sys
import os
import ctypes
import shutil
import glob
import tempfile
import json
import struct
from colorama import *
init(autoreset=True)
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *
from PySide6.QtCore import Signal as pyqtSignal
try:
    from argon2 import PasswordHasher
    ARGON2_AVAILABLE = True
    print(Fore.GREEN + "[DEV PRINT] Argon2ID is available; dr2" + Style.RESET_ALL)
except ImportError:
    ARGON2_AVAILABLE = False
try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

from core import BatchProcessorThread
from stylez import STYLE_SHEET
from outs import ProgressDialog, CustomDialog, ErrorExportDialog, DebugConsole, CustomArgon2Dialog, ArchiveCreationDialog, USBSetupDialog, USBSelectionDialog, enable_win_dark_mode
from sfx import SoundManager
from c_base import isca, check_aes_ni, aes_ni_aval

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
        except PermissionError:
            print(Fore.RED + f"[DEV PRINT] Cannot remove __pycache__ directory from '{cache_path}'.\n\ne: {e}" + Style.RESET_ALL)
        except OSError as e:
            print(Fore.RED + f"[DEV PRINT] Failed to remove __pycache__ from '{cache_path}'.\n\ne: {e}" + Style.RESET_ALL)

def get_resource_path(relative_path):
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
        self.setGeometry(100, 100, 500, 380)
        self.setFixedSize(500, 400)
        self.setStyleSheet(STYLE_SHEET)
        self.setAcceptDrops(True)
        enable_win_dark_mode(self)
        self.files_to_process = []
        self.custom_ext = "dat"
        self.output_dir = ""
        self.new_name_type = "keep"
        self.mute_sfx = False
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
        self.batch_processor = None
        self.progress_dialog = None
        self.config_path = self.get_config_path()
        self.load_settings()
        self.validate_output_dir()
        self.sound_manager = SoundManager()
        self.sound_manager.list_available_sounds()
        self.sound_manager.load_sound("success.wav")
        self.sound_manager.load_sound("error.wav")
        self.sound_manager.load_sound("info.wav")
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
            dialog.exec()

    def init_debug_console(self):
        if self.is_admin:
            VER = "1.5"
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
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        except Exception as e:
            self.sound_manager.play_sound("error.wav")
            dialog = CustomDialog("Oi blyat...", f"Failed to load settings: {e}", self)
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
            "argon2_parallelism": self.argon2_parallelism}
        with open(self.config_path, "w") as f:
            json.dump(config, f, indent=4)

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
            }
        """)
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
                }
            """)
            self.strength_label = QLabel("Password strength: X")
            self.strength_label.setStyleSheet("color: #888888; font-size: 9pt; margin-top: 2px;")
            self.strength_label.setWordWrap(True)
            password_layout.addWidget(self.strength_bar)
            password_layout.addWidget(self.strength_label)
            self.password_field.textChanged.connect(self.update_password_strength)
        else:
            self.strength_bar = None
            self.strength_label = None
        password_group.setLayout(password_layout)
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
        main_layout.addWidget(password_group)
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
            "secure_clear": self.secure_clear,
            "add_recovery_data": self.add_recovery_data,
            "chunk_size_mb": self.chunk_size_mb}
        dialog = ArchiveCreationDialog(parent=self, current_settings=current_settings)
        if dialog.exec() == QDialog.Accepted:
            archive_data = dialog.archive_data
            if archive_data:
                self.start_archive_creation(archive_data)

    def start_archive_creation(self, archive_data): ## ¯\_(ツ)_/¯
        self.status_label.setText("[INFO] Creating archive...")
        self.encrypt_button.setEnabled(False)
        self.decrypt_button.setEnabled(False)
        self.create_archive_button.setEnabled(False)
        self.progress_dialog = ProgressDialog("Creating archive...", self)
        self.progress_dialog.canceled.connect(self.cancel_operation)
        self.progress_dialog.show()
        output_path = os.path.join(archive_data["output_dir"], archive_data["archive_name"])
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
            archive_name=archive_data["archive_name"],
            parent=self)
        self.batch_processor.batch_progress_updated.connect(self.progress_dialog.update_batch_progress)
        self.batch_processor.status_message.connect(lambda msg: self.progress_dialog.file_label.setText(msg))
        self.batch_processor.progress_updated.connect(lambda p: self.progress_dialog.file_progress_bar.setValue(int(p)))
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
            error_message = "Archive creation failed:\n" + "\n".join(errors)
            self.status_label.setText("[ERROR] Archive creation failed.")
            dialog = ErrorExportDialog("Archive creation failed", error_message, errors, self)
            dialog.exec()
        else:
            if not self.mute_sfx:
                self.sound_manager.play_sound("success.wav")
            self.status_label.setText("[INFO] Archive created successfully.")
            dialog = CustomDialog("Success", "Archive created successfully; no errors caught.", self)
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

    def create_settings_audio_tab(self):
        audio_tab = QWidget()
        layout = QVBoxLayout(audio_tab)
        audio_group = QGroupBox("Audio settings")
        audio_layout = QFormLayout()
        self.mute_sfx_checkbox = QCheckBox()
        self.mute_sfx_checkbox.setChecked(self.mute_sfx)
        audio_layout.addRow("Mute sfx:", self.mute_sfx_checkbox)
        self.mute_sfx_checkbox.setToolTip("Mute sfx\n\nMute all sound effects in PyKryptor.")
        audio_group.setLayout(audio_layout)
        layout.addWidget(audio_group)
        layout.addStretch()
        return audio_tab

    def handle_warning_checkbox(self, state, checkbox, title, message):
        if state:
            self.play_warning_sound()
            dialog = CustomDialog(title, message, self)
            if dialog.exec() != QDialog.Accepted:
                checkbox.setChecked(False)

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
            QGroupBox { margin-bottom: 10px; }
        """)
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        encryption_group = QGroupBox("Encryption")
        encryption_layout = QFormLayout()
        self.aead_combo = QComboBox()
        self.aead_combo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        aead_map = {"aes-gcm": "AES-256-GCM", "chacha20-poly1305": "ChaCha20-Poly1305"}
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
        self.pbkdf2_hash_combo.currentTextChanged.connect(self.update_pbkdf2_hash)
        kdf_layout.addRow("PBKDF2 hash type:", self.pbkdf2_hash_combo)
        self.pbkdf2_hash_combo.setToolTip("PBKDF2 hash type\n\nChoose if PBKDF2 will use\nSHA-256 or SHA-512 for key hashing.")
        kdf_layout.addRow("PBKDF2 iterations:", self.kdf_iterations_spinbox)
        self.argon2_time_spinbox = QSpinBox()
        self.argon2_time_spinbox.setRange(1, 20)
        self.argon2_time_spinbox.setValue(self.argon2_time_cost)
        self.argon2_time_spinbox.setToolTip("Argon2ID time cost (iterations).\n\nTime amout for cracking / decryping Argon2ID,\nthe higher the stronger and slower it is.")
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
        self.argon2_memory_spinbox.setToolTip("Argon2ID memory usage in KB.\n\nHigher usage is more secure and makes\nbruteforcing harder at the cost of RAM itself\nwhile encrypting / decrypting.")
        kdf_layout.addRow("Argon2ID memory cost:", argon2_memory_layout)
        self.argon2_parallelism_spinbox = QSpinBox()
        self.argon2_parallelism_spinbox.setRange(1, 16)
        self.argon2_parallelism_spinbox.setValue(self.argon2_parallelism)
        self.argon2_parallelism_spinbox.setToolTip("ArgonID2 parallelism (threads).\n\nAmout of cores Argon2ID will use,\nrecommended to match CPU cores.")
        kdf_layout.addRow("Argon2ID parallelism:", self.argon2_parallelism_spinbox)       
        kdf_group.setLayout(kdf_layout)
        compression_group = QGroupBox("Compression")
        compression_layout = QFormLayout()
        self.compression_combo = QComboBox()
        self.compression_combo.addItems(["None", "Normal (fast)", "Best (slow-er)", "ULTRAKILL (probably slow)", "[L] ULTRAKILL (???)"])
        compression_mapping = {"None": "none", "Normal (fast)": "normal", "Best (slow-er)": "best", "ULTRAKILL (probably slow)": "ultrakill", "[L] ULTRAKILL (???)": "[L] ultrakill"}
        current_text = [k for k, v in compression_mapping.items() if v == self.compression_level][0]
        self.compression_combo.setCurrentText(current_text)
        self.compression_combo.setToolTip("Compression level\n\nCompression makes (or tries) to make files smaller,\nif you want speed it is NOT recommended\nto use compression at all.")
        compression_layout.addRow("Compression level:", self.compression_combo)
        compression_group.setLayout(compression_layout)
        security_group = QGroupBox("Security / data integrity")
        security_layout = QFormLayout()
        self.secure_clear_checkbox = QCheckBox()
        self.secure_clear_checkbox.setChecked(self.secure_clear)
        if not isca():
            self.secure_clear_checkbox.setEnabled(False)
            self.secure_clear_checkbox.setToolTip("Disabled: eh, C library not found... a shame for you.")
        else:
            self.secure_clear_checkbox.stateChanged.connect(lambda state: self.handle_warning_checkbox(state, self.secure_clear_checkbox, "Warning",
                "This enables a feature to overwrite the password in memory after use.\n\nThis is an experimental security measure and relies on a compiled C library, aka shit MIGHT go wrong!!"))
        security_layout.addRow("Securely clear password from memory:", self.secure_clear_checkbox)
        self.recovery_checkbox = QCheckBox()
        self.recovery_checkbox.setChecked(self.add_recovery_data)
        self.recovery_checkbox.stateChanged.connect(lambda state: self.handle_warning_checkbox(state, self.recovery_checkbox, "Warning",
            "This adds Reedsolo recovery data to each chunk.\n\nThis can help repair files from minor corruption (bit rot) but will increase file size and processing time. It does not protect against malicious tampering fuck face.\n\nThis feature is SO slow in fact that I do not even test it myself :)"))
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
        subtitle_label = QLabel("WinRAR is probably enough but use this for your needs™")
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
            disclaimer_path = get_resource_path(os.path.join("txts", "disclaimer.txt"))
            with open(disclaimer_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return "Disclaimer file not found; shame for ya."

    def load_info(self):
        try:
            info_path = get_resource_path(os.path.join("txts", "info.txt"))
            with open(info_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return "Info file not found; ball is out nerd."

    def load_log(self):
        try:
            changelogs_path = get_resource_path(os.path.join("txts", "changelog.txt"))
            with open(changelogs_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return "Changelogs file not found; perhaps guess what's new?"

    def update_settings(self):
        compression_mapping = {"None": "none", "Normal (fast)": "normal", "Best (slow-er)": "best", "ULTRAKILL (probably slow)": "ultrakill", "[L] ULTRAKILL (???)": "[L] ultrakill"}
        aead_map_rev = {"AES-256-GCM": "aes-gcm", "ChaCha20-Poly1305": "chacha20-poly1305"}
        self.aead_algorithm = aead_map_rev.get(self.aead_combo.currentText(), "aes-gcm")
        self.compression_level = compression_mapping[self.compression_combo.currentText()]
        self.custom_ext = self.custom_ext_field.text()
        self.output_dir = self.output_dir_field.text()
        self.new_name_type = self.new_name_type_combo.currentText()
        self.mute_sfx = self.mute_sfx_checkbox.isChecked()
        self.chunk_size_mb = self.chunk_size_spinbox.value()
        self.kdf_iterations = self.kdf_iterations_spinbox.value()
        self.secure_clear = self.secure_clear_checkbox.isChecked()
        self.add_recovery_data = self.recovery_checkbox.isChecked()
        self.archive_mode = self.archive_mode_checkbox.isChecked()
        self.use_argon2 = self.use_argon2_checkbox.isChecked() and ARGON2_AVAILABLE
        self.argon2_time_cost = self.argon2_time_spinbox.value()
        self.argon2_memory_cost = self.argon2_memory_spinbox.value()
        self.argon2_parallelism = self.argon2_parallelism_spinbox.value()
        if self.output_dir and not os.path.exists(self.output_dir):
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            if not os.path.exists(desktop_path): desktop_path = os.path.expanduser("~")
            self.output_dir = desktop_path
            self.output_dir_field.setText(self.output_dir)
            self.play_warning_sound()
            dialog = CustomDialog("Warning", f"Output directory was invalid and changed to:\n{desktop_path}", self)
            dialog.exec()
        if not self.mute_sfx: self.sound_manager.play_sound("success.wav")
        dialog = CustomDialog("Success", "Settings have been saved to 'config.json'", self)
        dialog.exec()
        self.save_settings()
        self.status_label.setText("[INFO] Settings saved (hopefully)")

    def select_files(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        if file_dialog.exec():
            self.files_to_process = file_dialog.selectedFiles()
            if len(self.files_to_process) == 1: self.input_path_field.setText(self.files_to_process[0])
            else: self.input_path_field.setText(f"{len(self.files_to_process)} files selected.")
            self.status_label.setText("[INFO] Files ready to process.")

    def select_output_dir(self):
        dir_dialog = QFileDialog()
        dir_dialog.setFileMode(QFileDialog.Directory)
        if dir_dialog.exec():
            selected_dir = dir_dialog.selectedFiles()[0]
            if os.path.exists(selected_dir):
                self.output_dir = selected_dir
                self.output_dir_field.setText(self.output_dir)
            else:
                dialog = CustomDialog("Warning", "Selected directory does not exist, somehow...?", self)
                dialog.exec()

    def start_operation(self, operation):
        password = self.password_field.text()
        if not self.files_to_process:
            self.play_warning_sound()
            dialog = CustomDialog("Warning", "Maybe choose some file(s) first, pal?", self)
            dialog.exec()
            return
        if not password:
            self.play_warning_sound()
            dialog = CustomDialog("Warning", "No password; you nitwit.", self)
            dialog.exec()
            return
        usb_key_path = None
        if operation == "decrypt":
            try:
                with open(self.files_to_process[0], "rb") as f:
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
        self.status_label.setText("[INFO] Starting...")
        self.encrypt_button.setEnabled(False)
        self.decrypt_button.setEnabled(False)
        self.create_archive_button.setEnabled(False)
        self.progress_dialog = ProgressDialog("Processing...", self)
        self.progress_dialog.canceled.connect(self.cancel_operation)
        self.progress_dialog.show()    
        self.batch_processor = BatchProcessorThread(
            operation=operation, file_paths=self.files_to_process, password=password,
            custom_ext=self.custom_ext, output_dir=self.output_dir, new_name_type=self.new_name_type,
            chunk_size=self.chunk_size_mb * 1024 * 1024, kdf_iterations=self.kdf_iterations,
            secure_clear=self.secure_clear, add_recovery_data=self.add_recovery_data,
            compression_level=self.compression_level, archive_mode=self.archive_mode,
            use_argon2=self.use_argon2, argon2_time_cost=self.argon2_time_cost,
            argon2_memory_cost=self.argon2_memory_cost, argon2_parallelism=self.argon2_parallelism,
            aead_algorithm=self.aead_algorithm, pbkdf2_hash=self.pbkdf2_hash,
            usb_key_path=usb_key_path, parent=self) ## not doing a one-liner for this one 😒
        self.batch_processor.batch_progress_updated.connect(self.progress_dialog.update_batch_progress)
        self.batch_processor.status_message.connect(lambda msg: self.progress_dialog.file_label.setText(msg))
        self.batch_processor.progress_updated.connect(lambda p: self.progress_dialog.file_progress_bar.setValue(int(p)))
        self.batch_processor.finished.connect(self.on_batch_finished)
        self.batch_processor.start()

    def update_aead_algorithm(self, text):
        self.aead_algorithm = text.lower()
        self.save_settings()

    def update_pbkdf2_hash(self, text):
        self.pbkdf2_hash = text.lower()
        self.save_settings()

    def toggle_password_visibility(self, checked):
        if checked:
            self.password_field.setEchoMode(QLineEdit.Normal)
            icon_path = get_resource_path(os.path.join("img", "hide_pass_img.png"))
            self.peek_button.setIcon(QIcon(icon_path))
            self.peek_button.setIconSize(QSize(32, 32))
        else:
            self.password_field.setEchoMode(QLineEdit.Password)
            icon_path = get_resource_path(os.path.join("img", "show_pass_img.png"))
            self.peek_button.setIcon(QIcon(icon_path))
            self.peek_button.setIconSize(QSize(32, 32))

    def update_password_strength(self, password):
        if not ZXCVBN_AVAILABLE or not self.strength_bar:
            return
        if not password:
            self.strength_bar.setValue(0)
            self.strength_bar.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #5A5A5A;
                    background-color: #3C3C3C;
                    border-radius: 3px;
                }
                QProgressBar::chunk {
                    background-color: #FF4444;
                    border-radius: 2px;
                }""")
            self.strength_label.setText("Password strength: X")
            self.strength_label.setStyleSheet("color: #888888; font-size: 9pt;")
            return
        if len(password) > 72:
            self.strength_bar.setValue(4)
            self.strength_bar.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #5A5A5A;
                    background-color: #3C3C3C;
                    border-radius: 3px;
                }
                QProgressBar::chunk {
                    background-color: #44DD44;
                    border-radius: 2px;
                }""")
            self.strength_label.setText("Password strength: Strong (length: 72+ chars)")
            self.strength_label.setStyleSheet("color: #44DD44; font-size: 9pt;")
            return
        result = zxcvbn(password)
        score = result["score"]
        self.strength_bar.setValue(score)
        colors = {
            0: ("#FF4444", "Really?"),
            1: ("#FF8844", "Weak"),
            2: ("#FFAA44", "Fair"),
            3: ("#88DD44", "Good"),
            4: ("#44DD44", "Strong")}
        color, label = colors.get(score, ("#FF4444", "Really?"))
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #5A5A5A;
                background-color: #3C3C3C;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 2px;
            }}""")
        crack_time = result.get("crack_times_display", {}).get("offline_slow_hashing_1e4_per_second", "unknown")
        status_text = f"Password strength: {label} (crack time: {crack_time})"
        if score < 2:
            warning = result.get("feedback", {}).get("warning", "")
            if warning:
                warning = warning.replace("This is a top 10 common password", "Common password")
                warning = warning.replace("This is a top 100 common password", "Common password")
                warning = warning.replace("This is similar to a commonly used password", "Similar to common")
                warning = warning.replace("Straight rows of keys are easy to guess", "Keyboard pattern")
                warning = warning.replace("Short keyboard patterns are easy to guess", "Keyboard pattern")
                warning = warning.replace("Repeats like 'aaa' are easy to guess", "Repeated chars")
                warning = warning.replace("Repeats like 'abcabcabc' are only slightly harder to guess than 'abc'", "Pattern repeat")
                warning = warning.replace("Sequences like abc or 6543 are easy to guess", "Sequence")
                warning = warning.replace("Recent years are easy to guess", "Contains year")
                warning = warning.replace("Dates are often easy to guess", "Contains date")
                status_text = f"{label} - {warning}"
        self.strength_label.setText(status_text)
        self.strength_label.setStyleSheet(f"color: {color}; font-size: 9pt;")

    def play_warning_sound(self):
        if not self.mute_sfx:
            self.sound_manager.play_sound("info.wav")

    def cancel_operation(self):
        if self.batch_processor and self.batch_processor.isRunning():
            self.batch_processor.cancel()
        if self.progress_dialog: self.progress_dialog.close()
        self.encrypt_button.setEnabled(True)
        self.decrypt_button.setEnabled(True)
        self.create_archive_button.setEnabled(True)
        self.play_warning_sound()
        self.status_label.setText("[INFO] Operation canceled.")

    def on_batch_finished(self, errors):
        if self.progress_dialog: self.progress_dialog.close()
        self.encrypt_button.setEnabled(True)
        self.decrypt_button.setEnabled(True)
        self.create_archive_button.setEnabled(True)
        if errors:
            if not self.mute_sfx: self.sound_manager.play_sound("error.wav")
            error_message = "Some file(s) or archive(s) failed to process:\n" + "\n".join(errors)
            self.status_label.setText("[ERROR] Something failed.")
            dialog = ErrorExportDialog("Ahh kaput...", error_message, errors, self)
            dialog.exec()
        else:
            if not self.mute_sfx: self.sound_manager.play_sound("success.wav")
            self.status_label.setText("[INFO] All file(s) / archive(s) processed successfully.")
            dialog = CustomDialog("Success", "All file(s) / archive(s) processed successfully.", self)
            dialog.exec()

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls(): event.acceptProposedAction()

    def dropEvent(self, event):
        urls = [url.toLocalFile() for url in event.mimeData().urls()]
        self.files_to_process.clear()
        for url in urls:
            if os.path.isdir(url):
                for root, _, files in os.walk(url):
                    for name in files:
                        self.files_to_process.append(os.path.join(root, name))
            else:
                self.files_to_process.append(url)
        if len(self.files_to_process) == 1: self.input_path_field.setText(self.files_to_process[0])
        else: self.input_path_field.setText(f"{len(self.files_to_process)} files selected.")
        self.status_label.setText("[INFO] File(s) ready to process.")
        event.acceptProposedAction()

    def closeEvent(self, event):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        if self.batch_processor and self.batch_processor.isRunning(): self.batch_processor.cancel()
        self.save_settings()
        self.sound_manager.unload()
        event.accept()

if __name__ == "__main__":
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
    ## rm_pycache() <-- shit slows down the app like CRAZY
    if window.debug_console:
        stream_redirect.connect_target(window.debug_console.append_text)   
    window.show()
    print(Fore.GREEN + "[DEV PRINT] Hello my dear World..." + Style.RESET_ALL)
    sys.exit(app.exec())

## end