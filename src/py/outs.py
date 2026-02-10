## outs.py
## last updated: 10/02/2026 <d/m/y>
## p-y-k-x
import os
import tempfile
import struct
import glob
import ctypes
import sys
import re
import string
import secrets
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *
from PySide6.QtCore import Signal as pyqtSignal

from sfx import SoundManager
from c_base import get_resource_path
try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False
try:
    from usb_codec import list_usb_drives, setup_usb_key, is_usb_key_initialized, get_usb_key_info, get_usb_key
    USB_CODEC_AVAILABLE = True
except ImportError:
    USB_CODEC_AVAILABLE = False

def enable_win_dark_mode(widget):
    if sys.platform == "win32":
        try:
            from ctypes import wintypes
            hwnd = int(widget.winId())
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            value = wintypes.DWORD(1)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(value), ctypes.sizeof(value))
        except:
            pass

def strip_ansi_codes(text):
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)

class CustomDialog(QDialog):
    def __init__(self, title, message, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(400, 200)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setStyleSheet("QTextEdit { background-color: #3C3C3C; color: #E0E0E0; border: 1px solid #5A5A5A; }")
        enable_win_dark_mode(self)
        layout = QVBoxLayout(self)
        self.message_label = QLabel(title)
        self.message_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
        layout.addWidget(self.message_label)
        self.message_text = QTextEdit()
        self.message_text.setPlainText(message)
        self.message_text.setReadOnly(True)
        layout.addWidget(self.message_text)
        self.ok_button = QPushButton("OK")
        icon_path = get_resource_path(os.path.join("img", "continue_img.png"))
        self.ok_button.setIcon(QIcon(icon_path))
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(self.ok_button)
        self.setLayout(layout)

class KeyfileGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate Keyfile")
        self.setFixedSize(400, 200)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        enable_win_dark_mode(self)
        layout = QVBoxLayout(self)
        info = QLabel("Generate a random 512 byte keyfile.\nThis file can be used in place of, or in addition to, a password.")
        info.setWordWrap(True)
        layout.addWidget(info)
        self.generate_btn = QPushButton("Generate keyfile")
        self.generate_btn.clicked.connect(self.generate)
        layout.addWidget(self.generate_btn)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        layout.addWidget(self.cancel_btn)
        
    def generate(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save keyfile", "keyfile.pykx", "PyKryptor ;eyfiles (*.pykx);;All files (*)")
        if file_path:
            try:
                data = os.urandom(512)
                with open(file_path, "wb") as f:
                    f.write(data)
                CustomDialog("Success", f"Keyfile generated successfully at:\n{file_path}", self).exec()
                self.accept()
            except Exception as e:
                CustomDialog("Error", f"Failed to generate keyfile.\n\ne:{e}", self).exec()

class ArchiveCreationDialog(QDialog):
    def __init__(self, parent=None, current_settings=None):
        super().__init__(parent)
        self.setWindowTitle("Create archive")
        self.setFixedSize(600, 650)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setAcceptDrops(True)
        enable_win_dark_mode(self)
        self.archive_data = None
        self.current_settings = current_settings or {}
        main_layout = QVBoxLayout(self)
        name_group = QGroupBox("Archive name and output")
        name_layout = QVBoxLayout()
        archive_name_layout = QHBoxLayout()
        self.archive_name_field = QLineEdit()
        self.archive_name_field.setPlaceholderText("archive.dat")
        self.archive_name_field.setText(self.current_settings.get("archive_name", "archive.dat"))
        self.browse_output_button = QPushButton()
        icon_path = get_resource_path(os.path.join("img", "browse_img.png"))
        self.browse_output_button.setIcon(QIcon(icon_path))
        self.browse_output_button.setToolTip("Browse for output location")
        self.browse_output_button.setFixedSize(40, 25)
        self.browse_output_button.clicked.connect(self.browse_output_location)
        archive_name_layout.addWidget(QLabel("Archive name:"))
        archive_name_layout.addWidget(self.archive_name_field)
        archive_name_layout.addWidget(self.browse_output_button)
        self.output_dir_field = QLineEdit()
        self.output_dir_field.setReadOnly(True)
        self.output_dir_field.setPlaceholderText("Output directory...")
        output_dir = self.current_settings.get("output_dir", "")
        if output_dir:
            self.output_dir_field.setText(output_dir)
        name_layout.addLayout(archive_name_layout)
        name_layout.addWidget(self.output_dir_field)
        name_group.setLayout(name_layout)
        files_group = QGroupBox("Files to archive (drag n' drop here)")
        files_layout = QVBoxLayout()
        self.files_list = QListWidget()
        self.files_list.setMaximumHeight(120)
        files_button_layout = QHBoxLayout()
        self.add_files_button = QPushButton("Add files")
        icon_path = get_resource_path(os.path.join("img", "add_files_img.png"))
        self.add_files_button.setIcon(QIcon(icon_path))
        self.add_files_button.clicked.connect(self.add_files)
        self.add_folder_button = QPushButton("Add folder")
        icon_path = get_resource_path(os.path.join("img", "add_folder_img.png"))
        self.add_folder_button.setIcon(QIcon(icon_path))
        self.add_folder_button.clicked.connect(self.add_folder)
        self.remove_files_button = QPushButton("Remove selected")
        icon_path = get_resource_path(os.path.join("img", "remove_selected_img.png"))
        self.remove_files_button.setIcon(QIcon(icon_path))
        self.remove_files_button.clicked.connect(self.remove_selected)
        self.clear_files_button = QPushButton("Clear all")
        icon_path = get_resource_path(os.path.join("img", "remove_all_img.png"))
        self.clear_files_button.setIcon(QIcon(icon_path))
        self.clear_files_button.clicked.connect(self.clear_files)
        files_button_layout.addWidget(self.add_files_button)
        files_button_layout.addWidget(self.add_folder_button)
        files_button_layout.addWidget(self.remove_files_button)
        files_button_layout.addWidget(self.clear_files_button)
        files_layout.addWidget(self.files_list)
        files_layout.addLayout(files_button_layout)
        files_group.setLayout(files_layout)
        settings_tabs = QTabWidget()
        encryption_tab = QWidget()
        encryption_layout = QFormLayout()
        self.aead_combo = QComboBox()
        self.aead_combo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        aead_value = self.current_settings.get("aead_algorithm", "aes-gcm")
        aead_map = {"aes-gcm": "AES-256-GCM", "chacha20-poly1305": "ChaCha20-Poly1305"}
        self.aead_combo.setCurrentText(aead_map.get(aead_value, "AES-256-GCM"))
        encryption_layout.addRow("AEAD algorithm:", self.aead_combo)
        encryption_tab.setLayout(encryption_layout)
        kdf_content_widget = QWidget() 
        kdf_layout = QFormLayout(kdf_content_widget)
        kdf_tab = QScrollArea()
        kdf_tab.setWidgetResizable(True)
        kdf_tab.setWidget(kdf_content_widget)
        self.use_argon2_checkbox = QCheckBox()
        try:
            from argon2 import PasswordHasher
            ARGON2_AVAILABLE = True
        except ImportError:
            ARGON2_AVAILABLE = False
        self.use_argon2_checkbox.setChecked(self.current_settings.get("use_argon2", False) and ARGON2_AVAILABLE)
        if not ARGON2_AVAILABLE:
            self.use_argon2_checkbox.setEnabled(False)
        kdf_layout.addRow("Use Argon2ID:", self.use_argon2_checkbox)
        self.pbkdf2_hash_combo = QComboBox()
        self.pbkdf2_hash_combo.addItems(["sha-256", "sha-512"])
        self.pbkdf2_hash_combo.setCurrentText(self.current_settings.get("pbkdf2_hash", "sha-256"))
        kdf_layout.addRow("PBKDF2 hash:", self.pbkdf2_hash_combo)
        self.kdf_iterations_spinbox = QSpinBox()
        self.kdf_iterations_spinbox.setRange(100000, 5000000)
        self.kdf_iterations_spinbox.setSingleStep(100000)
        self.kdf_iterations_spinbox.setValue(self.current_settings.get("kdf_iterations", 1000000))
        self.kdf_iterations_spinbox.setGroupSeparatorShown(True)
        kdf_layout.addRow("PBKDF2 iterations:", self.kdf_iterations_spinbox)
        self.argon2_time_spinbox = QSpinBox()
        self.argon2_time_spinbox.setRange(1, 20)
        self.argon2_time_spinbox.setValue(self.current_settings.get("argon2_time_cost", 3))
        kdf_layout.addRow("Argon2ID time cost:", self.argon2_time_spinbox)
        self.argon2_memory_spinbox = QSpinBox()
        self.argon2_memory_spinbox.setRange(1024, 1048576)
        self.argon2_memory_spinbox.setSingleStep(1024)
        self.argon2_memory_spinbox.setValue(self.current_settings.get("argon2_memory_cost", 65536))
        self.argon2_memory_spinbox.setGroupSeparatorShown(True)
        self.argon2_memory_spinbox.setSuffix(" KB")
        kdf_layout.addRow("Argon2ID memory:", self.argon2_memory_spinbox)
        self.argon2_parallelism_spinbox = QSpinBox()
        self.argon2_parallelism_spinbox.setRange(1, 16)
        self.argon2_parallelism_spinbox.setValue(self.current_settings.get("argon2_parallelism", 4))
        kdf_layout.addRow("Argon2ID parallelism:", self.argon2_parallelism_spinbox)
        compression_tab = QWidget()
        compression_layout = QFormLayout()
        self.compression_combo = QComboBox()
        self.compression_combo.addItems(["None", "Normal (fast)", "Best (slow-er)", "ULTRAKILL (probably slow)", "[L] ULTRAKILL (???)"])
        compression_mapping = {
            "none": "None",
            "normal": "Normal (fast)",
            "best": "Best (slow-er)",
            "ultrakill": "ULTRAKILL (probably slow)",
            "[L] ultrakill": "[L] ULTRAKILL (???)"}
        current_compression = self.current_settings.get("compression_level", "none")
        self.compression_combo.setCurrentText(compression_mapping.get(current_compression, "None"))
        compression_layout.addRow("Compression level:", self.compression_combo)
        self.detection_mode_combo = QComboBox()
        self.detection_mode_combo.addItems(["Legacy (extension)", "Magic bytes", "Entropy heuristic", "Magic bytes + Entropy", "None (Smart Skipper disabled)"])
        detection_map = {
            "legacy": "Legacy (extension)",
            "magic": "Magic bytes",
            "entropy": "Entropy heuristic",
            "magic+entropy": "Magic bytes + Entropy",
            "none": "None (Smart Skipper disabled)"}
        current_detection = self.current_settings.get("compression_detection", "legacy")
        self.detection_mode_combo.setCurrentText(detection_map.get(current_detection, "Legacy (extension)"))
        self.detection_mode_combo.setToolTip("Detection mode\n\nWe use the detection mode to check for already compressed\nfiles with PyKryptor. Each one written in C has it's own\nlittle quirks...\n\nLegacy - only checks for certain file extensions and skips\nthose when compressing.\n\nMagic bytes - we use said signatures; as used;\nto check if the file has compressed data or markings too.\n\nEntropy heuristic - samples around 8KB of a non-determined file to see if\nthe compression ratio is worth, or not.\n\nMagic bytes + Entropy - combines 2nd and 3rd methods into one, most accurate.\n\nNone - Disables detection (Smart Skipper); always attempts compression.")
        compression_layout.addRow("Detection mode:", self.detection_mode_combo)
        self.entropy_threshold_spinbox = QDoubleSpinBox()
        self.entropy_threshold_spinbox.setRange(6.0, 8.0)
        self.entropy_threshold_spinbox.setSingleStep(0.1)
        self.entropy_threshold_spinbox.setDecimals(1)
        self.entropy_threshold_spinbox.setValue(self.current_settings.get("entropy_threshold", 7.5))
        self.entropy_threshold_spinbox.setToolTip("Entropy threshold\n\nThe higher an entropy value is the less likely it\nis to detect compression. Range is from 6.0-8.0;\ndefault is 7.5, and this setting only applies to\nmethods that include entropy.")
        compression_layout.addRow("Entropy threshold:", self.entropy_threshold_spinbox)
        compression_tab.setLayout(compression_layout)
        security_tab = QWidget()
        security_scroll = QScrollArea()
        security_scroll.setWidgetResizable(True)
        security_scroll.setStyleSheet("QScrollArea { border: none; }")
        security_content = QWidget()
        security_layout = QFormLayout(security_content)
        self.secure_clear_checkbox = QCheckBox()
        self.secure_clear_checkbox.setChecked(self.current_settings.get("secure_clear", False))
        security_layout.addRow("Secure clear password:", self.secure_clear_checkbox)
        self.recovery_checkbox = QCheckBox()
        self.recovery_checkbox.setChecked(self.current_settings.get("add_recovery_data", False))
        security_layout.addRow("Add recovery data:", self.recovery_checkbox)
        self.usb_key_checkbox = QCheckBox()
        self.usb_key_checkbox.setChecked(self.current_settings.get("use_usb_key", False))
        if not USB_CODEC_AVAILABLE:
            self.usb_key_checkbox.setEnabled(False)
            self.usb_key_checkbox.setToolTip("USB-codec not available")
        else:
            self.usb_key_checkbox.setToolTip("USB-codec\n\nBlitz(1)")
        security_layout.addRow("Use USB-codec:", self.usb_key_checkbox)
        self.usb_path_field = QLineEdit()
        self.usb_path_field.setReadOnly(True)
        self.usb_path_field.setPlaceholderText("No USB selected")
        if self.current_settings.get("usb_key_path"):
            self.usb_path_field.setText(self.current_settings.get("usb_key_path"))
        usb_browse_button = QPushButton("Select")
        usb_browse_button.clicked.connect(self.browse_usb_key)
        usb_path_layout = QHBoxLayout()
        usb_path_layout.addWidget(self.usb_path_field)
        usb_path_layout.addWidget(usb_browse_button)
        security_layout.addRow("USB path:", usb_path_layout)
        self.chunk_size_spinbox = QSpinBox()
        self.chunk_size_spinbox.setRange(1, 128)
        self.chunk_size_spinbox.setValue(self.current_settings.get("chunk_size_mb", 3))
        self.chunk_size_spinbox.setSuffix(" MB")
        security_layout.addRow("Chunk size:", self.chunk_size_spinbox)
        security_scroll.setWidget(security_content)
        settings_tabs.addTab(encryption_tab, "Encryption")
        settings_tabs.addTab(kdf_tab, "KDF")
        settings_tabs.addTab(compression_tab, "Compression")
        settings_tabs.addTab(security_scroll, "Security")
        password_group = QGroupBox("Archive password")
        password_layout = QVBoxLayout()
        password_field_layout = QHBoxLayout()
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.Password)
        self.password_field.setPlaceholderText("Enter password...")
        self.peek_button = QPushButton()
        icon_path = get_resource_path(os.path.join("img", "show_pass_img.png"))
        self.peek_button.setIcon(QIcon(icon_path))
        self.peek_button.setCheckable(True)
        self.peek_button.setFixedSize(50, 25)
        self.peek_button.setIconSize(QSize(32, 32))
        self.peek_button.setToolTip("Show / hide password")
        self.peek_button.toggled.connect(self.toggle_password_visibility)
        password_field_layout.addWidget(self.password_field)
        password_field_layout.addWidget(self.peek_button)
        password_layout.addLayout(password_field_layout)
        if ZXCVBN_AVAILABLE:
            self.strength_label = QLabel("Password strength: X")
            self.strength_label.setStyleSheet("color: #888888; font-size: 9pt; margin-top: 2px;")
            password_layout.addWidget(self.strength_label)
            self.password_field.textChanged.connect(self.update_password_strength)
        else:
            self.strength_label = None
        password_group.setLayout(password_layout)
        self.password_group = password_group
        keyfile_group = QGroupBox("Keyfile selection")
        keyfile_group_layout = QVBoxLayout()
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
        keyfile_group_layout.addLayout(keyfile_input_layout)
        keyfile_group.setLayout(keyfile_group_layout)
        self.keyfile_group = keyfile_group
        self.keyfile_group.setVisible(False)
        self.auth_mode_hint = QLabel("Press CTRL + SHIFT + K to switch to keyfile mode")
        self.auth_mode_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.auth_mode_hint.setStyleSheet("color: #888888; font-size: 8pt; margin-top: 5px;")
        button_layout = QHBoxLayout()
        self.create_button = QPushButton("Create archive")
        icon_path = get_resource_path(os.path.join("img", "create_archive_img.png"))
        self.create_button.setIcon(QIcon(icon_path))
        self.create_button.clicked.connect(self.create_archive)
        self.cancel_button = QPushButton("Cancel")
        icon_path = get_resource_path(os.path.join("img", "cancel_img.png"))
        self.cancel_button.setIcon(QIcon(icon_path))
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(self.create_button)
        button_layout.addWidget(self.cancel_button)
        main_layout.addWidget(name_group)
        main_layout.addWidget(files_group)
        main_layout.addWidget(settings_tabs)
        main_layout.addWidget(self.password_group)
        main_layout.addWidget(self.keyfile_group)
        main_layout.addWidget(self.auth_mode_hint)
        main_layout.addLayout(button_layout)
        self.keyfile_shortcut = QShortcut(QKeySequence("Ctrl+Shift+K"), self)
        self.keyfile_shortcut.activated.connect(self.toggle_authentication_mode)
    
    def toggle_authentication_mode(self):
        if self.password_group.isVisible():
            self.password_group.setVisible(False)
            self.keyfile_group.setVisible(True)
            self.password_field.clear()
            self.auth_mode_hint.setText("Press CTRL + SHIFT + K to switch to password mode")
        else:
            self.keyfile_group.setVisible(False)
            self.password_group.setVisible(True)
            self.main_keyfile_path_field.clear()
            self.auth_mode_hint.setText("Press CTRL + SHIFT + K to switch to keyfile mode")

    def browse_main_keyfile(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select keyfile", "", "PyKryptor keyfiles (*.pykx);;All files (*)")
        if file:
            self.main_keyfile_path_field.setText(file)

    def generate_main_keyfile(self):
        dialog = KeyfileGeneratorDialog(self)
        dialog.exec()
        
    def browse_usb_key(self):
        dialog = USBSelectionDialog(self)
        if dialog.exec() == QDialog.Accepted and dialog.usb_path:
            self.usb_path_field.setText(dialog.usb_path)
            self.usb_key_checkbox.setChecked(True)
    
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            urls = [url.toLocalFile() for url in event.mimeData().urls()]
            for url in urls:
                if os.path.isdir(url):
                    for root, _, files in os.walk(url):
                        for name in files:
                            file_path = os.path.join(root, name)
                            if not self.files_list.findItems(file_path, Qt.MatchExactly):
                                self.files_list.addItem(file_path)
                elif os.path.isfile(url):
                    if not self.files_list.findItems(url, Qt.MatchExactly):
                        self.files_list.addItem(url)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)

    def browse_output_location(self):
        dir_dialog = QFileDialog()
        dir_dialog.setFileMode(QFileDialog.Directory)
        if dir_dialog.exec():
            selected_dir = dir_dialog.selectedFiles()[0]
            self.output_dir_field.setText(selected_dir)
    
    def add_files(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        if file_dialog.exec():
            files = file_dialog.selectedFiles()
            for file_path in files:
                if self.files_list.findItems(file_path, Qt.MatchExactly):
                    continue
                self.files_list.addItem(file_path)
    
    def add_folder(self):
        dir_dialog = QFileDialog()
        dir_dialog.setFileMode(QFileDialog.Directory)
        if dir_dialog.exec():
            folder_path = dir_dialog.selectedFiles()[0]
            for root, _, files in os.walk(folder_path):
                for name in files:
                    file_path = os.path.join(root, name)
                    if self.files_list.findItems(file_path, Qt.MatchExactly):
                        continue
                    self.files_list.addItem(file_path)
    
    def remove_selected(self):
        for item in self.files_list.selectedItems():
            self.files_list.takeItem(self.files_list.row(item))

    def clear_files(self):
        self.files_list.clear()

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
        if not ZXCVBN_AVAILABLE or not self.strength_label:
            return
        if not password:
            self.strength_label.setText("Password strength: N/A")
            self.strength_label.setStyleSheet("color: #888888; font-size: 9pt;")
            return
        if len(password) > 72:
            self.strength_label.setText("Password strength: Strong")
            self.strength_label.setStyleSheet("color: #44DD44; font-size: 9pt;")
            return
        result = zxcvbn(password)
        score = result["score"]
        colors = {
            0: ("#FF4444", "Really?"),
            1: ("#FF8844", "Weak"),
            2: ("#FFAA44", "Fair"),
            3: ("#88DD44", "Good"),
            4: ("#44DD44", "Strong")}
        color, label = colors.get(score, ("#FF4444", "Really?"))
        self.strength_label.setText(f"Password strength: {label}")
        self.strength_label.setStyleSheet(f"color: {color}; font-size: 9pt;")

    def browse_usb_key(self):
        dialog = USBSelectionDialog(self)
        if dialog.exec() == QDialog.Accepted and dialog.usb_path:
            self.usb_path_field.setText(dialog.usb_path)
            self.usb_key_checkbox.setChecked(True)
    
    def create_archive(self):
        if self.files_list.count() == 0:
            dialog = CustomDialog("Warning", "Please add at LEAST one file to the archive.", self)
            dialog.exec()
            return
        keyfile_path = None
        password = ""
        if self.keyfile_group.isVisible():
            keyfile_path = self.main_keyfile_path_field.text().strip()
            if keyfile_path and not os.path.exists(keyfile_path):
                keyfile_path = None # Invalid
        else:
            password = self.password_field.text()
        use_usb_key = self.usb_key_checkbox.isChecked()
        usb_key_path = self.usb_path_field.text().strip() if use_usb_key else None
        if not password and not keyfile_path and not usb_key_path:
            dialog = CustomDialog("Warning", "You must provide a Password, Keyfile, or USB-codec Key.", self)
            dialog.exec()
            return
        archive_name = self.archive_name_field.text().strip()
        if not archive_name:
            dialog = CustomDialog("Warning", "Name for the archive cannot be empty.", self)
            dialog.exec()
            return
        output_dir = self.output_dir_field.text().strip()
        if not output_dir:
            dialog = CustomDialog("Warning", "Uh output dir pls?", self)
            dialog.exec()
            return

        if use_usb_key:
            if not usb_key_path:
                dialog = CustomDialog("Warning", "USB-codec is enabled but no USB-codec PATH selected.", self)
                dialog.exec()
                return
            try:
                from usb_codec import is_usb_key_initialized
                if not is_usb_key_initialized(usb_key_path):
                    dialog = CustomDialog("Error", "The selected USB does not fall under USB-codec; perhaps it is not setup.", self)
                    dialog.exec()
                    return
            except Exception as e:
                dialog = CustomDialog("Error", f"Failed to verify USB: {str(e)}", self)
                dialog.exec()
                return
        files = []
        for i in range(self.files_list.count()):
            files.append(self.files_list.item(i).text())
        compression_mapping = {
            "None": "none",
            "Normal (fast)": "normal",
            "Best (slow-er)": "best",
            "ULTRAKILL (probably slow)": "ultrakill",
            "[L] ULTRAKILL (???)": "[L] ultrakill"}
        detection_map_rev = {
            "Legacy (extension)": "legacy",
            "Magic bytes": "magic",
            "Entropy heuristic": "entropy",
            "Magic bytes + Entropy": "magic+entropy",
            "None (Smart Skipper disabled)": "none"}
        aead_map_rev = {"AES-256-GCM": "aes-gcm", "ChaCha20-Poly1305": "chacha20-poly1305"}
        self.archive_data = {
            "files": files,
            "archive_name": archive_name,
            "output_dir": output_dir,
            "password": password,
            "aead_algorithm": aead_map_rev.get(self.aead_combo.currentText(), "aes-gcm"),
            "use_argon2": self.use_argon2_checkbox.isChecked(),
            "pbkdf2_hash": self.pbkdf2_hash_combo.currentText(),
            "kdf_iterations": self.kdf_iterations_spinbox.value(),
            "argon2_time_cost": self.argon2_time_spinbox.value(),
            "argon2_memory_cost": self.argon2_memory_spinbox.value(),
            "argon2_parallelism": self.argon2_parallelism_spinbox.value(),
            "compression_level": compression_mapping[self.compression_combo.currentText()],
            "compression_detection": detection_map_rev.get(self.detection_mode_combo.currentText(), "legacy"),
            "entropy_threshold": self.entropy_threshold_spinbox.value(),
            "secure_clear": self.secure_clear_checkbox.isChecked(),
            "add_recovery_data": self.recovery_checkbox.isChecked(),
            "use_usb_key": use_usb_key,
            "usb_key_path": usb_key_path,
            "keyfile_path": keyfile_path,
            "chunk_size_mb": self.chunk_size_spinbox.value()}
        self.accept()

class ErrorExportDialog(QDialog):
    def __init__(self, title, message, errors, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(500, 300)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setStyleSheet("QTextEdit { background-color: #3C3C3C; color: #E0E0E0; border: 1px solid #5A5A5A; }")
        enable_win_dark_mode(self)
        self.errors = errors
        layout = QVBoxLayout(self)
        self.message_label = QLabel(title)
        self.message_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
        layout.addWidget(self.message_label)
        self.message_text = QTextEdit()
        self.message_text.setPlainText(message)
        self.message_text.setReadOnly(True)
        layout.addWidget(self.message_text)
        button_layout = QHBoxLayout()
        self.export_button = QPushButton("Export errors")
        icon_path = get_resource_path(os.path.join("img", "export_img.png"))
        self.export_button.setIcon(QIcon(icon_path))
        self.export_button.clicked.connect(self.export_errors)
        self.ok_button = QPushButton("OK")
        icon_path = get_resource_path(os.path.join("img", "continue_img.png"))
        self.ok_button.setIcon(QIcon(icon_path))
        self.ok_button.clicked.connect(self.accept)     
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.ok_button)
        layout.addLayout(button_layout)      
        self.setLayout(layout)
    
    def export_errors(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export errors", "this_software_fucking_sucks.txt", "Text file(s) (*.txt)")
        if file_path:
            with open(file_path, "w") as f:
                f.write("\n".join(self.errors))
            dialog = CustomDialog("Export successful", f"Errors exported to:\n{file_path}", self)
            dialog.exec()

class ProgressDialog(QDialog):
    canceled = pyqtSignal()
    
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(400, 150)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        layout = QVBoxLayout(self)       
        self.batch_label = QLabel("Total Progress: (0/0)")
        self.batch_progress_bar = QProgressBar()
        self.batch_progress_bar.setRange(0, 100)
        self.batch_progress_bar.setValue(0)
        self.file_label = QLabel("Current file:")
        self.file_progress_bar = QProgressBar()
        self.file_progress_bar.setRange(0, 100)
        self.file_progress_bar.setValue(0)        
        button_layout = QHBoxLayout()
        self.cancel_button = QPushButton("Cancel")
        enable_win_dark_mode(self)
        self.cancel_button.clicked.connect(self.cancel_operation)
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)
        layout.addWidget(self.batch_label)
        layout.addWidget(self.batch_progress_bar)
        layout.addWidget(self.file_label)
        layout.addWidget(self.file_progress_bar)
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def cancel_operation(self):
        self.canceled.emit()
        self.close()

    def update_batch_progress(self, current, total):
        self.batch_label.setText(f"Total progress: ({current}/{total})")
        if total > 0:
            self.batch_progress_bar.setValue(int((current / total) * 100))

class CustomArgon2Dialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Argon2ID memory cost :)")
        self.setModal(True)
        self.selected_value = 0
        self.setFixedSize(400, 260)
        main_layout = QVBoxLayout(self)
        info_label = QLabel("Choose an Argon2ID memory preset based on how fucking afraid you are:")
        info_label.setWordWrap(True)
        main_layout.addWidget(info_label)
        presets = {
            "Interactive (fast)": 32768,
            "Sensitive (balanced)": 65536,
            "Paranoid (reaaaaally slow)": 262144,
            "ULTRAKILL (what are you hiding?)": 524288,
            "Ok bro... (why?)": 1048576}      
        for name, value in presets.items():
            button = QPushButton(f"{name} - {value:,} KB ({value // 1024} MB)")
            button.clicked.connect(lambda checked, v=value: self.set_preset(v))
            main_layout.addWidget(button)
        cancel_button = QPushButton("Cancel")
        enable_win_dark_mode(self)
        cancel_button.clicked.connect(self.reject)
        main_layout.addWidget(cancel_button)

    def play_warning_sound(self):
        parent = self.parent()
        if parent and hasattr(parent, "sound_manager"):
            if not parent.mute_sfx:
                parent.sound_manager.play_sound("info.wav")

    def set_preset(self, value):
        if value >= 1048576:
            self.play_warning_sound()
            dialog = CustomDialog("Warning", "Warning Argon2ID\n\nThis option uses one WHOLE ass gigabyte of RAM per encrypt (a single file); this option is HIGHLY not recommended if you do not have high specs.", self)
            result = dialog.exec()
            if result == QDialog.Accepted:
                self.selected_value = value
                self.accept()
        else:
            self.selected_value = value
            self.accept()

class DebugConsole(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_app = parent
        self.setWindowTitle("DBG")
        self.setGeometry(150, 150, 600, 400)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        layout = QVBoxLayout(self)
        self.output_view = QTextEdit()
        self.output_view.setReadOnly(True)
        self.output_view.setStyleSheet("font-family: 'Consolas', 'Monaco', monospace; background-color: #1E1E1E; color: #E0E0E0;")
        enable_win_dark_mode(self)
        self.input_line = QLineEdit()
        self.input_line.setPlaceholderText("Enter command (e.g., ?help)...")
        self.input_line.returnPressed.connect(self.process_command)
        layout.addWidget(self.output_view)
        layout.addWidget(self.input_line)
        self.setLayout(layout)

    def append_text(self, text):
        clean_text = strip_ansi_codes(text)
        self.output_view.moveCursor(QTextCursor.End)
        self.output_view.insertPlainText(clean_text)
        self.output_view.moveCursor(QTextCursor.End)

    def process_command(self):
        command = self.input_line.text().strip()
        self.input_line.clear()
        self.append_text(f"\n\n>>> {command}\n")
        if not command:
            return
        if not command.startswith("?"):
            self.append_text("[ERROR] Unknown command. Commands must start with '?'.\n")
            return
        parts = command.split()
        cmd = parts[0]
        args = parts[1:]
        if cmd == "?chc_mem":
            self.check_memory_clearing()
        elif cmd == "?test_sfx":
            self.test_sound_effect(args)
        elif cmd == "?rand_pass":
            self.generate_password()
        elif cmd == "?help":
            self.append_text("\n\nAvailable commands:\n")
            self.append_text("  ?help             - Shows this help message.\n")
            self.append_text("  ?cls              - Clears the console.\n")
            self.append_text("  ?chc_mem          - Tests the secure memory clearing function.\n")
            self.append_text("  ?test_sfx [sound] - Plays a sound file (e.g., success.wav).\n")
            self.append_text("  ?rand_pass        - Generate a cryptographic secure password with secrets.\n")
        elif cmd == "?cls":
            self.output_view.clear()
        else:
            self.append_text(f"[ERROR] Unknown command '{cmd}'. Type '?help' for a list of commands.\n")

    def check_memory_clearing(self):
        from c_base import clear_buffer, isca
        import ctypes
        self.append_text("\n\n--- MCT ---\n")
        if not isca():
            self.append_text("Result: C library for secure memory clearing is NOT loaded.\n")
            self.append_text("Using fallback Python method (less secure).\n")
        else:
            self.append_text("Result: C library for secure memory clearing IS loaded.\n")
        test_string = b"If you can read this, the memory was not cleared."
        buffer = ctypes.create_string_buffer(len(test_string))
        buffer.raw = test_string
        self.append_text(f"Original buffer content: {buffer.raw.decode("utf-8", errors="ignore")}\n")
        clear_buffer(buffer)
        cleared_content = buffer.raw
        self.append_text(f"Buffer content after clearing: {cleared_content}\n")
        if all(b == 0 for b in cleared_content):
            self.append_text("Success: Buffer was successfully zeroed out.\n")
        else:
            self.append_text("Failure: Buffer still contains data (oops)...\n")
        self.append_text("--------------------------\n")

    def generate_password(self, length=64, include_symbols=True):
        chars = string.ascii_letters + string.digits
        if include_symbols:
            chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
        password = "".join(secrets.choice(chars) for _ in range(length))
        self.append_text("\n\n--- RP ---\n")
        self.append_text(f"Random {length} char crypto password:\n")
        self.append_text(f"`{password}`\n")
        self.append_text(f"(Copypaste ADF – {len(password)} chars)\n")
        self.append_text("--------------------------\n")

    def test_sound_effect(self, args):
        if not args:
            self.append_text("[ERROR] Missing argument; usage: ?test_sfx [sound_name]\n")
            return
        sound_name = args[0]
        self.append_text(f"Attempting to play sound: {sound_name}\n")
        if self.parent_app and hasattr(self.parent_app, "sound_manager"):
            self.parent_app.sound_manager.play_sound(sound_name)
            self.append_text("Play command sent. Check your audio output.\n")
        else:
            self.append_text("[ERROR] Sound manager not found.\n")

    def closeEvent(self, event):
        self.hide()
        event.ignore()

class USBSetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Setup USB-codec")
        self.setFixedSize(500, 400)
        self.setWindowFlags((self.windowFlags() | Qt.WindowType.MSWindowsFixedSizeDialogHint) & ~Qt.WindowType.WindowContextHelpButtonHint)
        enable_win_dark_mode(self)
        self.usb_path = None
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(12)
        info_label = QLabel("Select a USB drive to initialize as a PyKryptor key device.\nThis will create a random keyfile on the USB that will be used for encryption.")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("padding: 10px;")
        main_layout.addWidget(info_label)
        usb_group = QGroupBox("Available USB drives")
        usb_layout = QVBoxLayout()
        self.usb_list = QListWidget()
        self.usb_list.setMinimumHeight(150)
        refresh_button = QPushButton("Refresh")
        icon_path = get_resource_path(os.path.join("img", "refresh_img.png"))
        refresh_button.setIcon(QIcon(icon_path))
        refresh_button.clicked.connect(self.refresh_usb_list)
        usb_layout.addWidget(self.usb_list)
        usb_layout.addWidget(refresh_button)
        usb_group.setLayout(usb_layout)
        main_layout.addWidget(usb_group)
        status_label = QLabel("")
        status_label.setWordWrap(True)
        status_label.setStyleSheet("color: #888888; padding: 5px;")
        main_layout.addWidget(status_label)
        self.status_label = status_label
        self.refresh_usb_list()
        button_layout = QHBoxLayout()
        setup_button = QPushButton("Confirm")
        icon_path = get_resource_path(os.path.join("img", "confirm_img.png"))
        setup_button.setIcon(QIcon(icon_path))
        setup_button.clicked.connect(self.setup_usb)
        cancel_button = QPushButton("Cancel")
        icon_path = get_resource_path(os.path.join("img", "cancel_img.png"))
        cancel_button.setIcon(QIcon(icon_path))
        cancel_button.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(setup_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)
    
    def refresh_usb_list(self):
        self.usb_list.clear()
        if not USB_CODEC_AVAILABLE:
            self.status_label.setText("USB-codec not available")
            return
        try:
            drives = list_usb_drives()
            for drive in drives:
                initialized = is_usb_key_initialized(drive)
                info = get_usb_key_info(drive) if initialized else None
                item_text = f"{drive}"
                if initialized and info:
                    item_text += f" (Initialized - UUID: {info["uuid"][:8]}...)"
                item = QListWidgetItem(item_text)
                item.setData(Qt.ItemDataRole.UserRole, drive)
                if initialized:
                    item.setForeground(QColor("#4A90E2"))
                    try:
                        icon_path = get_resource_path(os.path.join("img", "usb_img.png"))
                        if os.path.exists(icon_path):
                            item.setIcon(QIcon(icon_path))
                    except:
                        pass
                self.usb_list.addItem(item)
            if not drives:
                self.status_label.setText("No USB drives detected; plug one in nitwit.")
            else:
                self.status_label.setText(f"Found {len(drives)} USB drive(s)")
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
    
    def setup_usb(self):
        selected_items = self.usb_list.selectedItems()
        if not selected_items:
            dialog = CustomDialog("Warning", "Please select a USB drive to initialize for USB-codec.", self)
            dialog.exec()
            return
        usb_path = selected_items[0].data(Qt.ItemDataRole.UserRole)
        if is_usb_key_initialized(usb_path):
            dialog = CustomDialog("Warning", "This USB is already initialized as a USB-codec.\n\nIf you want to reinitialize it, you'll need to manually delete the key files first.", self)
            dialog.exec()
            return
        try:
            usb_key, uuid = setup_usb_key(usb_path)
            if self.parent() and hasattr(self.parent(), "sound_manager") and not self.parent().mute_sfx:
                self.parent().sound_manager.play_sound("success.wav")
            dialog = CustomDialog("Success", f"USB-codec initialized successfully.\n\nUUID: {uuid}\n\nKeep this USB safe; you'll need it to decrypt files encrypted with it.", self)
            dialog.exec()
            self.usb_path = usb_path
            self.accept()
        except Exception as e:
            if self.parent() and hasattr(self.parent(), "sound_manager") and not self.parent().mute_sfx:
                self.parent().sound_manager.play_sound("error.wav")
            dialog = CustomDialog("Error", f"Failed to setup USB-codec:\n{str(e)}", self)
            dialog.exec()

class USBSelectionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select USB key")
        self.setFixedSize(500, 360)
        self.setWindowFlags((self.windowFlags() | Qt.WindowType.MSWindowsFixedSizeDialogHint) & ~Qt.WindowType.WindowContextHelpButtonHint)
        enable_win_dark_mode(self)
        self.usb_path = None
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(12)
        info_label = QLabel("You are either using a USB to encrypt an archive or using a USB to decrypt it.\nFor decryption insert the corresponding USB; for encryption select an intialized USB-codec key.")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("padding: 10px;")
        main_layout.addWidget(info_label)
        usb_group = QGroupBox("Available USB drives")
        usb_layout = QVBoxLayout()
        self.usb_list = QListWidget()
        self.usb_list.setMinimumHeight(150)
        refresh_button = QPushButton("Refresh")
        icon_path = get_resource_path(os.path.join("img", "refresh_img.png"))
        refresh_button.setIcon(QIcon(icon_path))
        refresh_button.clicked.connect(self.refresh_usb_list)
        usb_layout.addWidget(self.usb_list)
        usb_layout.addWidget(refresh_button)
        usb_group.setLayout(usb_layout)
        main_layout.addWidget(usb_group)
        status_label = QLabel("")
        status_label.setWordWrap(True)
        status_label.setStyleSheet("color: #888888; padding: 5px;")
        main_layout.addWidget(status_label)
        self.status_label = status_label
        self.refresh_usb_list()
        button_layout = QHBoxLayout()
        select_button = QPushButton("Select USB")
        icon_path = get_resource_path(os.path.join("img", "confirm_img.png"))
        select_button.setIcon(QIcon(icon_path))
        select_button.clicked.connect(self.select_usb)
        cancel_button = QPushButton("Cancel")
        icon_path = get_resource_path(os.path.join("img", "cancel_img.png"))
        cancel_button.setIcon(QIcon(icon_path))
        cancel_button.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(select_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)
    
    def refresh_usb_list(self):
        self.usb_list.clear()
        if not USB_CODEC_AVAILABLE:
            self.status_label.setText("USB-codec not available")
            return
        try:
            drives = list_usb_drives()
            initialized_drives = []
            for drive in drives:
                if is_usb_key_initialized(drive):
                    info = get_usb_key_info(drive)
                    item_text = f"{drive} (UUID: {info['uuid'][:12]}...)"
                    item = QListWidgetItem(item_text)
                    item.setData(Qt.ItemDataRole.UserRole, drive)
                    item.setForeground(QColor("#4A90E2"))
                    try:
                        icon_path = get_resource_path(os.path.join("img", "usb_img.png"))
                        if os.path.exists(icon_path):
                            item.setIcon(QIcon(icon_path))
                    except:
                        pass
                    self.usb_list.addItem(item)
                    initialized_drives.append(drive)
            if not initialized_drives:
                self.status_label.setText("No initialized USB-codec keys were found; maybe double check ya USB?")
            else:
                self.status_label.setText(f"Found {len(initialized_drives)} initialized USB(s)")
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
    
    def select_usb(self):
        selected_items = self.usb_list.selectedItems()
        if not selected_items:
            dialog = CustomDialog("Warning", "Please select a USB drive.", self)
            dialog.exec()
            return
        usb_path = selected_items[0].data(Qt.ItemDataRole.UserRole)
        try:
            from usb_codec import get_usb_key
            get_usb_key(usb_path) 
            self.usb_path = usb_path
            self.accept()
        except Exception as e:
            if self.parent() and hasattr(self.parent(), "sound_manager") and not self.parent().mute_sfx:
                self.parent().sound_manager.play_sound("error.wav")
            dialog = CustomDialog("Error", f"{str(e)}\n\nPlug in the original USB containing the USB-codec format used to encrypt this archive.", self)
            dialog.exec()

## end