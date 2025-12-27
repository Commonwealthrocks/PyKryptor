## stylez.py
## last updated: 27/12/2025 <d/m/y>
## p-y-k-x
STYLE_SHEET = """
QWidget {
    font-family: 'MS Shell Dlg 2', 'Tahoma', 'Arial';
    font-size: 10pt;
    color: #D0D0D0;
    background-color: #202020;
}
QFrame#mainFrame {
    border: 1px solid #2E3A3E;
    background-color: #202020;
    border-radius: 0px;
    padding: 5px;
}
QScrollBar:vertical {
    border: none;
    background: #202020;
    width: 10px;
    margin: 0px 0px 0px 0px;
}
QScrollBar::handle:vertical {
    background: #3E4E52;
    min-height: 20px;
    border-radius: 0px;
}
QScrollBar::handle:vertical:hover {
    background: #4A5E62;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    border: none;
    background: none;
    height: 0px;
    width: 0px;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: #000000;
}
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
    background-color: #202020;
    border: 1px solid #3E4E52;
    color: #D0D0D0;
    padding: 3px;
    selection-background-color: #4A5E62;
}
QPushButton {
    background-color: #202020;
    border: 1px solid #3E4E52;
    color: #D0D0D0;
    padding: 5px 15px;
    border-radius: 2px;
}
QPushButton:hover {
    background-color: #3E4E52;
    border: 1px solid #4A5E62;
}
QPushButton:pressed {
    background-color: #2A363A;
    border: 1px solid #3E4E52;
}
QLabel {
    color: #D0D0D0;
}
QProgressBar {
    border: 1px solid #3E4E52;
    background-color: #2E3A3E;
    color: #D0D0D0;
    text-align: center;
}
QProgressBar::chunk {
    background-color: #3CB371;
    border-radius: 2px;
}
QGroupBox {
    border: 1px solid #3E4E52;
    border-radius: 3px;
    margin-top: 1em;
    padding: 8px;
    background-color: #202020;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top center;
    padding: 0 3px;
    background-color: #202020;
    color: #C0C0C0;
}
QTabWidget::pane {
    border-top: 1px solid #3E4E52;
    background: #202020;
}
QTabBar::tab {
    background: #202020;
    color: #C0C0C0;
    border: 1px solid #3E4E52;
    border-bottom-color: #1C2526;
    border-top-left-radius: 3px;
    border-top-right-radius: 3px;
    min-width: 8ex;
    padding: 4px;
}
QTabBar::tab:selected {
    background: #1C2526;
    border-color: #3E4E52;
    border-bottom-color: #1C2526;
}
"""

## end 