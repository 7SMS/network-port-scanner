"""
QSS stylesheet — dark theme with neon-green accents.

Kept as a single string constant so it ships with the code (no resource files
to package). If you want to theme this differently, edit STYLESHEET below.
"""

# Color palette — exposed so other components can use the same colors.
COLORS = {
    "bg":          "#0a0e14",   # near-black with a hint of blue
    "bg_alt":      "#11161e",   # slightly lighter for cards/panels
    "bg_hover":    "#1a2028",
    "border":      "#1f2933",
    "border_hot":  "#2d3744",
    "text":        "#c5d1de",
    "text_dim":    "#7a8694",
    "text_bright": "#e4ecf5",
    "accent":      "#39ff14",   # neon green
    "accent_dim":  "#2bc70f",
    "accent_glow": "#39ff1433",
    "warn":        "#ffb000",
    "danger":      "#ff3860",
    "info":        "#3abff8",
    "open":        "#39ff14",
    "closed":      "#7a8694",
    "filtered":    "#ffb000",
    "error":       "#ff3860",
}

STYLESHEET = f"""
* {{
    font-family: "Consolas", "Menlo", "Monaco", "Courier New", monospace;
    font-size: 13px;
    color: {COLORS['text']};
}}

QMainWindow, QWidget {{
    background-color: {COLORS['bg']};
}}

/* ---- Sidebar ---- */
#Sidebar {{
    background-color: {COLORS['bg_alt']};
    border-right: 1px solid {COLORS['border']};
}}

#SidebarTitle {{
    color: {COLORS['accent']};
    font-size: 18px;
    font-weight: bold;
    padding: 16px 12px 4px 16px;
    border: none;
    background: transparent;
}}

#SidebarSubtitle {{
    color: {COLORS['text_dim']};
    font-size: 10px;
    padding: 0px 12px 4px 16px;
    border: none;
    background: transparent;
    letter-spacing: 2px;
}}

#DevSignature {{
    color: {COLORS['accent']};
    font-size: 11px;
    font-weight: bold;
    padding: 0px 12px 16px 16px;
    border: none;
    background: transparent;
    letter-spacing: 3px;
}}

QPushButton#NavButton {{
    background-color: transparent;
    color: {COLORS['text']};
    border: none;
    border-left: 3px solid transparent;
    text-align: left;
    padding: 12px 16px;
    font-size: 13px;
}}
QPushButton#NavButton:hover {{
    background-color: {COLORS['bg_hover']};
    color: {COLORS['text_bright']};
}}
QPushButton#NavButton:checked {{
    background-color: {COLORS['bg_hover']};
    color: {COLORS['accent']};
    border-left: 3px solid {COLORS['accent']};
    font-weight: bold;
}}

/* ---- Cards/Panels ---- */
QFrame#Card {{
    background-color: {COLORS['bg_alt']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
}}

QLabel#CardTitle {{
    color: {COLORS['accent']};
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 2px;
    background: transparent;
    border: none;
}}

QLabel#FieldLabel {{
    color: {COLORS['text_dim']};
    font-size: 11px;
    background: transparent;
    border: none;
}}

QLabel {{
    background: transparent;
    border: none;
}}

/* ---- Inputs ---- */
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {{
    background-color: {COLORS['bg']};
    color: {COLORS['text_bright']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    padding: 6px 8px;
    selection-background-color: {COLORS['accent_dim']};
    selection-color: {COLORS['bg']};
}}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {{
    border: 1px solid {COLORS['accent']};
}}
QLineEdit:hover, QSpinBox:hover, QDoubleSpinBox:hover, QComboBox:hover {{
    border: 1px solid {COLORS['border_hot']};
}}

QComboBox::drop-down {{
    border: none;
    background: transparent;
    width: 20px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {COLORS['accent']};
    margin-right: 8px;
}}
QComboBox QAbstractItemView {{
    background-color: {COLORS['bg_alt']};
    color: {COLORS['text']};
    border: 1px solid {COLORS['border_hot']};
    selection-background-color: {COLORS['bg_hover']};
    selection-color: {COLORS['accent']};
    outline: 0;
}}

/* ---- Buttons ---- */
QPushButton {{
    background-color: {COLORS['bg_alt']};
    color: {COLORS['text']};
    border: 1px solid {COLORS['border_hot']};
    border-radius: 4px;
    padding: 8px 16px;
    font-weight: bold;
}}
QPushButton:hover {{
    background-color: {COLORS['bg_hover']};
    border: 1px solid {COLORS['accent_dim']};
    color: {COLORS['text_bright']};
}}
QPushButton:pressed {{
    background-color: {COLORS['border']};
}}
QPushButton:disabled {{
    color: {COLORS['text_dim']};
    border: 1px solid {COLORS['border']};
    background-color: {COLORS['bg_alt']};
}}

QPushButton#PrimaryButton {{
    background-color: {COLORS['accent_dim']};
    color: {COLORS['bg']};
    border: 1px solid {COLORS['accent']};
}}
QPushButton#PrimaryButton:hover {{
    background-color: {COLORS['accent']};
}}
QPushButton#PrimaryButton:disabled {{
    background-color: {COLORS['border']};
    color: {COLORS['text_dim']};
    border: 1px solid {COLORS['border_hot']};
}}

QPushButton#DangerButton {{
    background-color: transparent;
    color: {COLORS['danger']};
    border: 1px solid {COLORS['danger']};
}}
QPushButton#DangerButton:hover {{
    background-color: {COLORS['danger']};
    color: {COLORS['bg']};
}}

/* ---- Progress ---- */
QProgressBar {{
    background-color: {COLORS['bg']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    text-align: center;
    color: {COLORS['text_bright']};
    height: 18px;
}}
QProgressBar::chunk {{
    background-color: {COLORS['accent_dim']};
    border-radius: 3px;
}}

/* ---- Terminal output ---- */
QTextEdit#Terminal, QPlainTextEdit#Terminal {{
    background-color: #050709;
    color: {COLORS['text']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    padding: 8px;
    font-family: "Consolas", "Menlo", "Monaco", "Courier New", monospace;
    font-size: 12px;
    selection-background-color: {COLORS['accent_dim']};
    selection-color: {COLORS['bg']};
}}

/* ---- Table — applies to BOTH QTableWidget and QTableView ---- */
QTableWidget, QTableView {{
    background-color: {COLORS['bg_alt']};
    color: {COLORS['text']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    gridline-color: {COLORS['border']};
    selection-background-color: {COLORS['bg_hover']};
    selection-color: {COLORS['accent']};
    alternate-background-color: #0d1219;
}}
QTableWidget::item, QTableView::item {{
    padding: 4px;
    border: none;
    /* Force dark colors on cells to override any palette fallbacks.
       Without this, QTableView falls back to system palette which is
       white/light grey on most desktops. */
    background-color: transparent;
    color: {COLORS['text']};
}}
QTableWidget::item:alternate, QTableView::item:alternate {{
    background-color: #0d1219;
}}
QTableWidget::item:selected, QTableView::item:selected {{
    background-color: {COLORS['bg_hover']};
    color: {COLORS['accent']};
}}
QTableWidget::item:selected:alternate, QTableView::item:selected:alternate {{
    background-color: {COLORS['bg_hover']};
    color: {COLORS['accent']};
}}
QHeaderView {{
    background-color: {COLORS['bg']};
    border: none;
}}
QHeaderView::section {{
    background-color: {COLORS['bg']};
    color: {COLORS['accent']};
    border: none;
    border-right: 1px solid {COLORS['border']};
    border-bottom: 1px solid {COLORS['border']};
    padding: 6px 8px;
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 1px;
}}
QTableCornerButton::section {{
    background-color: {COLORS['bg']};
    border: none;
}}

/* ---- Scrollbars ---- */
QScrollBar:vertical {{
    background: {COLORS['bg']};
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {COLORS['border_hot']};
    min-height: 20px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical:hover {{
    background: {COLORS['accent_dim']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    background: none; height: 0;
}}
QScrollBar:horizontal {{
    background: {COLORS['bg']};
    height: 10px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {COLORS['border_hot']};
    min-width: 20px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {COLORS['accent_dim']};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    background: none; width: 0;
}}

/* ---- Tabs / Splitter ---- */
QSplitter::handle {{
    background-color: {COLORS['border']};
}}
QSplitter::handle:hover {{
    background-color: {COLORS['accent_dim']};
}}

/* ---- Group Box ---- */
QGroupBox {{
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    margin-top: 14px;
    padding-top: 8px;
    color: {COLORS['accent']};
    font-weight: bold;
    font-size: 11px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    background-color: {COLORS['bg']};
}}

/* ---- Status bar ---- */
QStatusBar {{
    background-color: {COLORS['bg_alt']};
    color: {COLORS['text_dim']};
    border-top: 1px solid {COLORS['border']};
}}

/* ---- Checkbox ---- */
QCheckBox {{
    color: {COLORS['text']};
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    border: 1px solid {COLORS['border_hot']};
    border-radius: 2px;
    background-color: {COLORS['bg']};
}}
QCheckBox::indicator:checked {{
    background-color: {COLORS['accent_dim']};
    border: 1px solid {COLORS['accent']};
}}
QCheckBox::indicator:hover {{
    border: 1px solid {COLORS['accent']};
}}

/* ---- Dialogs ---- */
QMessageBox, QDialog {{
    background-color: {COLORS['bg_alt']};
}}
QMessageBox QLabel, QDialog QLabel {{
    color: {COLORS['text']};
    background: transparent;
}}

/* ---- Disclaimer ---- */
#DisclaimerBanner {{
    background-color: {COLORS['bg_alt']};
    color: {COLORS['warn']};
    border: 1px solid {COLORS['warn']};
    border-radius: 4px;
    padding: 6px 12px;
    font-size: 11px;
    letter-spacing: 1px;
}}
"""
