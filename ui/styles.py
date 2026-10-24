class ThemeManager:
    """
    WinUI 现代双模式调色板与 QSS 样式表 (极夜深色 / 日光浅色)
    """
    DARK_QSS = """
        QWidget {
            color: #FFFFFF;
            font-family: "Segoe UI Variable Text", "Segoe UI", "Microsoft YaHei UI", sans-serif;
            font-size: 13px;
        }
        #Sidebar {
            background-color: rgba(20, 24, 33, 0.78);
            border-right: 1px solid rgba(255, 255, 255, 0.08);
            border-top-left-radius: 12px;
            border-bottom-left-radius: 12px;
        }
        #NavBtn {
            background: transparent;
            border: none;
            border-radius: 8px;
            color: #B0B7C3;
            font-size: 13px;
            font-weight: 500;
            text-align: left;
            padding: 8px 12px;
        }
        #NavBtn:hover {
            background-color: rgba(255, 255, 255, 0.08);
            color: #FFFFFF;
        }
        #NavBtn:checked {
            background-color: rgba(79, 70, 229, 0.25);
            color: #818CF8;
            font-weight: 600;
            border-left: 3px solid #6366F1;
        }
        #CentralWidget {
            background-color: rgba(15, 17, 23, 0.85);
            border-top-right-radius: 12px;
            border-bottom-right-radius: 12px;
        }
        #TitleBar {
            background-color: transparent;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        #TitleLabel {
            font-size: 14px;
            font-weight: 600;
            color: #E2E8F0;
            letter-spacing: 0.5px;
        }
        #BadgeLabel {
            background-color: rgba(99, 102, 241, 0.2);
            color: #A5B4FC;
            border: 1px solid rgba(99, 102, 241, 0.4);
            border-radius: 4px;
            padding: 1px 6px;
            font-size: 11px;
            font-weight: 600;
        }
        #PillShield {
            background-color: rgba(16, 185, 129, 0.15);
            color: #34D399;
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 10px;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: 600;
        }
        #PillHardware {
            background-color: rgba(245, 158, 11, 0.15);
            color: #FBBF24;
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-radius: 10px;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: 600;
        }
        #Card {
            background-color: rgba(30, 35, 48, 0.65);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
        }
        QLineEdit, QComboBox {
            background-color: rgba(20, 24, 33, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 6px;
            padding: 6px 10px;
            color: #FFFFFF;
        }
        QLineEdit:focus, QComboBox:focus {
            border: 1px solid #6366F1;
            background-color: rgba(20, 24, 33, 0.95);
        }
        QPushButton#BtnPrimary {
            background-color: #4F46E5;
            color: #FFFFFF;
            border: none;
            border-radius: 6px;
            padding: 8px 16px;
            font-weight: 600;
        }
        QPushButton#BtnPrimary:hover {
            background-color: #4338CA;
        }
        QPushButton#BtnSecondary {
            background-color: rgba(255, 255, 255, 0.08);
            color: #E2E8F0;
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 6px;
            padding: 8px 16px;
            font-weight: 500;
        }
        QPushButton#BtnSecondary:hover {
            background-color: rgba(255, 255, 255, 0.15);
        }
        QProgressBar {
            background-color: rgba(255, 255, 255, 0.08);
            border: none;
            border-radius: 4px;
            text-align: center;
            color: #FFFFFF;
            font-weight: 600;
            height: 10px;
        }
        QProgressBar::chunk {
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #4F46E5, stop:1 #06B6D4);
            border-radius: 4px;
        }
        QPlainTextEdit {
            background-color: rgba(12, 14, 20, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            font-family: "Consolas", "Courier New", monospace;
            font-size: 12px;
            color: #A5B4FC;
            padding: 8px;
        }
        #DropZone {
            background-color: rgba(20, 24, 33, 0.45);
            border: 2px dashed rgba(99, 102, 241, 0.35);
            border-radius: 8px;
            color: #CBD5E1;
            font-size: 13px;
            padding: 8px;
        }
        #DropZone:hover {
            background-color: rgba(79, 70, 229, 0.12);
            border: 2px dashed #818CF8;
            color: #FFFFFF;
        }
        QTabWidget::pane {
            border: 1px solid rgba(255, 255, 255, 0.08);
            background-color: rgba(18, 22, 31, 0.75);
            border-bottom-left-radius: 8px;
            border-bottom-right-radius: 8px;
            border-top-right-radius: 8px;
            top: -1px;
        }
        QTabBar::tab {
            background-color: rgba(20, 24, 33, 0.5);
            color: #94A3B8;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-bottom: none;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            padding: 6px 14px;
            margin-right: 4px;
            font-size: 12px;
            font-weight: 500;
        }
        QTabBar::tab:hover {
            background-color: rgba(255, 255, 255, 0.08);
            color: #E2E8F0;
        }
        QTabBar::tab:selected {
            background-color: rgba(18, 22, 31, 0.85);
            color: #818CF8;
            border-top: 2px solid #6366F1;
            border-left: 1px solid rgba(255, 255, 255, 0.12);
            border-right: 1px solid rgba(255, 255, 255, 0.12);
            font-weight: 600;
        }
        QTabBar::tab:disabled {
            color: #64748B;
            background-color: rgba(0, 0, 0, 0.2);
        }
        QListWidget {
            background-color: transparent;
            border: none;
            border-radius: 6px;
            padding: 4px;
            outline: none;
        }
        QListWidget::item {
            border-radius: 6px;
            margin-bottom: 2px;
        }
        QScrollBar:vertical {
            background: transparent;
            width: 6px;
            margin: 0px;
        }
        QScrollBar::handle:vertical {
            background: rgba(255, 255, 255, 0.15);
            min-height: 20px;
            border-radius: 3px;
        }
        QScrollBar::handle:vertical:hover {
            background: rgba(99, 102, 241, 0.5);
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QScrollBar:horizontal {
            background: transparent;
            height: 6px;
            margin: 0px;
        }
        QScrollBar::handle:horizontal {
            background: rgba(255, 255, 255, 0.15);
            min-width: 20px;
            border-radius: 3px;
        }
        QScrollBar::handle:horizontal:hover {
            background: rgba(99, 102, 241, 0.5);
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0px;
        }
    """

    LIGHT_QSS = """
        QWidget {
            color: #1E293B;
            font-family: "Segoe UI Variable Text", "Segoe UI", "Microsoft YaHei UI", sans-serif;
            font-size: 13px;
        }
        #Sidebar {
            background-color: rgba(241, 245, 249, 0.88);
            border-right: 1px solid rgba(0, 0, 0, 0.08);
            border-top-left-radius: 12px;
            border-bottom-left-radius: 12px;
        }
        #NavBtn {
            background: transparent;
            border: none;
            border-radius: 8px;
            color: #475569;
            font-size: 13px;
            font-weight: 500;
            text-align: left;
            padding: 8px 12px;
        }
        #NavBtn:hover {
            background-color: rgba(0, 0, 0, 0.06);
            color: #0F172A;
        }
        #NavBtn:checked {
            background-color: rgba(79, 70, 229, 0.15);
            color: #4F46E5;
            font-weight: 600;
            border-left: 3px solid #4F46E5;
        }
        #CentralWidget {
            background-color: rgba(255, 255, 255, 0.92);
            border-top-right-radius: 12px;
            border-bottom-right-radius: 12px;
        }
        #TitleBar {
            background-color: transparent;
            border-bottom: 1px solid rgba(0, 0, 0, 0.06);
        }
        #TitleLabel {
            font-size: 14px;
            font-weight: 600;
            color: #0F172A;
        }
        #BadgeLabel {
            background-color: rgba(99, 102, 241, 0.15);
            color: #4338CA;
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 4px;
            padding: 1px 6px;
            font-size: 11px;
            font-weight: 600;
        }
        #PillShield {
            background-color: rgba(16, 185, 129, 0.15);
            color: #047857;
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 10px;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: 600;
        }
        #PillHardware {
            background-color: rgba(245, 158, 11, 0.15);
            color: #B45309;
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-radius: 10px;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: 600;
        }
        #Card {
            background-color: rgba(248, 250, 252, 0.85);
            border: 1px solid rgba(0, 0, 0, 0.08);
            border-radius: 10px;
        }
        QLineEdit, QComboBox {
            background-color: #FFFFFF;
            border: 1px solid rgba(0, 0, 0, 0.15);
            border-radius: 6px;
            padding: 6px 10px;
            color: #0F172A;
        }
        QLineEdit:focus, QComboBox:focus {
            border: 1px solid #4F46E5;
        }
        QPushButton#BtnPrimary {
            background-color: #4F46E5;
            color: #FFFFFF;
            border: none;
            border-radius: 6px;
            padding: 8px 16px;
            font-weight: 600;
        }
        QPushButton#BtnPrimary:hover {
            background-color: #4338CA;
        }
        QPushButton#BtnSecondary {
            background-color: rgba(0, 0, 0, 0.05);
            color: #334155;
            border: 1px solid rgba(0, 0, 0, 0.12);
            border-radius: 6px;
            padding: 8px 16px;
            font-weight: 500;
        }
        QPushButton#BtnSecondary:hover {
            background-color: rgba(0, 0, 0, 0.1);
        }
        QProgressBar {
            background-color: rgba(0, 0, 0, 0.06);
            border: none;
            border-radius: 4px;
            text-align: center;
            color: #1E293B;
            font-weight: 600;
            height: 10px;
        }
        QProgressBar::chunk {
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #4F46E5, stop:1 #0284C7);
            border-radius: 4px;
        }
        QPlainTextEdit {
            background-color: #F8FAFC;
            border: 1px solid rgba(0, 0, 0, 0.1);
            border-radius: 8px;
            font-family: "Consolas", "Courier New", monospace;
            font-size: 12px;
            color: #1E293B;
            padding: 8px;
        }
        #DropZone {
            background-color: rgba(241, 245, 249, 0.65);
            border: 2px dashed rgba(79, 70, 229, 0.35);
            border-radius: 8px;
            color: #475569;
            font-size: 13px;
            padding: 8px;
        }
        #DropZone:hover {
            background-color: rgba(79, 70, 229, 0.08);
            border: 2px dashed #4F46E5;
            color: #1E293B;
        }
        QTabWidget::pane {
            border: 1px solid rgba(0, 0, 0, 0.08);
            background-color: rgba(248, 250, 252, 0.85);
            border-bottom-left-radius: 8px;
            border-bottom-right-radius: 8px;
            border-top-right-radius: 8px;
            top: -1px;
        }
        QTabBar::tab {
            background-color: rgba(0, 0, 0, 0.04);
            color: #64748B;
            border: 1px solid rgba(0, 0, 0, 0.08);
            border-bottom: none;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            padding: 6px 14px;
            margin-right: 4px;
            font-size: 12px;
            font-weight: 500;
        }
        QTabBar::tab:hover {
            background-color: rgba(0, 0, 0, 0.08);
            color: #0F172A;
        }
        QTabBar::tab:selected {
            background-color: rgba(248, 250, 252, 0.95);
            color: #4F46E5;
            border-top: 2px solid #4F46E5;
            border-left: 1px solid rgba(0, 0, 0, 0.1);
            border-right: 1px solid rgba(0, 0, 0, 0.1);
            font-weight: 600;
        }
        QTabBar::tab:disabled {
            color: #94A3B8;
            background-color: rgba(0, 0, 0, 0.02);
        }
        QListWidget {
            background-color: transparent;
            border: none;
            border-radius: 6px;
            padding: 4px;
            outline: none;
        }
        QListWidget::item {
            border-radius: 6px;
            margin-bottom: 2px;
        }
        QScrollBar:vertical {
            background: transparent;
            width: 6px;
            margin: 0px;
        }
        QScrollBar::handle:vertical {
            background: rgba(0, 0, 0, 0.15);
            min-height: 20px;
            border-radius: 3px;
        }
        QScrollBar::handle:vertical:hover {
            background: rgba(79, 70, 229, 0.4);
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
    """

    WINUI_QSS = DARK_QSS

    @classmethod
    def get_qss(cls, mode="dark"):
        return cls.LIGHT_QSS if mode == "light" else cls.DARK_QSS
