class ThemeManager:
    WINUI_QSS = """
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
            background-color: rgba(99, 102, 241, 0.25);
            color: #A5B4FC;
            font-weight: 600;
        }
        #LogoBadge {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #10B981, stop:1 #059669);
            color: #FFFFFF;
            border-radius: 8px;
            font-weight: bold;
            font-size: 15px;
        }
        #Card {
            background-color: rgba(26, 32, 46, 0.68);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
        }
        #TitleBar {
            background: transparent;
        }
        QListWidget {
            background-color: rgba(15, 20, 30, 0.45);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 8px;
            outline: none;
        }
        QListWidget::item {
            padding: 8px 10px;
            margin: 2px;
            border-radius: 6px;
            color: #E2E8F0;
        }
        QListWidget::item:hover {
            background-color: rgba(255, 255, 255, 0.06);
        }
        QListWidget::item:selected {
            background-color: rgba(99, 102, 241, 0.35);
            color: #FFFFFF;
        }
        QTabWidget::pane {
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 8px;
            background-color: transparent;
        }
        QTabBar::tab {
            background: rgba(15, 20, 30, 0.5);
            color: #94A3B8;
            padding: 7px 14px;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            margin-right: 2px;
            border: 1px solid transparent;
        }
        QTabBar::tab:selected {
            background: rgba(99, 102, 241, 0.4);
            color: #FFFFFF;
            font-weight: bold;
            border: 1px solid rgba(255, 255, 255, 0.12);
        }
        QLineEdit {
            background-color: rgba(15, 20, 30, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 8px 12px;
            color: #FFFFFF;
        }
        QLineEdit:focus {
            border: 1px solid #6366F1;
            background-color: rgba(15, 20, 30, 0.85);
        }
        QLineEdit:disabled {
            background-color: rgba(255, 255, 255, 0.03);
            color: #64748B;
        }
        QComboBox {
            background-color: rgba(15, 20, 30, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 6px 12px;
            color: #FFFFFF;
        }
        QComboBox:focus {
            border: 1px solid #6366F1;
        }
        QPushButton {
            background-color: #4F46E5;
            color: #FFFFFF;
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 8px;
            padding: 8px 14px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #4338CA;
        }
        QPushButton:disabled {
            background-color: rgba(255, 255, 255, 0.05);
            color: #64748B;
            border: none;
        }
        QPushButton#BtnSecondary {
            background-color: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.08);
            color: #E2E8F0;
        }
        QPushButton#BtnSecondary:hover {
            background-color: rgba(255, 255, 255, 0.15);
            color: #FFFFFF;
        }
        QPushButton#BtnLock {
            background-color: rgba(255, 255, 255, 0.05);
            border: 1px solid #6366F1;
            color: #A5B4FC;
        }
        QPushButton#BtnLock:hover {
            background-color: #4F46E5;
            color: #FFFFFF;
        }
        QPushButton#BtnAbort {
            background-color: #DC2626;
        }
        QPushButton#BtnAbort:hover {
            background-color: #B91C1C;
        }
        QProgressBar {
            border: none;
            border-radius: 4px;
            text-align: center;
            background-color: rgba(15, 20, 30, 0.6);
            height: 6px;
        }
        QProgressBar::chunk {
            background-color: #6366F1;
            border-radius: 4px;
        }
        QPlainTextEdit {
            background-color: rgba(10, 15, 25, 0.65);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 8px;
            color: #94A3B8;
            font-family: "Consolas", monospace;
            padding: 8px;
        }
        QLabel#DropZone {
            border: 1.5px dashed rgba(255, 255, 255, 0.2);
            border-radius: 10px;
            background-color: rgba(15, 20, 30, 0.35);
            color: #94A3B8;
            font-size: 12px;
            font-weight: 500;
            padding: 10px;
        }
        QLabel#KeyTargetZone {
            border: 1.5px dashed #6366F1;
            border-radius: 10px;
            background-color: rgba(99, 102, 241, 0.08);
            color: #A5B4FC;
            font-size: 12px;
            font-weight: 500;
            padding: 10px;
        }
        QLabel#StatusCard {
            background-color: rgba(15, 20, 30, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 6px 10px;
            color: #E2E8F0;
            font-size: 12px;
        }
        QSlider::groove:horizontal {
            border: none;
            height: 4px;
            background: rgba(255, 255, 255, 0.15);
            border-radius: 2px;
        }
        QSlider::sub-page:horizontal {
            background: #6366F1;
            border-radius: 2px;
        }
        QSlider::handle:horizontal {
            background: #FFFFFF;
            width: 14px;
            margin-top: -5px;
            margin-bottom: -5px;
            border-radius: 7px;
        }
    """

