import sys
import os
from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    win = MainWindow(initial_files=sys.argv[1:] if len(sys.argv) > 1 else None)
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
