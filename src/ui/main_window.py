import sys

from PyQt5.QtCore import QSize, Qt, pyqtSignal
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Mail-Warden - Login")

        self.email = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.server = QLineEdit()
        self.server.setText("imap.gmail.com")

        layout = QFormLayout()
        layout.addRow("Email:", self.email)
        layout.addRow("Password:", self.password)
        layout.addRow("IMAP Server:", self.server)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        main_layout.addWidget(buttons)

        self.setLayout(main_layout)

    def get_credentials(self):
        return self.email.text(), self.password.text(), self.server.text()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.email_processor = None
        self.current_emails = []

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Mail-Warden")
        self.setGeometry(100, 100, 1200, 800)

        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")

        login_action = QAction("Login", self)
        login_action.triggered.connect(self.show_login_dialog)
        file_menu.addAction(login_action)

        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_emails)
        file_menu.addAction(refresh_action)

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        splitter = QSplitter(Qt.horizontal)

        list_panel = QWidget()
        list_layout = QVBoxLayout(list_panel)

        self.email_list = QListWidget()
        self.email_list.setMinimumWidth(300)
        self.email_list.currentItemChanged.connect(self.on_email_selected)

        list_layout.addWidget(QLabel("Inbox"))
        list_layout.addWidget(self.email_list)

        content_panel = QWidget()
        content_layout = QVBoxLayout(content_panel)

        self.subject_label = QHBoxLayout()
        self.subject_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.from_label = QLabel()
        self.date_label = QLabel()

        security_layout = QHBoxLayout()
        self.phishing_indicator = QLabel("Phishing: Not Checked")
        self.attachment_indicator = QLabel("Attachments: None")
        self.encryption_indicator = QLabel("Encryption: None")

        security_layout.addWidget(self.phishing_indicator)
        security_layout.addWidget(self.attachment_indicator)
        security_layout.addWidget(self.encryption_indicator)

        self.email_content = QTextEdit()
        self.email_content.setReadOnly(True)

        content_layout.addWidget(self.subject_label)
        content_layout.addWidget(self.from_label)
        content_layout.addWidget(self.date_label)
        content_layout.addLayout(security_layout)
        content_layout.addWidget(self.email_content)

        splitter.addWidget(list_panel)
        splitter.addWidget(content_panel)

        splitter.setSizes([300, 900])

        main_layout.addWidget(splitter)

        self.statusBar().showMessage("Not connected to email server")

    def show_login_dialog(self):
        dialog = LoginDialog(self)
        if dialog.exec():
            email, password, server = dialog.get_credentials()
            self.connect_to_email(email, password, server)

    def connect_to_email(self):
        from src.email_processor import EmailProcessor

        self.email_processor = EmailProcessor(self.email, self.password, self.server)
        if self.email_processor.connect():
            self.statusBar().showMessage(f"Connected to {self.email}")
            self.refresh_emails
        else:
            QMessageBox.critical(
                self,
                "Connection Error",
                "Failed to connect to email server. Please check your credentials.",
            )
            self.email_processor = None
