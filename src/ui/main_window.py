import os
import sys
import tempfile

from PyQt5.QtCore import QSize, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QIcon
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# Import our security components
from src.attachment_scanner import AttachmentScanner
from src.email_processor import EmailProcessor
from src.encryption_manager import EncryptionManager
from src.phishing_detector import PhishingDetector


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


class PasswordDialog(QDialog):
    def __init__(
        self, title="Enter Password", message="Enter your password:", parent=None
    ):
        super().__init__(parent)
        self.setWindowTitle(title)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)

        layout = QFormLayout()
        layout.addRow(QLabel(message))
        layout.addRow("Password:", self.password)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        main_layout.addWidget(buttons)

        self.setLayout(main_layout)

    def get_password(self):
        return self.password.text()


class KeyGenerationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate Encryption Keys")

        self.email = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)

        layout = QFormLayout()
        layout.addRow("Email Address:", self.email)
        layout.addRow("Key Password (Optional):", self.password)
        layout.addRow("Confirm Password:", self.confirm_password)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.validate_and_accept)
        buttons.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        main_layout.addWidget(buttons)

        self.setLayout(main_layout)

    def validate_and_accept(self):
        if not self.email.text():
            QMessageBox.warning(self, "Error", "Email address is required.")
            return

        if self.password.text() != self.confirm_password.text():
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return

        self.accept()

    def get_values(self):
        return self.email.text(), self.password.text()


class ContactKeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Contact's Public Key")

        self.email = QLineEdit()
        self.key_text = QTextEdit()

        self.import_button = QPushButton("Import from File...")
        self.import_button.clicked.connect(self.import_from_file)

        layout = QFormLayout()
        layout.addRow("Contact's Email:", self.email)
        layout.addRow("Public Key:", self.key_text)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        main_layout.addWidget(self.import_button)
        main_layout.addWidget(buttons)

        self.setLayout(main_layout)

    def import_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Public Key File",
            "",
            "Public Key Files (*.pem);;All Files (*)",
        )
        if file_path:
            try:
                with open(file_path, "r") as f:
                    self.key_text.setPlainText(f.read())
            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to read key file: {str(e)}"
                )

    def get_values(self):
        return self.email.text(), self.key_text.toPlainText()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.email_processor = None
        self.attachment_scanner = AttachmentScanner()
        self.phishing_detector = PhishingDetector()
        self.encryption_manager = EncryptionManager()

        self.current_emails = []
        self.current_email_index = None

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Mail-Warden")
        self.setGeometry(100, 100, 1200, 800)

        # Create menu bar
        menubar = self.menuBar()

        # File menu
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

        # Security menu
        security_menu = menubar.addMenu("Security")

        scan_action = QAction("Scan Current Email", self)
        scan_action.triggered.connect(self.scan_current_email)
        security_menu.addAction(scan_action)

        # Encryption menu
        encryption_menu = menubar.addMenu("Encryption")

        generate_keys_action = QAction("Generate Keys", self)
        generate_keys_action.triggered.connect(self.show_key_generation_dialog)
        encryption_menu.addAction(generate_keys_action)

        load_keys_action = QAction("Load Existing Keys", self)
        load_keys_action.triggered.connect(self.load_existing_keys)
        encryption_menu.addAction(load_keys_action)

        add_contact_action = QAction("Add Contact's Public Key", self)
        add_contact_action.triggered.connect(self.show_add_contact_dialog)
        encryption_menu.addAction(add_contact_action)

        view_contacts_action = QAction("View Contacts", self)
        view_contacts_action.triggered.connect(self.view_contacts)
        encryption_menu.addAction(view_contacts_action)

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        splitter = QSplitter(Qt.Horizontal)

        # Left panel for email list
        list_panel = QWidget()
        list_layout = QVBoxLayout(list_panel)

        self.email_list = QListWidget()
        self.email_list.setMinimumWidth(300)
        self.email_list.currentItemChanged.connect(self.on_email_selected)

        list_layout.addWidget(QLabel("Inbox"))
        list_layout.addWidget(self.email_list)

        # Right panel with tabs for email content and security details
        content_panel = QWidget()
        content_layout = QVBoxLayout(content_panel)

        # Create tabs
        self.tabs = QTabWidget()

        # Email content tab
        email_tab = QWidget()
        email_layout = QVBoxLayout(email_tab)

        # Email headers
        self.subject_label = QLabel()
        self.subject_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.from_label = QLabel()
        self.date_label = QLabel()

        # Security indicators
        security_layout = QHBoxLayout()
        self.phishing_indicator = QLabel("Phishing: Not Checked")
        self.attachment_indicator = QLabel("Attachments: None")
        self.encryption_indicator = QLabel("Encryption: None")

        security_layout.addWidget(self.phishing_indicator)
        security_layout.addWidget(self.attachment_indicator)
        security_layout.addWidget(self.encryption_indicator)

        # Email body
        self.email_content = QTextEdit()
        self.email_content.setReadOnly(True)

        # Scan button
        self.scan_button = QPushButton("Scan for Threats")
        self.scan_button.clicked.connect(self.scan_current_email)

        # Add all widgets to email tab layout
        email_layout.addWidget(self.subject_label)
        email_layout.addWidget(self.from_label)
        email_layout.addWidget(self.date_label)
        email_layout.addLayout(security_layout)
        email_layout.addWidget(self.email_content)
        email_layout.addWidget(self.scan_button)

        # Security details tab
        security_tab = QWidget()
        security_layout = QVBoxLayout(security_tab)

        self.security_details = QTextEdit()
        self.security_details.setReadOnly(True)
        security_layout.addWidget(self.security_details)

        # Attachments tab
        attachments_tab = QWidget()
        attachments_layout = QVBoxLayout(attachments_tab)

        self.attachments_list = QListWidget()
        self.scan_attachments_button = QPushButton("Scan Attachments")
        self.scan_attachments_button.clicked.connect(self.scan_attachments)

        attachments_layout.addWidget(self.attachments_list)
        attachments_layout.addWidget(self.scan_attachments_button)

        # Encryption tab
        encryption_tab = QWidget()
        encryption_layout = QVBoxLayout(encryption_tab)

        self.encrypt_button = QPushButton("Encrypt Message")
        self.encrypt_button.clicked.connect(self.encrypt_message)
        self.decrypt_button = QPushButton("Decrypt Message")
        self.decrypt_button.clicked.connect(self.decrypt_message)

        self.encryption_text = QTextEdit()

        encryption_layout.addWidget(self.encrypt_button)
        encryption_layout.addWidget(self.decrypt_button)
        encryption_layout.addWidget(self.encryption_text)

        # Add tabs to tab widget
        self.tabs.addTab(email_tab, "Email")
        self.tabs.addTab(security_tab, "Security Details")
        self.tabs.addTab(attachments_tab, "Attachments")
        self.tabs.addTab(encryption_tab, "Encryption")

        content_layout.addWidget(self.tabs)

        # Add panels to splitter
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

    def connect_to_email(self, email, password, server):
        self.email_processor = EmailProcessor(email, password, server)
        if self.email_processor.connect():
            self.statusBar().showMessage(f"Connected to {email}")
            self.refresh_emails()
        else:
            QMessageBox.critical(
                self,
                "Connection Error",
                "Failed to connect to email server. Please check your credentials.",
            )
            self.email_processor = None

    def refresh_emails(self):
        if not self.email_processor:
            QMessageBox.warning(
                self, "Not Connected", "Please connect to an email server first."
            )
            return

        self.email_list.clear()
        self.current_emails = []
        self.current_email_index = None

        self.statusBar().showMessage("Fetching Emails...")

        emails = self.email_processor.get_inbox_messages(limit=20)
        self.current_emails = emails

        for email in emails:
            item = QListWidgetItem()
            item.setText(f"{email['subject']}")
            item.setData(Qt.UserRole, emails.index(email))
            self.email_list.addItem(item)

        self.statusBar().showMessage(f"Loaded {len(emails)} emails")

    def on_email_selected(self, current, previous):
        if not current:
            return

        self.tabs.setCurrentIndex(0)  # Switch to email content tab
        index = current.data(Qt.UserRole)
        self.current_email_index = index
        email = self.current_emails[index]

        self.subject_label.setText(f"Subject: {email['subject']}")
        self.from_label.setText(f"From: {email['from']}")
        self.date_label.setText(f"Date: {email['date']}")

        # Reset security indicators
        self.phishing_indicator.setText("Phishing: Not Checked")
        self.phishing_indicator.setStyleSheet("")

        # Check for attachments
        if email.get("attachments"):
            self.attachment_indicator.setText(
                f"Attachments: {len(email['attachments'])}"
            )

            # Clear and populate attachments list
            self.attachments_list.clear()
            for name, path in email["attachments"]:
                item = QListWidgetItem(name)
                item.setData(Qt.UserRole, path)
                self.attachments_list.addItem(item)
        else:
            self.attachment_indicator.setText("Attachments: None")
            self.attachments_list.clear()

        # Check if message is encrypted
        body = email["body"]
        if body.startswith('{"encrypted_key":') or body.startswith(
            '{"method":"password"'
        ):
            self.encryption_indicator.setText("Encryption: Encrypted")
            self.encryption_indicator.setStyleSheet("color: green")
            self.email_content.setPlainText(
                "[Encrypted Message - Use the Encryption tab to decrypt]"
            )

            # Pre-fill the encryption text area
            self.encryption_text.setPlainText(body)
        else:
            self.encryption_indicator.setText("Encryption: None")
            self.encryption_indicator.setStyleSheet("")
            self.email_content.setPlainText(body)

            # Clear the encryption text area
            self.encryption_text.clear()

        # Clear security details
        self.security_details.clear()

    def scan_current_email(self):
        if self.current_email_index is None:
            QMessageBox.warning(
                self, "No Email Selected", "Please select an email to scan."
            )
            return

        email = self.current_emails[self.current_email_index]

        # Switch to security details tab
        self.tabs.setCurrentIndex(1)

        # Analyze for phishing
        self.security_details.append("Scanning for phishing indicators...\n")

        phishing_results = self.phishing_detector.analyze_email(email)

        if phishing_results["is_suspicious"]:
            self.phishing_indicator.setText(
                f"Phishing: Suspicious ({phishing_results['risk_score']:.2f})"
            )
            self.phishing_indicator.setStyleSheet("color: red")

            self.security_details.append(
                "⚠️ PHISHING ALERT: This email contains suspicious elements!\n"
            )
            self.security_details.append(
                f"Risk Score: {phishing_results['risk_score']:.2f}\n"
            )
            self.security_details.append("Reasons:")

            for reason in phishing_results["reasons"]:
                self.security_details.append(f"- {reason}")

            self.security_details.append("\n")
        else:
            self.phishing_indicator.setText("Phishing: Low Risk")
            self.phishing_indicator.setStyleSheet("color: green")
            self.security_details.append("✓ No phishing indicators detected.\n")

        # Check attachments if present
        if email.get("attachments"):
            self.security_details.append("\nAttachment Summary:")
            self.security_details.append(
                f"Found {len(email['attachments'])} attachment(s)."
            )
            self.security_details.append(
                "Use the Attachments tab to scan them individually.\n"
            )

        self.statusBar().showMessage("Email scan complete")

    def scan_attachments(self):
        if self.current_email_index is None:
            QMessageBox.warning(
                self, "No Email Selected", "Please select an email to scan attachments."
            )
            return

        email = self.current_emails[self.current_email_index]

        if not email.get("attachments"):
            QMessageBox.information(
                self, "No Attachments", "This email does not have any attachments."
            )
            return

        self.security_details.clear()
        self.security_details.append("Attachment Scan Results:\n")

        for name, path in email["attachments"]:
            self.security_details.append(f"Scanning: {name}")

            scan_result = self.attachment_scanner.scan_attachment(path, name)

            if scan_result["risk_level"] == "dangerous":
                self.security_details.append(f"⚠️ HIGH RISK ATTACHMENT: {name}")
                self.security_details.append(
                    f"Risk Score: {scan_result['risk_score']:.2f}\n"
                )
            elif scan_result["risk_level"] == "suspicious":
                self.security_details.append(f"⚠️ SUSPICIOUS ATTACHMENT: {name}")
                self.security_details.append(
                    f"Risk Score: {scan_result['risk_score']:.2f}\n"
                )
            else:
                self.security_details.append(f"✓ SAFE ATTACHMENT: {name}\n")

            if scan_result["reasons"]:
                self.security_details.append("Reasons:")
                for reason in scan_result["reasons"]:
                    self.security_details.append(f"- {reason}")

            self.security_details.append("\n")

        # Switch to security details tab
        self.tabs.setCurrentIndex(1)

        self.statusBar().showMessage("Attachment scan complete")

    def show_key_generation_dialog(self):
        dialog = KeyGenerationDialog(self)
        if dialog.exec():
            email, password = dialog.get_values()

            try:
                # Generate new keys
                key_info = self.encryption_manager.generate_user_keys(
                    email, password if password else None
                )

                QMessageBox.information(
                    self,
                    "Keys Generated",
                    f"Encryption keys generated successfully for {email}\n\nFingerprint: {key_info['fingerprint']}",
                )

                self.statusBar().showMessage(f"Encryption keys generated for {email}")
            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to generate keys: {str(e)}"
                )

    def load_existing_keys(self):
        email, ok = QInputDialog.getText(self, "Load Keys", "Enter email address:")
        if not ok or not email:
            return

        dialog = PasswordDialog(
            "Key Password",
            "Enter the password for your encryption key (leave empty if none):",
        )
        if dialog.exec():
            password = dialog.get_password()

            try:
                key_info = self.encryption_manager.load_user_keys(
                    email, password if password else None
                )

                if key_info:
                    QMessageBox.information(
                        self,
                        "Keys Loaded",
                        f"Encryption keys loaded successfully for {email}\n\nFingerprint: {key_info['fingerprint']}",
                    )

                    self.statusBar().showMessage(f"Encryption keys loaded for {email}")
                else:
                    QMessageBox.warning(
                        self, "Keys Not Found", f"No encryption keys found for {email}"
                    )
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load keys: {str(e)}")

    def show_add_contact_dialog(self):
        dialog = ContactKeyDialog(self)
        if dialog.exec():
            email, key_text = dialog.get_values()

            if not email or not key_text:
                QMessageBox.warning(
                    self,
                    "Missing Information",
                    "Both email and public key are required.",
                )
                return

            try:
                contact_info = self.encryption_manager.add_contact_key(email, key_text)

                if contact_info:
                    QMessageBox.information(
                        self,
                        "Contact Added",
                        f"Contact {email} added successfully\n\nFingerprint: {contact_info['fingerprint']}",
                    )
                else:
                    QMessageBox.warning(self, "Error", f"Failed to add contact key.")
            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to add contact key: {str(e)}"
                )

    def view_contacts(self):
        contacts = self.encryption_manager.list_contacts()

        if not contacts:
            QMessageBox.information(self, "Contacts", "No encrypted contacts found.")
            return

        contacts_text = "Encrypted Contacts:\n\n"
        for contact in contacts:
            contacts_text += (
                f"Email: {contact['email']}\nFingerprint: {contact['fingerprint']}\n\n"
            )

        msg = QMessageBox(self)
        msg.setWindowTitle("Encrypted Contacts")
        msg.setText(contacts_text)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def encrypt_message(self):
        if not self.encryption_manager.user_email:
            QMessageBox.warning(
                self, "No Keys Loaded", "Please load or generate encryption keys first."
            )
            return

        # Get the list of contacts
        contacts = self.encryption_manager.list_contacts()
        if not contacts:
            QMessageBox.warning(
                self,
                "No Contacts",
                "You need to add at least one contact before encrypting a message.",
            )
            return

        # Let user choose between public key or password encryption
        items = ["Public Key Encryption", "Password Protection"]
        choice, ok = QInputDialog.getItem(
            self, "Encryption Type", "Select encryption method:", items, 0, False
        )

        if not ok:
            return

        # Get the message text
        text, ok = QInputDialog.getMultiLineText(
            self, "Message", "Enter the message to encrypt:"
        )

        if not ok or not text:
            return

        try:
            if choice == "Public Key Encryption":
                # Choose a recipient
                recipient_emails = [contact["email"] for contact in contacts]
                recipient, ok = QInputDialog.getItem(
                    self, "Recipient", "Select recipient:", recipient_emails, 0, False
                )

                if not ok:
                    return

                encrypted_data = self.encryption_manager.encrypt_message(
                    recipient, text
                )

            else:  # Password Protection
                password_dialog = PasswordDialog(
                    "Encryption Password", "Create a password for this message:"
                )
                if not password_dialog.exec():
                    return

                password = password_dialog.get_password()
                if not password:
                    QMessageBox.warning(
                        self,
                        "No Password",
                        "A password is required for password-protected encryption.",
                    )
                    return

                encrypted_data = (
                    self.encryption_manager.create_password_protected_email(
                        text, password
                    )
                )

            # Display the encrypted data
            self.encryption_text.setPlainText(encrypted_data)
            self.statusBar().showMessage("Message encrypted successfully")

        except Exception as e:
            QMessageBox.critical(
                self, "Encryption Error", f"Failed to encrypt message: {str(e)}"
            )

    def decrypt_message(self):
        if not self.encryption_manager.user_email:
            QMessageBox.warning(
                self, "No Keys Loaded", "Please load or generate encryption keys first."
            )
            return

        encrypted_data = self.encryption_text.toPlainText()
        if not encrypted_data:
            QMessageBox.warning(self, "No Data", "No encrypted data to decrypt.")
            return

        try:
            # Check if it's password-protected
            is_password_protected = '"method":"password"' in encrypted_data

            if is_password_protected:
                password_dialog = PasswordDialog(
                    "Encryption Password", "Enter the password for this message:"
                )
                if not password_dialog.exec():
                    return

                password = password_dialog.get_password()
                decrypted_text = (
                    self.encryption_manager.decrypt_password_protected_email(
                        encrypted_data, password
                    )
                )
            else:
                decrypted_text = self.encryption_manager.decrypt_message(encrypted_data)

            # Show the decrypted message
            self.email_content.setPlainText(decrypted_text)
            self.tabs.setCurrentIndex(0)  # Switch to email tab
            self.statusBar().showMessage("Message decrypted successfully")

        except Exception as e:
            QMessageBox.critical(
                self, "Decryption Error", f"Failed to decrypt message: {str(e)}"
            )
