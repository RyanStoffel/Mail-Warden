import json
import os
import sys
import tempfile
import threading
from functools import partial
from tkinter import (
    Button,
    Entry,
    Frame,
    Label,
    Listbox,
    Menu,
    PhotoImage,
    Scrollbar,
    StringVar,
    Text,
    Tk,
    filedialog,
    messagebox,
    simpledialog,
    ttk,
)
from tkinter.simpledialog import Dialog
from tkinter.ttk import Notebook

# Import our security components
from src.attachment_scanner import AttachmentScanner
from src.email_processor import EmailProcessor
from src.encryption_manager import EncryptionManager
from src.phishing_detector import PhishingDetector


class LoginDialog(Dialog):
    def __init__(self, parent, title="Mail-Warden - Login"):
        self.email_var = StringVar()
        self.password_var = StringVar()
        self.server_var = StringVar(value="imap.gmail.com")
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="Email:").grid(
            row=0, column=0, sticky="w", padx=5, pady=5
        )
        ttk.Entry(master, textvariable=self.email_var, width=30).grid(
            row=0, column=1, padx=5, pady=5
        )

        ttk.Label(master, text="Password:").grid(
            row=1, column=0, sticky="w", padx=5, pady=5
        )
        password_entry = ttk.Entry(
            master, textvariable=self.password_var, width=30, show="*"
        )
        password_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(master, text="IMAP Server:").grid(
            row=2, column=0, sticky="w", padx=5, pady=5
        )
        ttk.Entry(master, textvariable=self.server_var, width=30).grid(
            row=2, column=1, padx=5, pady=5
        )

        return password_entry  # Initial focus

    def apply(self):
        self.result = (
            self.email_var.get(),
            self.password_var.get(),
            self.server_var.get(),
        )


class PasswordDialog(Dialog):
    def __init__(self, parent, title="Enter Password", message="Enter your password:"):
        self.message = message
        self.password_var = StringVar()
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text=self.message).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=5, pady=5
        )

        ttk.Label(master, text="Password:").grid(
            row=1, column=0, sticky="w", padx=5, pady=5
        )
        password_entry = ttk.Entry(
            master, textvariable=self.password_var, width=30, show="*"
        )
        password_entry.grid(row=1, column=1, padx=5, pady=5)

        return password_entry  # Initial focus

    def apply(self):
        self.result = self.password_var.get()


class KeyGenerationDialog(Dialog):
    def __init__(self, parent, title="Generate Encryption Keys"):
        self.email_var = StringVar()
        self.password_var = StringVar()
        self.confirm_password_var = StringVar()
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="Email Address:").grid(
            row=0, column=0, sticky="w", padx=5, pady=5
        )
        ttk.Entry(master, textvariable=self.email_var, width=30).grid(
            row=0, column=1, padx=5, pady=5
        )

        ttk.Label(master, text="Key Password (Optional):").grid(
            row=1, column=0, sticky="w", padx=5, pady=5
        )
        ttk.Entry(master, textvariable=self.password_var, width=30, show="*").grid(
            row=1, column=1, padx=5, pady=5
        )

        ttk.Label(master, text="Confirm Password:").grid(
            row=2, column=0, sticky="w", padx=5, pady=5
        )
        confirm_entry = ttk.Entry(
            master, textvariable=self.confirm_password_var, width=30, show="*"
        )
        confirm_entry.grid(row=2, column=1, padx=5, pady=5)

        return confirm_entry  # Initial focus

    def validate(self):
        if not self.email_var.get():
            messagebox.showwarning("Error", "Email address is required.")
            return False

        if self.password_var.get() != self.confirm_password_var.get():
            messagebox.showwarning("Error", "Passwords do not match.")
            return False

        return True

    def apply(self):
        self.result = (self.email_var.get(), self.password_var.get())


class ContactKeyDialog(Dialog):
    def __init__(self, parent, title="Add Contact's Public Key"):
        self.email_var = StringVar()
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="Contact's Email:").grid(
            row=0, column=0, sticky="w", padx=5, pady=5
        )
        ttk.Entry(master, textvariable=self.email_var, width=30).grid(
            row=0, column=1, padx=5, pady=5
        )

        ttk.Label(master, text="Public Key:").grid(
            row=1, column=0, sticky="w", padx=5, pady=5
        )

        self.key_text = Text(master, width=60, height=15)
        self.key_text.grid(row=1, column=1, padx=5, pady=5)

        import_button = ttk.Button(
            master, text="Import from File...", command=self.import_from_file
        )
        import_button.grid(row=2, column=1, sticky="e", padx=5, pady=5)

        return self.key_text  # Initial focus

    def import_from_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Public Key File",
            filetypes=[("Public Key Files", "*.pem"), ("All Files", "*")],
        )
        if file_path:
            try:
                with open(file_path, "r") as f:
                    self.key_text.delete(1.0, "end")
                    self.key_text.insert("end", f.read())
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read key file: {str(e)}")

    def apply(self):
        self.result = (self.email_var.get(), self.key_text.get(1.0, "end-1c"))


class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Mail-Warden")
        self.root.geometry("1200x800")

        self.email_processor = None
        self.attachment_scanner = AttachmentScanner()
        self.phishing_detector = PhishingDetector()
        self.encryption_manager = EncryptionManager()

        self.current_emails = []
        self.current_email_index = None

        # Initialize the status variable before setting up the UI
        self.status_var = StringVar(value="Not connected to email server")

        # Now set up the UI components
        self.setup_ui()
        self.update_status_bar()

    def setup_ui(self):
        # Create a modern style
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        style.configure("TButton", font=("Arial", 10))
        style.configure("Treeview", font=("Arial", 10))
        style.configure("TNotebook", background="#f0f0f0")
        style.configure("TNotebook.Tab", font=("Arial", 10))

        # Create menu bar
        self.create_menu_bar()

        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Create a PanedWindow for resizable split view
        paned_window = ttk.PanedWindow(main_frame, orient="horizontal")
        paned_window.pack(fill="both", expand=True)

        # Left panel for email list
        left_frame = ttk.Frame(paned_window, width=300)
        paned_window.add(left_frame, weight=1)

        ttk.Label(left_frame, text="Inbox", font=("Arial", 12, "bold")).pack(
            anchor="w", padx=5, pady=5
        )

        # Email listbox with scrollbar
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill="both", expand=True)

        self.email_list = Listbox(
            list_frame,
            font=("Arial", 10),
            activestyle="none",
            highlightthickness=0,
            bd=1,
            relief="solid",
        )
        self.email_list.pack(side="left", fill="both", expand=True)

        list_scrollbar = ttk.Scrollbar(
            list_frame, orient="vertical", command=self.email_list.yview
        )
        list_scrollbar.pack(side="right", fill="y")
        self.email_list.config(yscrollcommand=list_scrollbar.set)

        self.email_list.bind("<<ListboxSelect>>", self.on_email_selected)

        # Right panel with tabs
        right_frame = ttk.Frame(paned_window)
        paned_window.add(right_frame, weight=3)

        # Create notebook (tabbed interface)
        self.tabs = ttk.Notebook(right_frame)
        self.tabs.pack(fill="both", expand=True)

        # Email content tab
        email_tab = ttk.Frame(self.tabs)
        self.tabs.add(email_tab, text="Email")

        # Email headers
        header_frame = ttk.Frame(email_tab)
        header_frame.pack(fill="x", padx=5, pady=5)

        self.subject_label = ttk.Label(
            header_frame, text="Subject:", font=("Arial", 12, "bold")
        )
        self.subject_label.pack(anchor="w", pady=2)

        self.from_label = ttk.Label(header_frame, text="From:")
        self.from_label.pack(anchor="w", pady=2)

        self.date_label = ttk.Label(header_frame, text="Date:")
        self.date_label.pack(anchor="w", pady=2)

        # Security indicators
        indicator_frame = ttk.Frame(email_tab)
        indicator_frame.pack(fill="x", padx=5, pady=5)

        self.phishing_indicator = ttk.Label(
            indicator_frame, text="Phishing: Not Checked"
        )
        self.phishing_indicator.pack(side="left", padx=5)

        self.attachment_indicator = ttk.Label(indicator_frame, text="Attachments: None")
        self.attachment_indicator.pack(side="left", padx=5)

        self.encryption_indicator = ttk.Label(indicator_frame, text="Encryption: None")
        self.encryption_indicator.pack(side="left", padx=5)

        # Email content with scrollbar
        content_frame = ttk.Frame(email_tab)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.email_content = Text(content_frame, wrap="word", font=("Arial", 10))
        self.email_content.pack(side="left", fill="both", expand=True)
        self.email_content.config(state="disabled")

        content_scrollbar = ttk.Scrollbar(
            content_frame, orient="vertical", command=self.email_content.yview
        )
        content_scrollbar.pack(side="right", fill="y")
        self.email_content.config(yscrollcommand=content_scrollbar.set)

        # Scan button
        self.scan_button = ttk.Button(
            email_tab, text="Scan for Threats", command=self.scan_current_email
        )
        self.scan_button.pack(pady=10)

        # Security details tab
        security_tab = ttk.Frame(self.tabs)
        self.tabs.add(security_tab, text="Security Details")

        security_frame = ttk.Frame(security_tab)
        security_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.security_details = Text(security_frame, wrap="word", font=("Arial", 10))
        self.security_details.pack(side="left", fill="both", expand=True)
        self.security_details.config(state="disabled")

        security_scrollbar = ttk.Scrollbar(
            security_frame, orient="vertical", command=self.security_details.yview
        )
        security_scrollbar.pack(side="right", fill="y")
        self.security_details.config(yscrollcommand=security_scrollbar.set)

        # Attachments tab
        attachments_tab = ttk.Frame(self.tabs)
        self.tabs.add(attachments_tab, text="Attachments")

        attachments_frame = ttk.Frame(attachments_tab)
        attachments_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.attachments_list = Listbox(attachments_frame, font=("Arial", 10))
        self.attachments_list.pack(side="left", fill="both", expand=True)

        attachments_scrollbar = ttk.Scrollbar(
            attachments_frame, orient="vertical", command=self.attachments_list.yview
        )
        attachments_scrollbar.pack(side="right", fill="y")
        self.attachments_list.config(yscrollcommand=attachments_scrollbar.set)

        self.scan_attachments_button = ttk.Button(
            attachments_tab, text="Scan Attachments", command=self.scan_attachments
        )
        self.scan_attachments_button.pack(pady=10)

        # Encryption tab
        encryption_tab = ttk.Frame(self.tabs)
        self.tabs.add(encryption_tab, text="Encryption")

        encryption_button_frame = ttk.Frame(encryption_tab)
        encryption_button_frame.pack(fill="x", padx=5, pady=5)

        self.encrypt_button = ttk.Button(
            encryption_button_frame,
            text="Encrypt Message",
            command=self.encrypt_message,
        )
        self.encrypt_button.pack(side="left", padx=5)

        self.decrypt_button = ttk.Button(
            encryption_button_frame,
            text="Decrypt Message",
            command=self.decrypt_message,
        )
        self.decrypt_button.pack(side="left", padx=5)

        encryption_text_frame = ttk.Frame(encryption_tab)
        encryption_text_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.encryption_text = Text(
            encryption_text_frame, wrap="word", font=("Arial", 10)
        )
        self.encryption_text.pack(side="left", fill="both", expand=True)

        encryption_scrollbar = ttk.Scrollbar(
            encryption_text_frame, orient="vertical", command=self.encryption_text.yview
        )
        encryption_scrollbar.pack(side="right", fill="y")
        self.encryption_text.config(yscrollcommand=encryption_scrollbar.set)

        # Status bar
        self.status_bar = ttk.Label(
            self.root, textvariable=self.status_var, relief="sunken", anchor="w"
        )
        self.status_bar.pack(side="bottom", fill="x")

    def create_menu_bar(self):
        menubar = Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Login", command=self.show_login_dialog)
        file_menu.add_command(label="Refresh", command=self.refresh_emails)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Security menu
        security_menu = Menu(menubar, tearoff=0)
        security_menu.add_command(
            label="Scan Current Email", command=self.scan_current_email
        )
        menubar.add_cascade(label="Security", menu=security_menu)

        # Encryption menu
        encryption_menu = Menu(menubar, tearoff=0)
        encryption_menu.add_command(
            label="Generate Keys", command=self.show_key_generation_dialog
        )
        encryption_menu.add_command(
            label="Load Existing Keys", command=self.load_existing_keys
        )
        encryption_menu.add_command(
            label="Add Contact's Public Key", command=self.show_add_contact_dialog
        )
        encryption_menu.add_command(label="View Contacts", command=self.view_contacts)
        menubar.add_cascade(label="Encryption", menu=encryption_menu)

    def update_status_bar(self, message=None):
        if message:
            self.status_var.set(message)
        self.root.update_idletasks()

    def show_login_dialog(self):
        dialog = LoginDialog(self.root)
        if hasattr(dialog, "result") and dialog.result:
            email, password, server = dialog.result
            self.connect_to_email(email, password, server)

    def connect_to_email(self, email, password, server):
        self.update_status_bar("Connecting to email server...")

        # Use threading to prevent UI freeze during connection
        def connect_task():
            self.email_processor = EmailProcessor(email, password, server)
            if self.email_processor.connect():
                self.root.after(
                    0, lambda: self.update_status_bar(f"Connected to {email}")
                )
                self.root.after(0, self.refresh_emails)
            else:
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Connection Error",
                        "Failed to connect to email server. Please check your credentials.",
                    ),
                )
                self.email_processor = None
                self.root.after(
                    0, lambda: self.update_status_bar("Not connected to email server")
                )

        threading.Thread(target=connect_task).start()

    def refresh_emails(self):
        if not self.email_processor:
            messagebox.showwarning(
                "Not Connected", "Please connect to an email server first."
            )
            return

        self.update_status_bar("Fetching Emails...")
        self.email_list.delete(0, "end")
        self.current_emails = []
        self.current_email_index = None

        # Use threading to prevent UI freeze during email fetching
        def fetch_task():
            emails = self.email_processor.get_inbox_messages(limit=20)
            self.current_emails = emails

            self.root.after(0, lambda: self.populate_email_list(emails))
            self.root.after(
                0, lambda: self.update_status_bar(f"Loaded {len(emails)} emails")
            )

        threading.Thread(target=fetch_task).start()

    def populate_email_list(self, emails):
        for idx, email in enumerate(emails):
            self.email_list.insert("end", email["subject"])
            # Store the index in the item
            self.email_list.itemconfig(idx, {"selectbackground": "#c0d6e4"})

    def on_email_selected(self, event):
        selection = self.email_list.curselection()
        if not selection:
            return

        index = selection[0]
        self.current_email_index = index
        email = self.current_emails[index]

        # Switch to email content tab
        self.tabs.select(0)

        # Update email headers
        self.subject_label.config(text=f"Subject: {email['subject']}")
        self.from_label.config(text=f"From: {email['from']}")
        self.date_label.config(text=f"Date: {email['date']}")

        # Reset security indicators
        self.phishing_indicator.config(text="Phishing: Not Checked")
        self.phishing_indicator.config(foreground="black")

        # Check for attachments
        if email.get("attachments"):
            self.attachment_indicator.config(
                text=f"Attachments: {len(email['attachments'])}"
            )

            # Clear and populate attachments list
            self.attachments_list.delete(0, "end")
            for name, path in email["attachments"]:
                self.attachments_list.insert("end", name)
        else:
            self.attachment_indicator.config(text="Attachments: None")
            self.attachments_list.delete(0, "end")

        # Check if message is encrypted
        body = email["body"]
        if body.startswith('{"encrypted_key":') or body.startswith(
            '{"method":"password"'
        ):
            self.encryption_indicator.config(text="Encryption: Encrypted")
            self.encryption_indicator.config(foreground="green")

            # Update email content
            self.email_content.config(state="normal")
            self.email_content.delete(1.0, "end")
            self.email_content.insert(
                "end", "[Encrypted Message - Use the Encryption tab to decrypt]"
            )
            self.email_content.config(state="disabled")

            # Pre-fill the encryption text area
            self.encryption_text.delete(1.0, "end")
            self.encryption_text.insert("end", body)
        else:
            self.encryption_indicator.config(text="Encryption: None")
            self.encryption_indicator.config(foreground="black")

            # Update email content
            self.email_content.config(state="normal")
            self.email_content.delete(1.0, "end")
            self.email_content.insert("end", body)
            self.email_content.config(state="disabled")

            # Clear the encryption text area
            self.encryption_text.delete(1.0, "end")

        # Clear security details
        self.security_details.config(state="normal")
        self.security_details.delete(1.0, "end")
        self.security_details.config(state="disabled")

    def scan_current_email(self):
        if self.current_email_index is None:
            messagebox.showwarning(
                "No Email Selected", "Please select an email to scan."
            )
            return

        email = self.current_emails[self.current_email_index]

        # Switch to security details tab
        self.tabs.select(1)

        # Clear and update security details
        self.security_details.config(state="normal")
        self.security_details.delete(1.0, "end")
        self.security_details.insert("end", "Scanning for phishing indicators...\n\n")
        self.security_details.config(state="disabled")

        self.update_status_bar("Analyzing email...")

        # Use threading to prevent UI freeze during analysis
        def analyze_task():
            phishing_results = self.phishing_detector.analyze_email(email)

            self.root.after(
                0, lambda: self.update_phishing_results(phishing_results, email)
            )
            self.root.after(0, lambda: self.update_status_bar("Email scan complete"))

        threading.Thread(target=analyze_task).start()

    def update_phishing_results(self, phishing_results, email):
        self.security_details.config(state="normal")

        if phishing_results["is_suspicious"]:
            self.phishing_indicator.config(
                text=f"Phishing: Suspicious ({phishing_results['risk_score']:.2f})"
            )
            self.phishing_indicator.config(foreground="red")

            self.security_details.insert(
                "end", "⚠️ PHISHING ALERT: This email contains suspicious elements!\n\n"
            )
            self.security_details.insert(
                "end", f"Risk Score: {phishing_results['risk_score']:.2f}\n\n"
            )
            self.security_details.insert("end", "Reasons:\n")

            for reason in phishing_results["reasons"]:
                self.security_details.insert("end", f"- {reason}\n")

            self.security_details.insert("end", "\n")
        else:
            self.phishing_indicator.config(text="Phishing: Low Risk")
            self.phishing_indicator.config(foreground="green")
            self.security_details.insert(
                "end", "✓ No phishing indicators detected.\n\n"
            )

        # Check attachments if present
        if email.get("attachments"):
            self.security_details.insert("end", "Attachment Summary:\n")
            self.security_details.insert(
                "end", f"Found {len(email['attachments'])} attachment(s).\n"
            )
            self.security_details.insert(
                "end", "Use the Attachments tab to scan them individually.\n\n"
            )

        self.security_details.config(state="disabled")

    def scan_attachments(self):
        if self.current_email_index is None:
            messagebox.showwarning(
                "No Email Selected", "Please select an email to scan attachments."
            )
            return

        email = self.current_emails[self.current_email_index]

        if not email.get("attachments"):
            messagebox.showinfo(
                "No Attachments", "This email does not have any attachments."
            )
            return

        # Switch to security details tab
        self.tabs.select(1)

        # Clear security details
        self.security_details.config(state="normal")
        self.security_details.delete(1.0, "end")
        self.security_details.insert("end", "Attachment Scan Results:\n\n")
        self.security_details.config(state="disabled")

        self.update_status_bar("Scanning attachments...")

        # Use threading to prevent UI freeze during scanning
        def scan_task():
            results = []
            for name, path in email["attachments"]:
                scan_result = self.attachment_scanner.scan_attachment(path, name)
                results.append((name, scan_result))

            self.root.after(0, lambda: self.update_attachment_results(results))
            self.root.after(
                0, lambda: self.update_status_bar("Attachment scan complete")
            )

        threading.Thread(target=scan_task).start()

    def update_attachment_results(self, results):
        self.security_details.config(state="normal")

        for name, scan_result in results:
            if scan_result["risk_level"] == "dangerous":
                self.security_details.insert("end", f"⚠️ HIGH RISK ATTACHMENT: {name}\n")
                self.security_details.insert(
                    "end", f"Risk Score: {scan_result['risk_score']:.2f}\n\n"
                )
            elif scan_result["risk_level"] == "suspicious":
                self.security_details.insert(
                    "end", f"⚠️ SUSPICIOUS ATTACHMENT: {name}\n"
                )
                self.security_details.insert(
                    "end", f"Risk Score: {scan_result['risk_score']:.2f}\n\n"
                )
            else:
                self.security_details.insert("end", f"✓ SAFE ATTACHMENT: {name}\n\n")

            if scan_result["reasons"]:
                self.security_details.insert("end", "Reasons:\n")
                for reason in scan_result["reasons"]:
                    self.security_details.insert("end", f"- {reason}\n")

            self.security_details.insert("end", "\n")

        self.security_details.config(state="disabled")

    def show_key_generation_dialog(self):
        dialog = KeyGenerationDialog(self.root)
        if hasattr(dialog, "result") and dialog.result:
            email, password = dialog.result

            try:
                # Generate new keys
                key_info = self.encryption_manager.generate_user_keys(
                    email, password if password else None
                )

                messagebox.showinfo(
                    "Keys Generated",
                    f"Encryption keys generated successfully for {email}\n\nFingerprint: {key_info['fingerprint']}",
                )

                self.update_status_bar(f"Encryption keys generated for {email}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")

    def load_existing_keys(self):
        email = simpledialog.askstring("Load Keys", "Enter email address:")
        if not email:
            return

        dialog = PasswordDialog(
            self.root,
            "Key Password",
            "Enter the password for your encryption key (leave empty if none):",
        )

        if hasattr(dialog, "result"):
            password = dialog.result

            try:
                key_info = self.encryption_manager.load_user_keys(
                    email, password if password else None
                )

                if key_info:
                    messagebox.showinfo(
                        "Keys Loaded",
                        f"Encryption keys loaded successfully for {email}\n\nFingerprint: {key_info['fingerprint']}",
                    )

                    self.update_status_bar(f"Encryption keys loaded for {email}")
                else:
                    messagebox.showwarning(
                        "Keys Not Found", f"No encryption keys found for {email}"
                    )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load keys: {str(e)}")

    def show_add_contact_dialog(self):
        dialog = ContactKeyDialog(self.root)
        if hasattr(dialog, "result") and dialog.result:
            email, key_text = dialog.result

            if not email or not key_text:
                messagebox.showwarning(
                    "Missing Information", "Both email and public key are required."
                )
                return

            try:
                contact_info = self.encryption_manager.add_contact_key(email, key_text)

                if contact_info:
                    messagebox.showinfo(
                        "Contact Added",
                        f"Contact {email} added successfully\n\nFingerprint: {contact_info['fingerprint']}",
                    )
                else:
                    messagebox.showwarning("Error", "Failed to add contact key.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add contact key: {str(e)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add contact key: {str(e)}")

    def view_contacts(self):
        contacts = self.encryption_manager.list_contacts()

        if not contacts:
            messagebox.showinfo("Contacts", "No encrypted contacts found.")
            return

        contacts_dialog = Tk()
        contacts_dialog.title("Encrypted Contacts")
        contacts_dialog.geometry("500x400")

        contacts_frame = ttk.Frame(contacts_dialog, padding=10)
        contacts_frame.pack(fill="both", expand=True)

        contacts_text = Text(contacts_frame, wrap="word", font=("Arial", 10))
        contacts_text.pack(side="left", fill="both", expand=True)

        for contact in contacts:
            contacts_text.insert("end", f"Email: {contact['email']}\n")
            contacts_text.insert("end", f"Fingerprint: {contact['fingerprint']}\n\n")

        contacts_text.config(state="disabled")

        scrollbar = ttk.Scrollbar(
            contacts_frame, orient="vertical", command=contacts_text.yview
        )
        scrollbar.pack(side="right", fill="y")
        contacts_text.config(yscrollcommand=scrollbar.set)

        close_button = ttk.Button(
            contacts_dialog, text="Close", command=contacts_dialog.destroy
        )
        close_button.pack(pady=10)

        contacts_dialog.transient(self.root)
        contacts_dialog.grab_set()
        self.root.wait_window(contacts_dialog)

    def encrypt_message(self):
        if not self.encryption_manager.user_email:
            messagebox.showwarning(
                "No Keys Loaded", "Please load or generate encryption keys first."
            )
            return

        # Get the list of contacts
        contacts = self.encryption_manager.list_contacts()
        if not contacts:
            messagebox.showwarning(
                "No Contacts",
                "You need to add at least one contact before encrypting a message.",
            )
            return

        # Let user choose between public key or password encryption
        choice_dialog = Dialog(self.root, "Encryption Type")
        choice_dialog.title = "Encryption Type"

        choice_var = StringVar()
        choices = ["Public Key Encryption", "Password Protection"]

        for i, choice in enumerate(choices):
            ttk.Radiobutton(
                choice_dialog, text=choice, variable=choice_var, value=choice
            ).grid(row=i, column=0, sticky="w", padx=20, pady=10)

        choice_var.set(choices[0])  # Default selection

        # Create your own buttons
        button_frame = ttk.Frame(choice_dialog)
        button_frame.grid(row=len(choices), column=0, pady=10)

        ttk.Button(
            button_frame, text="OK", command=lambda: choice_dialog.destroy()
        ).pack(side="left", padx=5)
        ttk.Button(
            button_frame, text="Cancel", command=lambda: choice_dialog.destroy()
        ).pack(side="right", padx=5)

        self.root.wait_window(choice_dialog)

        choice = choice_var.get()
        if not choice:
            return

        # Get the message text
        message_dialog = Tk()
        message_dialog.title("Enter Message")
        message_dialog.geometry("500x300")

        ttk.Label(message_dialog, text="Enter the message to encrypt:").pack(pady=5)

        text_frame = ttk.Frame(message_dialog)
        text_frame.pack(fill="both", expand=True, padx=10, pady=5)

        message_text = Text(text_frame, wrap="word", font=("Arial", 10))
        message_text.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(
            text_frame, orient="vertical", command=message_text.yview
        )
        scrollbar.pack(side="right", fill="y")
        message_text.config(yscrollcommand=scrollbar.set)

        button_frame = ttk.Frame(message_dialog)
        button_frame.pack(pady=10)

        message_result = [False, ""]  # Use a list to store the result and status

        def on_ok():
            message_result[0] = True
            message_result[1] = message_text.get(1.0, "end-1c")
            message_dialog.destroy()

        ttk.Button(button_frame, text="OK", command=on_ok).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=message_dialog.destroy).pack(
            side="right", padx=5
        )

        message_dialog.transient(self.root)
        message_dialog.grab_set()
        self.root.wait_window(message_dialog)

        if not message_result[0] or not message_result[1]:
            return

        text = message_result[1]

        try:
            if choice == "Public Key Encryption":
                # Choose a recipient
                recipient_dialog = Tk()
                recipient_dialog.title("Select Recipient")
                recipient_dialog.geometry("300x200")

                ttk.Label(recipient_dialog, text="Select recipient:").pack(pady=10)

                recipient_var = StringVar()
                recipient_list = ttk.Combobox(
                    recipient_dialog, textvariable=recipient_var, state="readonly"
                )
                recipient_list["values"] = [contact["email"] for contact in contacts]
                recipient_list.current(0)
                recipient_list.pack(pady=10)

                recipient_result = [False, ""]

                def on_recipient_ok():
                    recipient_result[0] = True
                    recipient_result[1] = recipient_var.get()
                    recipient_dialog.destroy()

                ttk.Button(recipient_dialog, text="OK", command=on_recipient_ok).pack(
                    pady=10
                )

                recipient_dialog.transient(self.root)
                recipient_dialog.grab_set()
                self.root.wait_window(recipient_dialog)

                if not recipient_result[0] or not recipient_result[1]:
                    return

                recipient = recipient_result[1]
                encrypted_data = self.encryption_manager.encrypt_message(
                    recipient, text
                )

            else:  # Password Protection
                password_dialog = PasswordDialog(
                    self.root,
                    "Encryption Password",
                    "Create a password for this message:",
                )

                if not hasattr(password_dialog, "result"):
                    return

                password = password_dialog.result
                if not password:
                    messagebox.showwarning(
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
            self.encryption_text.delete(1.0, "end")
            self.encryption_text.insert("end", encrypted_data)
            self.update_status_bar("Message encrypted successfully")

        except Exception as e:
            messagebox.showerror(
                "Encryption Error", f"Failed to encrypt message: {str(e)}"
            )

    def decrypt_message(self):
        if not self.encryption_manager.user_email:
            messagebox.showwarning(
                "No Keys Loaded", "Please load or generate encryption keys first."
            )
            return

        encrypted_data = self.encryption_text.get(1.0, "end-1c")
        if not encrypted_data:
            messagebox.showwarning("No Data", "No encrypted data to decrypt.")
            return

        try:
            # Check if it's password-protected
            is_password_protected = '"method":"password"' in encrypted_data

            if is_password_protected:
                password_dialog = PasswordDialog(
                    self.root,
                    "Encryption Password",
                    "Enter the password for this message:",
                )

                if not hasattr(password_dialog, "result"):
                    return

                password = password_dialog.result
                decrypted_text = (
                    self.encryption_manager.decrypt_password_protected_email(
                        encrypted_data, password
                    )
                )
            else:
                decrypted_text = self.encryption_manager.decrypt_message(encrypted_data)

            # Show the decrypted message
            self.email_content.config(state="normal")
            self.email_content.delete(1.0, "end")
            self.email_content.insert("end", decrypted_text)
            self.email_content.config(state="disabled")

            self.tabs.select(0)  # Switch to email tab
            self.update_status_bar("Message decrypted successfully")

        except Exception as e:
            messagebox.showerror(
                "Decryption Error", f"Failed to decrypt message: {str(e)}"
            )


# The following code will only run if this file is executed directly
# For normal usage, the MainWindow class will be imported
if __name__ == "__main__":
    root = Tk()
    root.title("Mail-Warden")

    # Set app icon if available
    try:
        icon_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "assets", "icon.png"
        )
        if os.path.exists(icon_path):
            root.iconphoto(True, PhotoImage(file=icon_path))
    except:
        pass  # Icon not critical for functionality

    # Apply light theme
    root.configure(bg="#f0f0f0")

    app = MainWindow(root)
    root.mainloop()
