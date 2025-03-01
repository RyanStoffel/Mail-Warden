import base64
import json
import os
import tempfile
import time
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptionManager:
    def __init__(self, keys_directory=None):
        if keys_directory is None:
            user_dir = os.path.expanduser("~")
            self.keys_directory = os.path.join(user_dir, ".mail_warden", "keys")
        else:
            self.keys_directory = keys_directory

        os.makedirs(self.keys_directory, exist_ok=True)

        self.key_cache = {}

        self.user_email = None
        self.user_private_key = None
        self.user_public_key = None

    def generate_user_keys(self, email, password=None):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        public_key = private_key.public_key()

        self.user_email = email
        self.user_private_key = private_key
        self.user_public_key = public_key

        self._save_user_keys(email, private_key, public_key, password)

        return {"email": email, "fingerprint": self._get_key_fingerprint(public_key)}

    def load_user_keys(self, email, password=None):
        try:
            private_key_path = os.path.join(self.keys_directory, f"{email}_private.pem")
            public_key_path = os.path.join(self.keys_directory, f"{email}_public.pem")

            if not os.path.exists(private_key_path) or not os.path.exists(
                public_key_path
            ):
                return None

            with open(private_key_path, "rb") as key_file:
                if password:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=password.encode(),
                        backend=default_backend(),
                    )
                else:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(), password=None, backend=default_backend()
                    )

            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(), backend=default_backend()
                )

            self.user_email = email
            self.user_private_key = private_key
            self.user_public_key = public_key

            return {
                "email": email,
                "fingerprint": self._get_key_fingerprint(public_key),
            }

        except Exception as e:
            print(f"Error loading user keys: {e}")
            return None

    def add_contact_key(self, email, public_key_data):
        try:
            public_key = serialization.load_pem_public_key(
                (
                    public_key_data.encode()
                    if isinstance(public_key_data, str)
                    else public_key_data
                ),
                backend=default_backend(),
            )

            key_path = os.path.join(self.keys_directory, f"{email}_contact.pem")
            with open(key_path, "wb") as key_file:
                key_file.write(
                    public_key_data.encode()
                    if isinstance(public_key_data, str)
                    else public_key_data
                )

            self.key_cache[email] = public_key

            return {
                "email": email,
                "fingerprint": self._get_key_fingerprint(public_key),
            }

        except Exception as e:
            print(f"Error adding contact key: {e}")
            return None

    def get_contact_key(self, email):
        if email in self.key_cache:
            return self.key_cache[email]

        key_path = os.path.join(self.keys_directory, f"{email}_contact.pem")
        if not os.path.exists(key_path):
            return None

        try:
            with open(key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(), backend=default_backend()
                )

            self.key_cache[email] = public_key
            return public_key

        except Exception as e:
            print(f"Error loading contact key: {e}")
            return None

    def list_contacts(self):
        contacts = []

        for filename in os.listdir(self.keys_directory):
            if filename.endswith("_contact.pem"):
                email = filename.replace("_contact.pem", "")

                key_path = os.path.join(self.keys_directory, filename)
                try:
                    with open(key_path, "rb") as key_file:
                        public_key = serialization.load_pem_public_key(
                            key_file.read(), backend=default_backend()
                        )

                    contacts.append(
                        {
                            "email": email,
                            "fingerprint": self._get_key_fingerprint(public_key),
                        }
                    )
                except Exception:
                    pass

        return contacts

    def encrypt_message(self, recipient_email, message):
        if not isinstance(message, bytes):
            message = message.encode("utf-8")

        recipient_key = self.get_contact_key(recipient_email)
        if not recipient_key:
            raise ValueError(f"No public key found for {recipient_email}")

        symmetric_key = Fernet.generate_key()

        f = Fernet(symmetric_key)
        encrypted_message = f.encrypt(message)

        encrypted_key = recipient_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        result = {
            "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
            "encrypted_message": base64.b64encode(encrypted_message).decode("utf-8"),
            "sender": self.user_email,
            "timestamp": int(time.time()),
        }

        return json.dumps(result)

    def decrypt_message(self, encrypted_data):
        if self.user_private_key is None:
            raise ValueError("No private key loaded")

        if isinstance(encrypted_data, str):
            data = json.loads(encrypted_data)
        else:
            data = encrypted_data

        encrypted_key = base64.b64decode(data["encrypted_key"])
        encrypted_message = base64.b64decode(data["encrypted_message"])

        symmetric_key = self.user_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        f = Fernet(symmetric_key)
        decrypted_message = f.decrypt(encrypted_message)

        return decrypted_message.decode("utf-8")

    def create_password_protected_email(self, message, password):
        if not isinstance(message, bytes):
            message = message.encode("utf-8")

        password_bytes = password.encode("utf-8")
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))

        f = Fernet(key)
        encrypted_message = f.encrypt(message)

        result = {
            "method": "password",
            "salt": base64.b64encode(salt).decode("utf-8"),
            "encrypted_message": base64.b64encode(encrypted_message).decode("utf-8"),
            "sender": self.user_email,
            "timestamp": int(time.time()),
        }

        return json.dumps(result)

    def decrypt_password_protected_email(self, encrypted_data, password):
        """Decrypt a password-protected email"""
        if isinstance(encrypted_data, str):
            data = json.loads(encrypted_data)
        else:
            data = encrypted_data

        salt = base64.b64decode(data["salt"])
        encrypted_message = base64.b64decode(data["encrypted_message"])

        password_bytes = password.encode("utf-8")
        kdf = hashes.PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))

        try:
            f = Fernet(key)
            decrypted_message = f.decrypt(encrypted_message)
            return decrypted_message.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Incorrect password or corrupted data: {e}")

    def get_public_key_string(self):
        if self.user_public_key is None:
            return None

        public_bytes = self.user_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return public_bytes.decode("utf-8")

    def _save_user_keys(self, email, private_key, public_key, password=None):
        if password:
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    password.encode()
                ),
            )
        else:
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_key_path = os.path.join(self.keys_directory, f"{email}_private.pem")
        public_key_path = os.path.join(self.keys_directory, f"{email}_public.pem")

        with open(private_key_path, "wb") as key_file:
            key_file.write(private_bytes)

        with open(public_key_path, "wb") as key_file:
            key_file.write(public_bytes)

    def _get_key_fingerprint(self, public_key):
        der_data = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(der_data)
        fingerprint_bytes = digest.finalize()

        fingerprint = ":".join(
            [fingerprint_bytes[i : i + 2].hex() for i in range(0, 8, 2)]
        )
        return fingerprint
