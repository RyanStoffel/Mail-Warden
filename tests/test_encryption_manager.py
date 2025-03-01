import base64
import json
import os

# Make sure we can import our module
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.encryption_manager import EncryptionManager


class TestEncryptionManager(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for key storage
        self.temp_dir = tempfile.mkdtemp()
        self.encryption_manager = EncryptionManager(keys_directory=self.temp_dir)

        # Generate test keys
        self.test_email = "test@example.com"
        self.test_password = "testpassword"
        self.contact_email = "contact@example.com"

    def tearDown(self):
        # Clean up temporary files
        for file in os.listdir(self.temp_dir):
            try:
                os.remove(os.path.join(self.temp_dir, file))
            except:
                pass
        os.rmdir(self.temp_dir)

    def test_key_generation_and_loading(self):
        """Test that keys can be generated and loaded correctly"""
        # Generate keys
        key_info = self.encryption_manager.generate_user_keys(
            self.test_email, self.test_password
        )

        self.assertEqual(key_info["email"], self.test_email)
        self.assertIsNotNone(key_info["fingerprint"])

        # Check that keys were saved to disk
        private_key_path = os.path.join(self.temp_dir, f"{self.test_email}_private.pem")
        public_key_path = os.path.join(self.temp_dir, f"{self.test_email}_public.pem")

        self.assertTrue(os.path.exists(private_key_path))
        self.assertTrue(os.path.exists(public_key_path))

        # Create a new encryption manager to test loading
        new_manager = EncryptionManager(keys_directory=self.temp_dir)
        loaded_key_info = new_manager.load_user_keys(
            self.test_email, self.test_password
        )

        self.assertEqual(loaded_key_info["email"], self.test_email)
        self.assertEqual(loaded_key_info["fingerprint"], key_info["fingerprint"])

    def test_add_and_get_contact_key(self):
        """Test that contact keys can be added and retrieved correctly"""
        # Generate keys for the user first
        self.encryption_manager.generate_user_keys(self.test_email)

        # Get the public key as a string
        public_key_string = self.encryption_manager.get_public_key_string()

        # Add the public key as a contact key
        contact_info = self.encryption_manager.add_contact_key(
            self.contact_email, public_key_string
        )

        self.assertEqual(contact_info["email"], self.contact_email)
        self.assertIsNotNone(contact_info["fingerprint"])

        # Check that the contact key was saved to disk
        contact_key_path = os.path.join(
            self.temp_dir, f"{self.contact_email}_contact.pem"
        )
        self.assertTrue(os.path.exists(contact_key_path))

        # Get the contact key
        contact_key = self.encryption_manager.get_contact_key(self.contact_email)
        self.assertIsNotNone(contact_key)

    def test_encryption_and_decryption(self):
        """Test that messages can be encrypted and decrypted correctly"""
        # Generate keys
        self.encryption_manager.generate_user_keys(self.test_email)

        # Add the user's public key as a contact (for testing purposes)
        public_key_string = self.encryption_manager.get_public_key_string()
        self.encryption_manager.add_contact_key(self.contact_email, public_key_string)

        # Test message
        test_message = "This is a secret message for testing encryption and decryption."

        # Encrypt the message
        encrypted_data = self.encryption_manager.encrypt_message(
            self.contact_email, test_message
        )

        # Verify encrypted data structure
        encrypted_json = json.loads(encrypted_data)
        self.assertIn("encrypted_key", encrypted_json)
        self.assertIn("encrypted_message", encrypted_json)
        self.assertIn("sender", encrypted_json)
        self.assertIn("timestamp", encrypted_json)

        # Decrypt the message
        decrypted_message = self.encryption_manager.decrypt_message(encrypted_data)

        # Verify decryption
        self.assertEqual(decrypted_message, test_message)

    def test_password_protected_email(self):
        """Test that password-protected emails can be encrypted and decrypted correctly"""
        # Generate keys (not actually needed for password protection, but for consistency)
        self.encryption_manager.generate_user_keys(self.test_email)

        # Test message
        test_message = "This is a secret message protected by a password."
        test_password = "secretpassword123"

        # Create password-protected email
        encrypted_data = self.encryption_manager.create_password_protected_email(
            test_message, test_password
        )

        # Verify encrypted data structure
        encrypted_json = json.loads(encrypted_data)
        self.assertIn("method", encrypted_json)
        self.assertEqual(encrypted_json["method"], "password")
        self.assertIn("salt", encrypted_json)
        self.assertIn("encrypted_message", encrypted_json)
        self.assertIn("sender", encrypted_json)
        self.assertIn("timestamp", encrypted_json)

        # Decrypt the message with correct password
        decrypted_message = self.encryption_manager.decrypt_password_protected_email(
            encrypted_data, test_password
        )
        self.assertEqual(decrypted_message, test_message)

        # Attempt to decrypt with wrong password
        with self.assertRaises(ValueError):
            self.encryption_manager.decrypt_password_protected_email(
                encrypted_data, "wrongpassword"
            )

    def test_list_contacts(self):
        """Test that contacts can be listed correctly"""
        # Generate keys
        self.encryption_manager.generate_user_keys(self.test_email)

        # Add some contacts
        public_key_string = self.encryption_manager.get_public_key_string()
        self.encryption_manager.add_contact_key(
            "contact1@example.com", public_key_string
        )
        self.encryption_manager.add_contact_key(
            "contact2@example.com", public_key_string
        )

        # List contacts
        contacts = self.encryption_manager.list_contacts()

        # Verify contacts
        self.assertEqual(len(contacts), 2)
        contact_emails = [contact["email"] for contact in contacts]
        self.assertIn("contact1@example.com", contact_emails)
        self.assertIn("contact2@example.com", contact_emails)


if __name__ == "__main__":
    unittest.main()
