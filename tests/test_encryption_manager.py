import json
import os
import sys
import tempfile
import unittest

from src.encryption_manager import EncryptionManager

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestEncryptionManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.encryption_manager = EncryptionManager(keys_directory=self.temp_dir)

        self.test_email = "test@example.com"
        self.test_password = "testpassword"
        self.contact_email = "contact@example.com"

    def tearDown(self):
        for file in os.listdir(self.temp_dir):
            try:
                os.remove(os.path.join(self.temp_dir, file))
            except:
                pass
        os.rmdir(self.temp_dir)

    def test_key_generation_and_loading(self):
        key_info = self.encryption_manager.generate_user_keys(
            self.test_email, self.test_password
        )

        self.assertEqual(key_info["email"], self.test_email)
        self.assertIsNotNone(key_info["fingerprint"])

        private_key_path = os.path.join(self.temp_dir, f"{self.test_email}_private.pem")
        public_key_path = os.path.join(self.temp_dir, f"{self.test_email}_public.pem")

        self.assertTrue(os.path.exists(private_key_path))
        self.assertTrue(os.path.exists(public_key_path))

        new_manager = EncryptionManager(keys_directory=self.temp_dir)
        loaded_key_info = new_manager.load_user_keys(
            self.test_email, self.test_password
        )

        self.assertEqual(loaded_key_info["email"], self.test_email)
        self.assertEqual(loaded_key_info["fingerprint"], key_info["fingerprint"])

    def test_add_and_get_contact_key(self):
        self.encryption_manager.generate_user_keys(self.test_email)

        public_key_string = self.encryption_manager.get_public_key_string()

        contact_info = self.encryption_manager.add_contact_key(
            self.contact_email, public_key_string
        )

        self.assertEqual(contact_info["email"], self.contact_email)
        self.assertIsNotNone(contact_info["fingerprint"])

        contact_key_path = os.path.join(
            self.temp_dir, f"{self.contact_email}_contact.pem"
        )
        self.assertTrue(os.path.exists(contact_key_path))

        contact_key = self.encryption_manager.get_contact_key(self.contact_email)
        self.assertIsNotNone(contact_key)

    def test_encryption_and_decryption(self):
        self.encryption_manager.generate_user_keys(self.test_email)

        public_key_string = self.encryption_manager.get_public_key_string()
        self.encryption_manager.add_contact_key(self.contact_email, public_key_string)

        test_message = "This is a secret message for testing encryption and decryption."

        encrypted_data = self.encryption_manager.encrypt_message(
            self.contact_email, test_message
        )

        encrypted_json = json.loads(encrypted_data)
        self.assertIn("encrypted_key", encrypted_json)
        self.assertIn("encrypted_message", encrypted_json)
        self.assertIn("sender", encrypted_json)
        self.assertIn("timestamp", encrypted_json)

        decrypted_message = self.encryption_manager.decrypt_message(encrypted_data)

        self.assertEqual(decrypted_message, test_message)

    def test_password_protected_email(self):
        self.encryption_manager.generate_user_keys(self.test_email)

        test_message = "This is a secret message protected by a password."
        test_password = "secretpassword123"

        encrypted_data = self.encryption_manager.create_password_protected_email(
            test_message, test_password
        )

        encrypted_json = json.loads(encrypted_data)
        self.assertIn("method", encrypted_json)
        self.assertEqual(encrypted_json["method"], "password")
        self.assertIn("salt", encrypted_json)
        self.assertIn("encrypted_message", encrypted_json)
        self.assertIn("sender", encrypted_json)
        self.assertIn("timestamp", encrypted_json)

        decrypted_message = self.encryption_manager.decrypt_password_protected_email(
            encrypted_data, test_password
        )
        self.assertEqual(decrypted_message, test_message)

        with self.assertRaises(ValueError):
            self.encryption_manager.decrypt_password_protected_email(
                encrypted_data, "wrongpassword"
            )

    def test_list_contacts(self):
        self.encryption_manager.generate_user_keys(self.test_email)

        public_key_string = self.encryption_manager.get_public_key_string()
        self.encryption_manager.add_contact_key(
            "contact1@example.com", public_key_string
        )
        self.encryption_manager.add_contact_key(
            "contact2@example.com", public_key_string
        )

        contacts = self.encryption_manager.list_contacts()

        self.assertEqual(len(contacts), 2)
        contact_emails = [contact["email"] for contact in contacts]
        self.assertIn("contact1@example.com", contact_emails)
        self.assertIn("contact2@example.com", contact_emails)


if __name__ == "__main__":
    unittest.main()
