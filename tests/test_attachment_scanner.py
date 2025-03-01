import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.attachment_scanner import AttachmentScanner

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAttachmentScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = AttachmentScanner()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        # Clean up temporary files
        for file in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, file))
        os.rmdir(self.temp_dir)

    def create_test_file(self, name, content=b"test content"):
        path = os.path.join(self.temp_dir, name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_safe_file(self):
        file_path = self.create_test_file("test.txt")
        result = self.scanner.scan_attachment(file_path, "test.txt")

        self.assertEqual(result["risk_level"], "safe")
        self.assertAlmostEqual(result["risk_score"], 0.0)
        self.assertEqual(len(result["reasons"]), 0)

    def test_dangerous_extension(self):
        file_path = self.create_test_file("malware.exe")
        result = self.scanner.scan_attachment(file_path, "malware.exe")

        self.assertNotEqual(result["risk_level"], "safe")
        self.assertGreater(result["risk_score"], 0.0)
        self.assertGreater(len(result["reasons"]), 0)

        # Check if the reason mentions the dangerous extension
        self.assertTrue(
            any("dangerous extension" in reason.lower() for reason in result["reasons"])
        )

    def test_moderate_risk_extension(self):
        file_path = self.create_test_file("document.doc")
        result = self.scanner.scan_attachment(file_path, "document.doc")

        self.assertNotEqual(result["risk_level"], "safe")
        self.assertGreater(result["risk_score"], 0.0)
        self.assertGreater(len(result["reasons"]), 0)

        self.assertTrue(
            any("risky extension" in reason.lower() for reason in result["reasons"])
        )

    @patch("magic.Magic")
    def test_file_type_mismatch(self, mock_magic):
        magic_instance = MagicMock()
        magic_instance.from_file.return_value = "application/x-dosexec"
        mock_magic.return_value = magic_instance

        file_path = self.create_test_file("trojan.txt")
        result = self.scanner.scan_attachment(file_path, "trojan.txt")

        self.assertNotEqual(result["risk_level"], "safe")
        self.assertGreater(result["risk_score"], 0.0)

        self.assertTrue(
            any(
                "executable" in reason.lower()
                or "application/x-dosexec" in reason.lower()
                for reason in result["reasons"]
            ),
            "Test expected to find a reason mentioning the executable content",
        )

    def test_known_malware_hash(self):
        original_hashes = self.scanner.malware_hashes

        test_content = b"malicious content for testing"
        import hashlib

        md5 = hashlib.md5(test_content).hexdigest()
        self.scanner.malware_hashes = [md5]

        try:
            file_path = self.create_test_file("malware.bin", test_content)
            result = self.scanner.scan_attachment(file_path, "malware.bin")

            self.assertEqual(result["risk_level"], "dangerous")
            self.assertAlmostEqual(result["risk_score"], 1.0)
            self.assertTrue(
                any(
                    "malware signature" in reason.lower()
                    for reason in result["reasons"]
                )
            )
        finally:
            self.scanner.malware_hashes = original_hashes

    @patch("zipfile.is_zipfile")
    @patch("zipfile.ZipFile")
    def test_archive_with_dangerous_files(self, mock_zipfile, mock_is_zipfile):
        mock_is_zipfile.return_value = True

        mock_zip = MagicMock()
        mock_zip.namelist.return_value = ["safe.txt", "dangerous.exe", "bad.js"]
        mock_zipfile.return_value = mock_zip

        file_path = self.create_test_file("archive.zip")
        result = self.scanner.scan_attachment(file_path, "archive.zip")

        self.assertNotEqual(result["risk_level"], "safe")
        self.assertGreater(result["risk_score"], 0.0)
        self.assertTrue(
            any("dangerous files" in reason.lower() for reason in result["reasons"])
        )


if __name__ == "__main__":
    unittest.main()
