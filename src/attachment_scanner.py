import hashlib
import os
import re
import tempfile
import zipfile

import magic


class AttachmentScanner:
    def __init__(self):
        self.dangerous_extensions = [
            ".exe",
            ".scr",
            ".bat",
            ".cmd",
            ".js",
            ".vbs",
            ".ps1",
            ".wsf",
            ".jar",
            ".jse",
            ".lnk",
            ".pif",
            ".hta",
            ".msi",
            ".reg",
        ]

        self.moderate_risk_extensions = [
            ".doc",
            ".docm",
            ".xls",
            ".xlsm",
            ".ppt",
            ".pptm",
            ".pdf",
            ".zip",
            ".rar",
            ".7z",
        ]

        self.malware_hashes = [
            "44d88612fea8a8f36de82e1278abb02f",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ]

    def scan_attachment(self, file_path, file_name):
        result = {"risk_level": "safe", "risk_score": 0.0, "reasons": []}

        risk_factors = []

        extension_risk = self._check_extension(file_name)
        if extension_risk:
            risk_factors.append(extension_risk)

        file_type_risk = self._check_file_type(file_path)
        if file_type_risk:
            risk_factors.append(file_type_risk)

        hash_risk = self._check_file_hash(file_path)
        if hash_risk:
            risk_factors.append(hash_risk)

        if self._is_archive(file_path):
            archive_risk = self._scan_archive_contents(file_path)
            if archive_risk:
                risk_factors.append(archive_risk)

        if self._is_office_doc(file_path):
            macro_risk = self._check_for_macros(file_path)
            if macro_risk:
                risk_factors.append(macro_risk)

        if risk_factors:
            max_risk = max(factor[0] for factor in risk_factors)
            total_risk = sum(factor[0] for factor in risk_factors)
            result["risk_score"] = min(total_risk, 1.0)

            if max_risk >= 0.7:
                result["risk_level"] = "dangerous"
            elif max_risk >= 0.3:
                result["risk_level"] = "suspicious"

            for factor in risk_factors:
                result["reasons"].append(factor[1])

        return result

    def _check_extension(self, filename):
        """Check if file has a dangerous extension"""
        _, ext = os.path.splitext(filename.lower())

        if ext in self.dangerous_extensions:
            return (0.8, f"File has dangerous extension: {ext}")
        elif ext in self.moderate_risk_extensions:
            return (0.4, f"File has potentially risky extension: {ext}")

        return None

    def _check_file_type(self, file_path):
        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)

            dangerous_types = [
                "application/x-dosexec",
                "application/x-executable",
                "application/x-msdownload",
                "application/x-msdos-program",
            ]

            moderate_risk_types = [
                "application/vnd.ms-office",
                "application/vnd.openxmlformats-officedocument",
                "application/zip",
                "application/x-rar",
                "application/x-7z-compressed",
                "application/pdf",
            ]

            if file_type in dangerous_types:
                return (0.8, f"File detected as executable type: {file_type}")
            elif file_type in moderate_risk_types:
                return (0.3, f"File detected as potentially risky type: {file_type}")

            _, ext = os.path.splitext(file_path.lower())
            if ext == ".txt" and file_type != "text/plain":
                return (
                    0.7,
                    f"File extension mismatch: {ext} file contains {file_type}",
                )
            elif ext == ".jpg" and not file_type.startswith("image/"):
                return (
                    0.7,
                    f"File extension mismatch: {ext} file contains {file_type}",
                )
            elif ext == ".pdf" and file_type != "application/pdf":
                return (
                    0.7,
                    f"File extension mismatch: {ext} file contains {file_type}",
                )

        except Exception as e:
            return (0.4, f"Unable to determine file type: {str(e)}")

        return None

    def _check_file_hash(self, file_path):
        try:
            md5_hash = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
            md5_digest = md5_hash.hexdigest()

            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            sha256_digest = sha256_hash.hexdigest()

            if (
                md5_digest in self.malware_hashes
                or sha256_digest in self.malware_hashes
            ):
                return (1.0, f"File matches known malware signature")

        except Exception as e:
            return (0.2, f"Unable to calculate file hash: {str(e)}")

        return None

    def _is_archive(self, file_path):
        """Determine if file is an archive"""
        try:
            _, ext = os.path.splitext(file_path.lower())
            if ext in [".zip", ".rar", ".7z", ".tar", ".gz"]:
                return True

            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            if file_type in [
                "application/zip",
                "application/x-rar",
                "application/x-7z-compressed",
                "application/x-tar",
                "application/gzip",
            ]:
                return True

        except Exception:
            pass

        return False

    def _scan_archive_contents(self, file_path):
        try:
            if not zipfile.is_zipfile(file_path):
                return None

            archive = zipfile.ZipFile(file_path)
            file_list = archive.namelist()

            dangerous_count = 0
            suspicious_files = []

            for filename in file_list:
                _, ext = os.path.splitext(filename.lower())

                if ext in self.dangerous_extensions:
                    dangerous_count += 1
                    suspicious_files.append(filename)
                elif ext in self.moderate_risk_extensions:
                    suspicious_files.append(filename)

                if ext in [".zip", ".rar", ".7z"] and filename.count("/") > 2:
                    return (
                        0.6,
                        f"Archive contains deeply nested archives (potential archive bomb)",
                    )

            if dangerous_count > 0:
                return (
                    0.7,
                    f"Archive contains {dangerous_count} potentially dangerous files: {', '.join(suspicious_files[:3])}",
                )

            if len(file_list) > 1000:
                return (
                    0.5,
                    f"Archive contains an unusually large number of files ({len(file_list)})",
                )

        except Exception as e:
            return (0.3, f"Unable to analyze archive contents: {str(e)}")

        return None

    def _is_office_doc(self, file_path):
        try:
            _, ext = os.path.splitext(file_path.lower())
            office_extensions = [
                ".doc",
                ".docx",
                ".docm",
                ".xls",
                ".xlsx",
                ".xlsm",
                ".ppt",
                ".pptx",
                ".pptm",
            ]

            if ext in office_extensions:
                return True

            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)

            if (
                "officedocument" in file_type
                or "msword" in file_type
                or "ms-excel" in file_type
            ):
                return True

        except Exception:
            pass

        return False

    def _check_for_macros(self, file_path):
        try:
            _, ext = os.path.splitext(file_path.lower())
            if ext in [".docm", ".xlsm", ".pptm"]:
                return (0.5, f"Document has macro-enabled format: {ext}")

            if ext in [".doc", ".xls", ".ppt"]:
                with open(file_path, "rb") as f:
                    content = f.read()
                    if (
                        b"VBA" in content
                        or b"ThisDocument" in content
                        or b"Auto_Open" in content
                    ):
                        return (0.6, "Document appears to contain macros")

        except Exception as e:
            return (0.2, f"Unable to check for macros: {str(e)}")

        return None
