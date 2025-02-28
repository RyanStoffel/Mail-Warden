import email
import imaplib
import os
import tempfile
from email.header import decode_header


class EmailProcessor:
    def __init__(self, email_address, password, imap_server="imap.gmail.com"):
        self.email_address = email_address
        self.password = password
        self.imap_server = imap_server
        self.connection = None

    def connect(self):
        try:
            self.connection = imaplib.IMAP4_SSL(self.imap_server)
            self.connection.login(self.email_address, self.password)
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def disconnect(self):
        if self.connection:
            self.connection.logout()

    def get_inbox_messages(self, limit=10):
        if not self.connection:
            if not self.connect():
                return []

        messages = []
        try:
            status, messages_ids = self.connection.select("INBOX")
            if status != "OK":
                return []

            status, data = self.connection.search(None, "ALL")
            if status != "OK":
                return []

            email_ids = data[0].split()
            email_ids = email_ids[-limit:] if limit < len(email_ids) else email_ids

            for email_id in email_ids:
                status, data = self.connection.fetch(email_id, "(RFC822)")
                if status != "OK":
                    continue

                raw_email = data[0][1]
                email_message = email.message_from_bytes(raw_email)

                subject = self._decode_email_header(email_message["Subject"])
                from_address = self._decode_email_header(email_message["From"])
                date = email_message["Date"]

                body = ""
                attachments = []

                if email_message.is_multipart():
                    for part in email_message.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))

                        if (
                            content_type == "text/plain"
                            and "attachment" not in content_disposition
                        ):
                            body = part.get_payload(decode=True).decode()

                        if "attachment" in content_disposition:
                            filename = part.get_filename()
                            if filename:
                                with tempfile.NamedTemporaryFile(delete=False) as temp:
                                    temp.write(part.get_payload(decode=True))
                                    attachments.append(filename, temp.name)
                else:
                    body = email_message.get_payload(decode=True).decode()

                messages.append(
                    {
                        "id": email_id,
                        "subject": subject,
                        "from": from_address,
                        "date": date,
                        "body": body,
                        "attachments": attachments,
                        "raw_email": email_message,
                    }
                )

            return messages
        except Exception as e:
            print(f"Error fetching emails: {e}")
            return []

    def _decode_email_header(self, header):
        if header is None:
            return ""

        decoded_header = decode_header(header)
        header_parts = []

        for content, encoding in decoded_header:
            if isinstance(content, bytes):
                try:
                    header_parts.append(
                        content.decode(encoding if encoding else "utf-8")
                    )
                except:
                    try:
                        header_parts.append(content.decode("utf-8"))
                    except:
                        try:
                            header_parts.append(content.decode("latin-1"))
                        except:
                            header_parts.append(
                                content.decode("utf-8", errors="ignore")
                            )
            else:
                header_parts.append(content)

        return " ".join(header_parts)
