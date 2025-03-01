import re
import socket
import ssl
import urllib.parse
from datetime import datetime

import nltk
import whois
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

nltk.download("punkt")
nltk.download("stopwords")


class PhishingDetector:
    def __init__(self):
        self.suspicious_keywords = [
            "urgent",
            "alert",
            "verify",
            "suspended",
            "restriction",
            "confirm",
            "account",
            "banking",
            "security",
            "update",
            "login",
            "unusual",
            "unauthorized",
            "access",
            "click",
            "link",
            "password",
            "information",
        ]

        self.trusted_domains = [
            "google.com",
            "gmail.com",
            "microsoft.com",
            "apple.com",
            "amazon.com",
            "paypal.com",
            "facebook.com",
            "twitter.com",
        ]

    def analyze_email(self, email_data):
        results = {"is_suspicious": False, "risk_score": 0.0, "reasons": []}

        risk_factors = []

        links = self._extract_links(email_data["body"])
        suspicious_links = self._analyze_links(links)
        if suspicious_links:
            risk_factors.append(("suspicious_links", 0.4, suspicious_links))

        # Fixed: Now only passing the "from" field to _analyze_sender()
        sender_analysis = self._analyze_sender(email_data["from"])
        if sender_analysis["suspicious"]:
            risk_factors.append(("suspicious_sender", 0.3, sender_analysis["reasons"]))

        content_analysis = self._analyze_content(
            email_data["subject"], email_data["body"]
        )
        if content_analysis["suspicious"]:
            risk_factors.append(
                ("suspicious_content", 0.3, content_analysis["reasons"])
            )

        if risk_factors:
            total_score = sum(factor[1] for factor in risk_factors)
            results["risk_score"] = min(total_score, 1.0)

            results["is_suspicious"] = results["risk_score"] > 0.5

            for factor in risk_factors:
                for reason in factor[2]:
                    results["reasons"].append(reason)

        return results

    def _extract_links(self, body):
        url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
        return re.findall(url_pattern, body)

    def _analyze_links(self, links):
        suspicious_links = []

        for link in links:
            issues = []

            parsed = urllib.parse.urlparse(link)
            domain = parsed.netloc

            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
                issues.append(
                    f"URL contains IP Address instead of domain name: {domain}"
                )

            suspicious_tlds = [".tk", ".xyz", ".top", ".club", ".work", ".online"]
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                issues.append(f"Domain uses suspicious TLD: {domain}")

            try:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = min(domain_info.creation_date)
                    else:
                        creation_date = domain_info.creation_date

                    domain_age = (datetime.now() - creation_date).days
                    if domain_age < 30:
                        issues.append(
                            f"Domain is very new ({domain_age}) days old): {domain}"
                        )
            except:
                issues.append(f"Unable to verify domain age: {domain}")

            for trusted in self.trusted_domains:
                if self._is_lookalike_domain(domain, trusted) and domain != trusted:
                    issues.append(f"Possible lookalike domain: {domain} vs {trusted}")

            if issues:
                suspicious_links.append((link, issues))
        return suspicious_links

    def _is_lookalike_domain(self, domain, trusted_domain):
        domain_base = domain.split(".")[-2] if len(domain.split(".")) > 1 else domain
        trusted_base = (
            trusted_domain.split(".")[-2]
            if len(trusted_domain.split(".")) > 1
            else trusted_domain
        )

        substitutions = {
            "0": "o",
            "o": "0",
            "1": "l",
            "l": "1",
            "i": "1",
            "5": "s",
            "s": "5",
            "rn": "m",
            "m": "rn",
        }

        normalized_domain = domain_base.lower()
        normalized_trusted = trusted_base.lower()

        if normalized_domain == normalized_trusted:
            return False

        for char, subst in substitutions.items():
            if char in normalized_domain:
                if normalized_domain.replace(char, subst) == normalized_trusted:
                    return True

        if len(normalized_domain) > 3 and len(normalized_trusted) > 3:
            if abs(len(normalized_domain) - len(normalized_trusted)) <= 2:
                differences = sum(
                    a != b
                    for a, b in zip(
                        normalized_domain, normalized_trusted[: len(normalized_domain)]
                    )
                )
                differences += abs(len(normalized_domain) - len(normalized_trusted))

                if differences <= 2:
                    return True
        return False

    def _analyze_sender(self, sender):
        result = {"suspicious": False, "reasons": []}

        email_match = re.search(r"<([^>]+)>", sender)
        if email_match:
            email = email_match.group(1)
        else:
            email = sender

        try:
            username, domain = email.split("@")
        except ValueError:
            result["suspicious"] = True
            result["reasons"].append(f"Invalid email format: {email}")
            return result

        display_name = sender.split("<")[0].strip() if "<" in sender else ""
        for trusted_domain in self.trusted_domains:
            if (
                trusted_domain in display_name.lower()
                and trusted_domain not in domain.lower()
            ):
                result["suspicious"] = True
                result["reasons"].append(
                    f"Display name contains trusted organization ({trusted_domain}) "
                    f"but email is from a different domain ({domain})"
                )

        if any(domain.endswith(tld) for tld in [".tk", ".xyz", ".top", ".club"]):
            result["suspicious"] = True
            result["reasons"].append(f"Email from suspicious TLD: {domain}")

        if (
            re.match(r"^[a-z0-9]{10,}$", username)
            and sum(c.isdigit() for c in username) > 5
        ):
            result["suspicious"] = True
            result["reasons"].append(
                f"Username appears to be randomly generated: {username}"
            )
        return result

    def _analyze_content(self, subject, body):
        result = {"suspicious": False, "reasons": []}

        full_text = f"{subject} {body}".lower()

        keyword_count = sum(
            1 for keyword in self.suspicious_keywords if keyword in full_text.split()
        )

        if keyword_count > 3:
            result["suspicious"] = True
            result["reasons"].append(
                f"Contains multiple suspicious keywords ({keyword_count})"
            )

        urgency_patterns = [
            r"urgent",
            r"immediately",
            r"within 24 hours",
            r"as soon as possible",
            r"failure to",
            r"suspended",
            r"limited",
            r"restricted",
        ]

        urgency_matches = [
            pattern for pattern in urgency_patterns if re.search(pattern, full_text)
        ]
        if urgency_matches:
            result["suspicious"] = True
            result["reasons"].append("Contains urgent action language")

        tokens = word_tokenize(body)
        stop_words = set(stopwords.words("english"))
        non_stop_words = [word for word in tokens if word.lower() not in stop_words]

        unique_ratio = (
            len(set(non_stop_words)) / len(non_stop_words) if non_stop_words else 1
        )
        if unique_ratio < 0.5 and len(non_stop_words) > 20:
            result["suspicious"] = True
            result["reasons"].append("Contains repetitive or unusual text patterns")

        info_request_patterns = [
            r"verify your",
            r"confirm your",
            r"update your",
            r"enter your",
            r"provide your",
            r"password",
            r"account number",
            r"credit card",
            r"ssn",
            r"social security",
            r"credentials",
        ]

        info_matches = [
            pattern
            for pattern in info_request_patterns
            if re.search(pattern, full_text)
        ]
        if info_matches:
            result["suspicious"] = True
            result["reasons"].append("Requests sensitive personal information.")

        return result
