import re
import socket
import ssl
import urllib.parse
from datetime import datetime

import nltk
import whois
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

# Download necessary NLTK data
nltk.download("punkt")
nltk.download("stopwords")


class PhishingDetector:
    def __init__(self):
        # Common phishing keywords
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

        # Trusted domains (example)
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
        """
        Analyze email for phishing indicators

        Returns a dict with:
        - is_suspicious: bool
        - risk_score: float (0-1)
        - reasons: list of reasons for suspicion
        """
        results = {"is_suspicious": False, "risk_score": 0.0, "reasons": []}

        risk_factors = []

        # Check for suspicious links
        links = self._extract_links(email_data["body"])
        suspicious_links = self._analyze_links(links)
        if suspicious_links:
            risk_factors.append(("suspicious_links", 0.4, suspicious_links))

        # Check sender domain
        sender_analysis = self._analyze_sender(email_data["from"])
        if sender_analysis["suspicious"]:
            risk_factors.append(("suspicious_sender", 0.3, sender_analysis["reasons"]))

        # Check for suspicious content/keywords
        content_analysis = self._analyze_content(
            email_data["subject"], email_data["body"]
        )
        if content_analysis["suspicious"]:
            risk_factors.append(
                ("suspicious_content", 0.3, content_analysis["reasons"])
            )

        # Calculate total risk score
        if risk_factors:
            total_score = sum(factor[1] for factor in risk_factors)
            results["risk_score"] = min(total_score, 1.0)  # Cap at 1.0

            # Determine if suspicious based on threshold
            results["is_suspicious"] = results["risk_score"] > 0.5

            # Compile reasons
            for factor in risk_factors:
                for reason in factor[2]:
                    results["reasons"].append(reason)

        return results

    def _extract_links(self, body):
        """Extract all URLs from email body"""
        # URL regex pattern
        url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
        return re.findall(url_pattern, body)

    def _analyze_links(self, links):
        """Analyze links for suspicious characteristics"""
        suspicious_links = []

        for link in links:
            issues = []

            # Parse the URL
            parsed = urllib.parse.urlparse(link)
            domain = parsed.netloc

            # Check for IP address instead of domain
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
                issues.append(
                    f"URL contains IP address instead of domain name: {domain}"
                )

            # Check for suspicious TLDs
            suspicious_tlds = [".tk", ".xyz", ".top", ".club", ".work", ".online"]
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                issues.append(f"Domain uses suspicious TLD: {domain}")

            # Check for domain age if possible (would need whois library)
            try:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    # If domain has multiple creation dates, use the earliest
                    if isinstance(domain_info.creation_date, list):
                        creation_date = min(domain_info.creation_date)
                    else:
                        creation_date = domain_info.creation_date

                    # Check if domain is less than 30 days old
                    domain_age = (datetime.now() - creation_date).days
                    if domain_age < 30:
                        issues.append(
                            f"Domain is very new ({domain_age} days old): {domain}"
                        )
            except:
                # If whois lookup fails, consider it suspicious
                issues.append(f"Unable to verify domain age: {domain}")

            # Check for lookalike domains
            for trusted in self.trusted_domains:
                if self._is_lookalike_domain(domain, trusted) and domain != trusted:
                    issues.append(f"Possible lookalike domain: {domain} vs {trusted}")

            if issues:
                suspicious_links.append((link, issues))

        return suspicious_links

    def _is_lookalike_domain(self, domain, trusted_domain):
        """Check if a domain looks similar to a trusted domain"""
        # Remove TLD for comparison
        domain_base = domain.split(".")[-2] if len(domain.split(".")) > 1 else domain
        trusted_base = (
            trusted_domain.split(".")[-2]
            if len(trusted_domain.split(".")) > 1
            else trusted_domain
        )

        # Check for character substitution (e.g., 0 for o, l for 1)
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

        # Check if domains are very similar after normalization
        if normalized_domain == normalized_trusted:
            return False  # Exact match is not suspicious

        # Apply substitutions and check again
        for char, subst in substitutions.items():
            if char in normalized_domain:
                if normalized_domain.replace(char, subst) == normalized_trusted:
                    return True

        # Check Levenshtein distance (if domains are similar but not identical)
        # Simple implementation - for production, use a library
        if len(normalized_domain) > 3 and len(normalized_trusted) > 3:
            # If the domain is similar but with 1-2 character differences
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
        """Analyze the sender address for suspicious characteristics"""
        result = {"suspicious": False, "reasons": []}

        # Extract email address from "Name <email>" format
        email_match = re.search(r"<([^>]+)>", sender)
        if email_match:
            email = email_match.group(1)
        else:
            email = sender

        # Split into username and domain
        try:
            username, domain = email.split("@")
        except ValueError:
            result["suspicious"] = True
            result["reasons"].append(f"Invalid email format: {email}")
            return result

        # Check for trusted domain spoofing
        display_name = sender.split("<")[0].strip() if "<" in sender else ""
        for trusted_domain in self.trusted_domains:
            if (
                trusted_domain in display_name.lower()
                and trusted_domain not in domain.lower()
            ):
                result["suspicious"] = True
                result["reasons"].append(
                    f"Display name contains trusted organization ({trusted_domain}) "
                    f"but email is from different domain ({domain})"
                )

        # Check for suspicious domain characteristics
        if any(domain.endswith(tld) for tld in [".tk", ".xyz", ".top", ".club"]):
            result["suspicious"] = True
            result["reasons"].append(f"Email from suspicious TLD: {domain}")

        # Check for random-looking username (many numbers, random characters)
        if (
            re.match(r"^[a-z0-9]{10,}$", username)
            and sum(c.isdigit() for c in username) > 5
        ):
            result["suspicious"] = True
            result["reasons"].append(f"Username appears randomly generated: {username}")

        return result

    def _analyze_content(self, subject, body):
        """Analyze email content for phishing indicators"""
        result = {"suspicious": False, "reasons": []}

        # Combine subject and body for analysis
        full_text = f"{subject} {body}".lower()

        # Count suspicious keywords
        keyword_count = sum(
            1 for keyword in self.suspicious_keywords if keyword in full_text.split()
        )

        # If more than 3 suspicious keywords, flag it
        if keyword_count > 3:
            result["suspicious"] = True
            result["reasons"].append(
                f"Contains multiple suspicious keywords ({keyword_count})"
            )

        # Check for urgency language
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

        # Check for poor grammar/spelling (simplified check)
        tokens = word_tokenize(body)
        stop_words = set(stopwords.words("english"))
        non_stop_words = [word for word in tokens if word.lower() not in stop_words]

        # Simple ratio of words to unique words as a proxy for repetition/poor writing
        unique_ratio = (
            len(set(non_stop_words)) / len(non_stop_words) if non_stop_words else 1
        )
        if unique_ratio < 0.5 and len(non_stop_words) > 20:  # Simple heuristic
            result["suspicious"] = True
            result["reasons"].append("Contains repetitive or unusual text patterns")

        # Look for request for personal information
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
            result["reasons"].append("Requests sensitive personal information")

        return result
