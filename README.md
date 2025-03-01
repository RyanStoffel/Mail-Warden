# Mail-Warden

A comprehensive email security tool with phishing detection, attachment scanning, and encrypted communications.

## Features

### 1. Phishing Detection

- Analyzes email content for suspicious keywords and urgency indicators
- Detects suspicious links and lookalike domains
- Identifies sender spoofing attempts
- Alerts when sensitive information is requested

### 2. Attachment Scanner

- Scans email attachments for potential threats
- Detects dangerous file types and extensions
- Identifies file type/extension mismatches
- Inspects archives for hidden threats
- Checks for known malware signatures
- Detects potentially harmful macros in Office documents

### 3. Encryption Manager

- Provides public key cryptography for secure communications
- Allows password-protected emails for recipients without keys
- Securely manages contact keys
- Integrates with existing email workflows

## Getting Started

### Prerequisites

- Python 3.8+
- Required Python packages (see requirements.txt)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/mail-warden.git
cd mail-warden

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py
```

## Usage

1. Launch the application using `python run.py`
2. Log in to your email account
3. Browse your emails in the Mail-Warden interface
4. Use the security features:
   - Click "Scan for Threats" to analyze the selected email for phishing attempts
   - Use the Attachments tab to scan attachments for potential malware
   - Use the Encryption tab to encrypt/decrypt secure messages

## Project Structure

```
mail-warden/
├── data/                      # Data files for threat detection
│   ├── malware_signatures.db
│   └── phishing_patterns.json
├── src/                       # Source code
│   ├── attachment_scanner.py  # Scans attachments for threats
│   ├── email_processor.py     # Handles email retrieval
│   ├── encryption_manager.py  # Manages encryption capabilities
│   ├── main.py                # Application entry point
│   ├── phishing_detector.py   # Detects phishing attempts
│   └── ui/                    # User interface components
├── tests/                     # Unit tests
│   ├── test_attachment_scanner.py
│   ├── test_phishing_detector.py
│   └── test_encryption_manager.py
├── LICENSE                    # MIT License
├── README.md                  # Project documentation
├── requirements.txt           # Python dependencies
├── run.py                     # Application runner
└── setup.py                   # Package configuration
```

## Running Tests

```bash
# Run all tests
python -m unittest discover tests

# Run specific test modules
python -m unittest tests.test_attachment_scanner
python -m unittest tests.test_phishing_detector
python -m unittest tests.test_encryption_manager
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
