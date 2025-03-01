# Mail-Warden
Made by: Ryan Stoffel

A comprehensive email security tool with phishing detection, attachment scanning, and encrypted communications.
This project was made for my OS & Networking class at California Baptist University.

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

# Create a virtual environment
python -m venv myenv
source myenv/bin/activate

# Install dependencies using the setup helper file
python setup-helper.py

# Run the application
python run.py
```

## Usage

1. Launch the application using `python run.py`
2. Log in to your email account (For Gmail, you have to create an App-Specific Password)
3. Browse your emails in the Mail-Warden interface
4. Use the security features:
   - Click "Scan for Threats" to analyze the selected email for phishing attempts
   - Use the Attachments tab to scan attachments for potential malware
   - Use the Encryption tab to encrypt/decrypt secure messages

## Project Structure

```
mail-warden/
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
└── setup-helper.py            # Package configuration
└── run-tests.sh               # A script that runs all tests

```

## Running Tests

```bash
# Run all tests
chmod +x run-tests.sh
./run-tests.sh

# Run specific test modules
python -m unittest tests.test_attachment_scanner
python -m unittest tests.test_phishing_detector
python -m unittest tests.test_encryption_manager
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
