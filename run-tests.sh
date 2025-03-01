#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}Running Mail-Warden Test Suite${NC}"
echo "===================================="

print_test_header() {
    local module=$1
    local description=$2
    echo -e "\n${BLUE}Testing ${module}...${NC}"
    echo -e "${CYAN}Purpose: ${description}${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
}

print_test_header "Attachment Scanner" "Verifies the functionality for detecting dangerous files, malicious file types, extension mismatches, and analyzing archives for threats."
python -m unittest tests.test_attachment_scanner
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Attachment Scanner tests passed!${NC}"
else
    echo -e "${RED}✗ Attachment Scanner tests failed!${NC}"
    exit 1
fi

print_test_header "Phishing Detector" "Validates detection of suspicious keywords, spoofed senders, malicious URLs, lookalike domains, and urgent action language in emails."
python -m unittest tests.test_phishing_detector
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Phishing Detector tests passed!${NC}"
else
    echo -e "${RED}✗ Phishing Detector tests failed!${NC}"
    exit 1
fi

print_test_header "Encryption Manager" "Tests secure key generation, contact key management, public/private key encryption, and password-protected message functionality."
python -m unittest tests.test_encryption_manager
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Encryption Manager tests passed!${NC}"
else
    echo -e "${RED}✗ Encryption Manager tests failed!${NC}"
    exit 1
fi

echo -e "\n${GREEN}All tests passed successfully!${NC}"
echo -e "${YELLOW}------------------------------------${NC}"
echo -e "${CYAN}Security Components Status:${NC}"
echo -e "  ${GREEN}✓${NC} Attachment Scanner: Ready for use"
echo -e "  ${GREEN}✓${NC} Phishing Detector: Ready for use"
echo -e "  ${GREEN}✓${NC} Encryption Manager: Ready for use"
echo -e "${YELLOW}------------------------------------${NC}"
