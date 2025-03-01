#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Running Mail-Warden Test Suite${NC}"
echo "===================================="

# Run tests for attachment scanner
echo -e "\n${BLUE}Testing Attachment Scanner...${NC}"
python -m unittest tests.test_attachment_scanner
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Attachment Scanner tests passed!${NC}"
else
    echo -e "${RED}Attachment Scanner tests failed!${NC}"
    exit 1
fi

# Run tests for phishing detector
echo -e "\n${BLUE}Testing Phishing Detector...${NC}"
python -m unittest tests.test_phishing_detector
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Phishing Detector tests passed!${NC}"
else
    echo -e "${RED}Phishing Detector tests failed!${NC}"
    exit 1
fi

# Run tests for encryption manager
echo -e "\n${BLUE}Testing Encryption Manager...${NC}"
python -m unittest tests.test_encryption_manager
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Encryption Manager tests passed!${NC}"
else
    echo -e "${RED}Encryption Manager tests failed!${NC}"
    exit 1
fi

echo -e "\n${GREEN}All tests passed successfully!${NC}"
echo "===================================="
