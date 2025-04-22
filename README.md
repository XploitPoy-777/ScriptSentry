# 🔍 JS Security Scanner

**A comprehensive static analysis tool for detecting secrets, sensitive endpoints, and vulnerabilities in JavaScript files**

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Features

- 🕵️ **Secret Detection**: 800+ patterns for API keys, tokens, credentials, and sensitive data
- 🌐 **Endpoint Discovery**: Identify API routes, auth endpoints, and admin interfaces
- 🔑 **Hardcoded Secrets**: Find passwords, private keys, and credentials in code
- 💳 **Payment Info**: Detect credit card numbers and payment processing endpoints
- ☁️ **Cloud Credentials**: AWS, Azure, GCP, and other cloud service keys
- 📊 **Smart Filtering**: Skip common libraries to reduce false positives
- 🚀 **Multi-threaded**: Fast scanning with configurable thread count
- 📝 **Multiple Outputs**: Color-coded console output or JSON format

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/js-security-scanner.git
cd js-security-scanner

# Install dependencies
pip install -r requirements.txt
