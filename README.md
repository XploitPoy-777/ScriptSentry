# ScriptSentry - JavaScript Security Scanner

## Description

ScriptSentry is a powerful and comprehensive JavaScript security scanner designed to detect security vulnerabilities, exposed secrets, and sensitive information in JavaScript files. It automatically crawls websites to find JavaScript files and analyzes them for various security issues including hardcoded credentials, API keys, database connection strings, and other sensitive data that could pose security risks.

The tool is particularly useful for security researchers, penetration testers, and developers who want to identify potential security weaknesses in web applications by analyzing their client-side JavaScript code.

## Features

### 🔍 **Comprehensive Secret Detection**
- **API Keys & Tokens**: Detects various API keys (AWS, Google, Stripe, etc.)
- **Database Credentials**: Identifies database connection strings and credentials
- **Payment Information**: Finds payment-related secrets and credit card patterns
- **Authentication Tokens**: Discovers JWT tokens, OAuth secrets, and session tokens
- **Cloud Service Credentials**: Detects credentials for AWS, Azure, GCP, and other cloud providers

### 🌐 **Smart JavaScript Discovery**
- **Automatic JS File Discovery**: Crawls websites to find JavaScript files
- **Common Path Detection**: Searches in typical JS file locations
- **Direct JS File Support**: Can scan individual JavaScript files directly

### 🛡️ **Security Analysis**
- **Endpoint Discovery**: Identifies API endpoints and internal URLs
- **Sensitive Function Detection**: Finds functions that handle sensitive operations
- **Hidden Functionality**: Uncovers obfuscated or hidden code patterns
- **Hardcoded Credentials**: Detects credentials stored in variables or constants

### ⚡ **Performance & Usability**
- **Multi-threaded Scanning**: Configurable thread count for faster scanning
- **Color-coded Output**: Severity-based color coding for easy identification
- **Multiple Output Formats**: Text and JSON output options
- **Severity Filtering**: Filter results by minimum severity level
- **Verbose Mode**: Detailed logging for debugging and analysis

### 📊 **Reporting**
- **Structured Reports**: Organized findings by category and severity
- **Context Information**: Provides surrounding code context for findings
- **Source Tracking**: Links findings to specific JavaScript files
- **Severity Classification**: Critical, High, Medium, and Low severity levels

## Tools Required

- **Python 3.6+**: Core runtime environment
- **requests**: HTTP library for web requests
- **argparse**: Command-line argument parsing
- **concurrent.futures**: Multi-threading support
- **re**: Regular expression support
- **json**: JSON processing
- **urllib.parse**: URL parsing and manipulation
- **collections**: Data structure utilities

## Installation Instructions

### Prerequisites
- Python 3.6 or higher
- pip (Python package manager)

### Step-by-Step Installation

1. **Clone or Download the Repository**
   ```bash
   # If using git
   git clone <repository-url>
   cd ScriptSentry-main
   
   # Or download and extract the ZIP file
   ```

2. **Install Required Dependencies**
   ```bash
   pip install requests
   ```

3. **Verify Installation**
   ```bash
   python jsurpdat.py --help
   ```

### Alternative Installation Methods

**Using pip (if available as a package):**
```bash
pip install scriptsentry
```

**Manual Installation:**
```bash
# Download the script
wget https://raw.githubusercontent.com/username/ScriptSentry/main/jsurpdat.py

# Make it executable (Linux/Mac)
chmod +x jsurpdat.py
```

## Usage Instructions

### Basic Usage

**Scan a single website:**
```bash
python jsurpdat.py -u https://example.com
```

**Scan a specific JavaScript file:**
```bash
python jsurpdat.py -u https://example.com/static/js/app.js
```

**Scan multiple URLs from a file:**
```bash
python jsurpdat.py -l urls.txt
```

### Advanced Options

**Verbose output with custom thread count:**
```bash
python jsurpdat.py -u https://example.com -v -t 10
```

**Generate JSON output:**
```bash
python jsurpdat.py -u https://example.com -o json
```

**Filter by minimum severity:**
```bash
python jsurpdat.py -u https://example.com --min-severity high
```

**Complete example with all options:**
```bash
python jsurpdat.py -u https://example.com -v -t 8 -o json --min-severity medium
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-u, --url` | Single URL to scan | None |
| `-l, --list` | File containing list of URLs | None |
| `-v, --verbose` | Enable verbose output | False |
| `-t, --threads` | Number of threads for scanning | 5 |
| `-o, --output` | Output format (text/json) | text |
| `--min-severity` | Minimum severity level (critical/high/medium/low) | low |

## Output Files

### Console Output
The tool provides real-time console output with:
- **Color-coded severity levels**: Critical (red bold), High (red), Medium (yellow), Low (blue)
- **Progress indicators**: Shows scanning progress and discovered files
- **Error messages**: Displays connection errors and timeouts

### JSON Output Format
When using `-o json`, the tool generates structured JSON output:
```json
{
  "secrets": [
    {
      "type": "API Key",
      "key": "api_key",
      "value": "sk_live_1234567890abcdef...",
      "storage": "variable",
      "source": "https://example.com/js/app.js",
      "severity": "critical",
      "found": "api_key: \"sk_live_1234567890abcdef\"",
      "context": "const config = { api_key: \"sk_live_1234567890abcdef\" };"
    }
  ],
  "endpoints": [...],
  "sensitive_functions": [...],
  "hardcoded_credentials": [...]
}
```

### Text Output Format
Default text output includes:
- **Category headers**: Organized by finding type
- **Severity indicators**: Clear severity level display
- **Context information**: Surrounding code for each finding
- **Source tracking**: File location for each finding

## Example

### Sample Scan Output
```bash
$ python jsurpdat.py -u https://example.com -v

Color Legend:
Critical
High
Medium
Low

[+] Scanning: https://example.com
[*] Analyzing: https://example.com/static/js/app.js
[*] Analyzing: https://example.com/static/js/vendor.js

=== SECRETS ===

[CRITICAL] API Key
- Location: https://example.com/static/js/app.js
- Value: sk_live_1234567890abcdef...
- Found: api_key: "sk_live_1234567890abcdef"
- Context: const config = { api_key: "sk_live_1234567890abcdef" };
- Storage: variable

[HIGH] Database Connection String
- Location: https://example.com/static/js/config.js
- Value: mongodb://user:pass@localhost:27017/db
- Found: db_url: "mongodb://user:pass@localhost:27017/db"
- Context: const db_url = "mongodb://user:pass@localhost:27017/db";
- Storage: variable

=== ENDPOINTS ===

[MEDIUM] Internal API Endpoint
- Location: https://example.com/static/js/api.js
- Value: /api/internal/users
- Found: fetch('/api/internal/users')
- Context: const response = await fetch('/api/internal/users');
```

### Sample URLs File (urls.txt)
```
https://example1.com
https://example2.com
https://example3.com/static/js/app.js
https://api.example.com
```

## Dependencies

### Core Dependencies
- **Python 3.6+**: Required for modern Python features and syntax
- **requests**: HTTP library for making web requests
  ```bash
  pip install requests
  ```

### Optional Dependencies
- **colorama**: For better color support on Windows (auto-detected)
- **urllib3**: For advanced HTTP features (included with requests)

### System Requirements
- **Operating System**: Windows, macOS, or Linux
- **Memory**: Minimum 512MB RAM (recommended 1GB+)
- **Network**: Internet connection for scanning external websites
- **Storage**: Minimal disk space (script is ~50KB)

## Reminder

### ⚠️ **Important Security Notes**

1. **Legal Compliance**: Only scan websites you own or have explicit permission to test
2. **Rate Limiting**: Be respectful of target servers and avoid overwhelming them
3. **Data Handling**: Treat discovered secrets as sensitive information
4. **Reporting**: Report findings responsibly to the appropriate parties

### 🔧 **Best Practices**

1. **Start with Low Thread Count**: Begin with default 5 threads to avoid overwhelming servers
2. **Use Verbose Mode**: Enable verbose output for detailed analysis
3. **Filter Results**: Use severity filtering to focus on important findings
4. **Save Output**: Redirect output to files for later analysis
   ```bash
   python jsurpdat.py -u https://example.com -o json > results.json
   ```

### 🚀 **Performance Tips**

1. **Adjust Thread Count**: Increase threads for faster scanning on robust targets
2. **Use Direct JS URLs**: Scan specific JS files for targeted analysis
3. **Batch Processing**: Use URL lists for scanning multiple targets
4. **Output Format**: Use JSON for programmatic processing of results

### 📝 **Troubleshooting**

- **Connection Errors**: Check network connectivity and target availability
- **Timeout Issues**: Increase timeout values or reduce thread count
- **Permission Errors**: Ensure proper file permissions for output files
- **Color Display**: Colors may not display in some terminals or when redirecting output

---

**ScriptSentry** - Your JavaScript Security Guardian 🛡️ 
