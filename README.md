# 🛡️ Advanced File Type Identifier & Malware Hint Scanner

A lightweight, powerful static analysis tool written in Python to detect **Extension Spoofing** and cross-reference files using digital fingerprints (SHA-256).

## 🚀 Key Features
* **🔍 Magic Byte Validation:** Inspects raw binary headers to determine true identity, ignoring deceptive extensions.
* **🧬 Cryptographic Hashing:** Generates unique **SHA-256** digital fingerprints using memory-efficient chunk reading.
* **🌐 VirusTotal Integration:** Communicates with the VirusTotal API via secure hashes to scan files across 60+ antivirus engines.
* **📁 Directory Batch Scanning:** Recursively traverses through folders to audit file systems.

## 📦 Installation & Setup
1. Clone this repository or download the files.
2. Install dependencies:
   ```bash
   pip install requests