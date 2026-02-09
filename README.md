
# Encrypted File Management Utility
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)


This repository provides a utility script intended for educational purposes and authorized security testing within controlled environments. It demonstrates file encryption techniques using Python's cryptography library, along with system interaction via ctypes on Windows platforms.

**Disclaimer:** This software is for educational use only. Unauthorized use of this software on computer systems or networks without explicit permission is illegal and unethical. The author assumes no responsibility for misuse or damage caused by this software.

## Features

-   **File Encryption:** Encrypts files in specified directories (Documents, Downloads, Desktop) using AES-256 in CBC mode.
    
-   **Unique IVs:** Generates a unique Initialization Vector (IV) for each file encryption operation.
    
-   **Asymmetric Key Protection:** Secures the symmetric AES key using RSA public key encryption (OAEP padding with SHA-256).
    
-   **System API Integration:** Utilizes Windows API calls directly via `ctypes` for file system operations, registry modification, and secure random number generation.
    
-   **Persistence Mechanism:** Demonstrates a method for adding a startup entry for the executable.
    
-   **Anti-Analysis (Basic):** Includes a sleep timer to delay execution, a common technique in malware analysis evasion (for educational demonstration).
    

## Prerequisites

-   **Operating System:** Windows (due to specific WinAPI calls).
    
-   **Python:** Python 3.x installed.
    
-   **Libraries:**
    
    -   `cryptography`: `pip install cryptography`
        

## Installation

1.  **Clone the Repository:**
   
    ```
    git clone https://github.com/yourusername/your-repo-name.git
    cd your-repo-name   
    ```
    
2.  **Install Dependencies:**
    
    ```
    pip install cryptography  
    ```
    

## Usage

1.  **Review the Code:** Examine `RANSOMWARE.py` to understand its functionality. Note the RSA public key embedded in the script. You would typically generate your own key pair for a real deployment scenario.
    
2.  **Run the Script:**
    
    **WARNING:** executing this script will encrypt files in your Documents, Downloads, and Desktop folders. **Run this ONLY in a safe, isolated virtual machine.**
    
   
    
    ```
    python RANSOMWARE.py  
    ```
    

## Technical Details

### Cryptography

The script uses a hybrid encryption scheme:

1.  **Symmetric Encryption (AES-256-CBC):** A random 32-byte key is generated for the session. Each file is encrypted with this key and a unique 16-byte IV.
    
2.  **Asymmetric Encryption (RSA-2048):** The session AES key is encrypted using an embedded RSA public key. The encrypted key is then prepended to every encrypted file.
    

### Windows API Usage

The script interacts with the Windows OS through `ctypes`:

-   `kernel32.dll`, `advapi32.dll`, `shell32.dll`, `shlwapi.dll` are loaded.
    
-   Functions like `FindFirstFileW`, `GetFileAttributesW`, `CryptGenRandom`, `RegSetValueExW` are manually defined and called.
    
-   This approach bypasses some high-level Python wrappers, offering a lower-level interaction demonstration.
    

### Persistence

The script attempts to copy itself to the Windows Startup folder to ensure execution on subsequent logins. This is achieved by resolving the `APPDATA` environment variable and constructing the path dynamically.

## Contributing

Contributions are welcome for educational improvements or security analysis features. Please ensure all pull requests adhere to ethical guidelines.

## License

[MIT License](https://www.google.com/search?q=LICENSE) - Please use responsibly.
