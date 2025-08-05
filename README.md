# 🔐 Password Generator 

![Python](https://img.shields.io/badge/Python-3.6+-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-green)
![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey)
![Security](https://img.shields.io/badge/Security-Cryptographically%20Secure-green)

**Created by [Soumit Santra] — Advanced Security Tools**  
© 2025 Soumit Santra. All rights reserved.

---

A comprehensive, cryptographically secure password generator with advanced features including configurable settings, history management, TOTP support, and encrypted vault storage.

---

## ⚠️ Security Notice

> **This tool generates cryptographically secure passwords using Python's `secrets` module.**
>
> - **All passwords are generated using secure random sources.**
> - **History is stored locally and can be encrypted.**
> - **Clipboard auto-clear prevents password exposure.**
> - **Memory is securely cleared after use.**

**Security Features:**
- Uses cryptographically secure random number generation
- AES-256-GCM encryption for password vault
- Secure memory handling with automatic cleanup
- PBKDF2 key derivation for vault encryption
- Password strength analysis with crack time estimates

---

## ✨ Features

- **Multiple Generation Types:**
  - Cryptographically secure passwords
  - Diceware-style passphrases
  - TOTP/2FA codes
  - Custom character sets
  - Configurable minimum requirements

- **Advanced Capabilities:**
  - **History Management:** Track, filter, and delete password history
  - **Strength Analysis:** Comprehensive password evaluation with zxcvbn
  - **Encrypted Vault:** AES-256-GCM encrypted password storage
  - **Clipboard Integration:** Auto-copy with timed clearing
  - **Interactive Mode:** Full-featured CLI experience
  - **Configurable Settings:** Persistent configuration management
  - **Multi-platform Support:** Windows, Linux, macOS
  - **Auto-dependency Installation:** Installs required packages automatically

- **History Management:**
  - Delete entries by ID, type, age, or strength score
  - Detailed statistics and analytics
  - Export capabilities
  - Configurable retention policies

- **Security Analysis:**
  - Entropy calculation
  - Pattern detection (sequential, repeating, keyboard patterns)
  - Crack time estimates
  - Character composition analysis
  - Strength scoring (0-100)

---

## 🛠️ Requirements

- Python **3.6+**
- The script will auto-install if missing:
  - `colorama` (colored output)
  - `pyperclip` (clipboard operations)
  - `pyotp` (TOTP generation)
  - `zxcvbn` (password strength analysis)
  - `cryptography` (encryption)
  - `requests` (wordlist download)

---

## 💻 Installation

### 🪟 Windows

1. Clone or download the repository.
2. Open Command Prompt or PowerShell and navigate to the project directory.
3. Run:
   ```cmd
   python password_generator.py
   ```
   > The script will install any missing dependencies automatically.

### 🐧 Linux / 🍎 macOS

1. Clone or download the repository.
2. Open a terminal and navigate to the project directory.
3. Ensure Python 3.6+ is installed:
   ```bash
   python3 --version
   ```
4. Run:
   ```bash
   python3 password_generator.py
   ```
   > The script will install any missing dependencies automatically.

---

## 🚦 Usage

### Interactive Mode (Recommended)

Simply run the script without arguments for the full interactive experience:

```bash
python password_generator.py
```

**Interactive Menu Options:**
```
1. 🔐 Generate Password
2. 📝 Generate Passphrase
3. 🔢 Generate TOTP Code
4. 📊 View Generation History
5. 🗑️  Manage History
6. 📈 Show Statistics
7. 🧪 Password Strength Test
8. ⚙️  Settings
9. ❌ Exit
```

### Command Line Interface

```bash
# Generate a 20-character password and copy to clipboard
python password_generator.py -l 20 --copy

# Generate a 5-word passphrase
python password_generator.py -t passphrase -w 5

# Generate TOTP code
python password_generator.py -t totp --secret YOUR_SECRET_KEY

# Test password strength
python password_generator.py --test

# View generation history
python password_generator.py --history

# Show detailed statistics
python password_generator.py --stats

# Configure settings
python password_generator.py --set-default-length 24 --save-settings
```

---

## 🛠️ Advanced Features

### Password Generation Options

```bash
# Custom password with specific requirements
python password_generator.py -l 16 --min-upper 2 --min-digits 3 --exclude-similar

# Multiple passwords
python password_generator.py -n 5 -l 12

# No symbols, exclude ambiguous characters
python password_generator.py --no-symbols --exclude-ambiguous
```

### Passphrase Options

```bash
# Capitalized words with number and symbol
python password_generator.py -t passphrase --capitalize --add-number --add-symbol

# Custom separator
python password_generator.py -t passphrase -s "_" -w 6
```

### History Management

```bash
# Delete weak passwords from history
python password_generator.py --delete-weak-history

# Delete entries older than 30 days
python password_generator.py --delete-history-older-than 30

# Delete all passwords (keeps passphrases)
python password_generator.py --delete-history-by-type password

# Clear all history (with confirmation)
python password_generator.py --clear-history
```

### Settings Configuration

```bash
# Change default password length
python password_generator.py --set-default-length 20

# Set clipboard clear time to 60 seconds
python password_generator.py --set-clipboard-time 60

# Set minimum character requirements
python password_generator.py --set-min-upper 2 --set-min-symbols 2

# Show current settings
python password_generator.py --show-settings
```

---

## 📁 Configuration Files

The tool creates several files in your home directory:

- `~/.password_generator_config.ini` - Configuration settings
- `~/.password_history.json` - Generation history
- `~/password_vault.enc` - Encrypted password vault (when used)
- `~/wordlist.txt` - Cached wordlist for passphrases
- `password_generator.log` - Application logs

---

## 🔧 Configuration Options

All settings can be customized via command line or interactive mode:

| Setting | Default | Description |
|---------|---------|-------------|
| Default Password Length | 16 | Default length for generated passwords |
| Default Passphrase Words | 4 | Default number of words in passphrases |
| Clipboard Clear Time | 30s | Time before clipboard is cleared |
| Max History Size | 50 | Maximum number of history entries |
| Minimum Character Requirements | 1 each | Minimum uppercase, lowercase, digits, symbols |
| Word Length Range | 3-8 | Length range for passphrase words |
| Log Level | INFO | Logging verbosity level |

---

## 📊 Password Strength Analysis

The tool provides comprehensive password analysis including:

- **Strength Rating:** Excellent, Very Strong, Strong, Moderate, Weak, Very Weak
- **Entropy Calculation:** Bits of entropy based on character set
- **Pattern Detection:** Sequential, repeating, keyboard patterns
- **Crack Time Estimates:** Time to crack with various attack methods
- **Character Composition:** Breakdown of character types used
- **zxcvbn Integration:** Advanced password strength estimation

---

## 🔐 Security Features

### Cryptographic Security
- Uses Python's `secrets` module for cryptographically secure random generation
- AES-256-GCM encryption for vault storage
- PBKDF2 key derivation with 100,000 iterations
- Secure memory clearing for sensitive data

### Privacy Protection
- Passwords never logged or stored in plain text
- Automatic clipboard clearing
- Secure deletion of sensitive variables
- Local-only storage (no cloud/network transmission)

---

## 📋 Example Output

```
🔐 PASSWORD ANALYSIS
============================================================
Password: X8#mP2$nQ7@kL9!v
Length: 16 characters
Strength: Excellent (94.5/100)
Entropy: 84.32 bits

📊 Character Composition:
  Types: Uppercase, Lowercase, Digits, Symbols
  Character set size: 94

⏱️  Estimated Crack Times:
  Online throttled: centuries
  Online unthrottled: 4 years
  Offline slow: 6 months
  Offline fast: 3 days
============================================================
```

---

## 🗂️ History Management

Track and manage all generated passwords:

```
📜 Recent History Entries:
--------------------------------------------------------------------------------
ID:   1699123456789 |   Password | Length: 16 | Strength:  94.5 | 2024-11-04 15:30
ID:   1699123456790 | Passphrase | Length: 23 | Strength:  87.2 | 2024-11-04 15:31
ID:   1699123456791 |   Password | Length: 12 | Strength:  78.9 | 2024-11-04 15:32
```

**Management Options:**
- Delete by ID, type, age, or strength score
- View detailed statistics
- Export history data
- Bulk operations for cleanup

---

## 📝 Command Reference

### Generation Commands
```bash
-t, --type {password,passphrase,totp}  # Type of secret to generate
-l, --length LENGTH                    # Password length
-w, --words WORDS                      # Number of passphrase words
-n, --count COUNT                      # Number of items to generate
--copy                                 # Copy to clipboard
--hide                                 # Hide output
```

### Password Options
```bash
--no-upper                             # Exclude uppercase
--no-lower                             # Exclude lowercase  
--no-digits                            # Exclude digits
--no-symbols                           # Exclude symbols
--exclude-similar                      # Exclude I,l,1,O,0
--exclude-ambiguous                    # Exclude ambiguous symbols
--min-upper N                          # Minimum uppercase chars
--min-lower N                          # Minimum lowercase chars
--min-digits N                         # Minimum digit chars
--min-symbols N                        # Minimum symbol chars
```

### History Commands
```bash
--history                              # Show generation history
--stats                                # Show detailed statistics
--delete-history-entry ID              # Delete specific entry
--delete-history-by-type TYPE          # Delete by type
--delete-history-older-than DAYS       # Delete old entries
--delete-weak-history                  # Delete weak entries
--clear-history                        # Clear all history
```

### Settings Commands
```bash
--show-settings                        # Display current settings
--save-settings                        # Save settings to file
--set-default-length N                 # Set default password length
--set-clipboard-time SECONDS           # Set clipboard clear time
--set-history-size N                   # Set max history size
```

---

## 🚨 Error Handling

The tool includes comprehensive error handling:

- **Dependency Installation:** Auto-installs missing packages
- **Network Issues:** Graceful fallback for wordlist download
- **File Permissions:** Clear error messages for file access issues
- **Invalid Input:** Input validation with helpful error messages
- **Interrupted Operations:** Clean shutdown on Ctrl+C

---

## 🔄 Logging

All operations are logged to `password_generator.log`:

```
2024-11-04 15:30:15,123 - INFO - Password generated successfully
2024-11-04 15:30:16,456 - INFO - Added password to history with ID: 1699123456789
2024-11-04 15:30:20,789 - INFO - Clipboard cleared after 30 seconds
```

Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

**Areas for contribution:**
- Additional character sets
- New password strength algorithms
- Export format options
- GUI interface
- Additional encryption methods

---

## 📄 License

This project is open-source software licensed under the **MIT License**.

---

## 📧 Contact

**[Soumit Santra]**  
For questions, suggestions, or collaboration opportunities.

---

## 🚀 Future Enhancements

- **Web Interface:** Browser-based GUI
- **API Mode:** RESTful API for integration
- **Password Policies:** Organizational policy enforcement
- **Cloud Sync:** Encrypted cloud synchronization
- **Mobile App:** Companion mobile application
- **Browser Extension:** Direct browser integration
- **Team Features:** Shared password generation policies

---

*Remember: Strong passwords are your first line of defense. Use this tool to create unique, secure passwords for all your accounts.*
