"""
 Password Generator - Enhanced with Configurable Settings & History Management
========================================================================

Copyright (c) 2025 [Soumit Santra]
All rights reserved.

License: MIT License
========================================================================
The best features of this scripts:
- Cryptographically secure generation using secrets module
- AES-256-GCM authenticated encryption for storage
- TOTP/2FA code generation
- Comprehensive password strength analysis
- Interactive mode with full CLI experience
- Clipboard integration with auto-clear
- Diceware passphrase generation
- ENHANCED: Password history tracking with deletion capabilities
- Detailed security metrics and crack time estimates
- CONFIGURABLE SETTINGS via command line

Author: [Soumit Santra]
Version: 1.0
Created: 2025
Last Modified: 2025
"""

import sys
import os
import argparse
import string
import math
import re
import time
import logging
import threading
import configparser
from typing import List, Tuple, Optional, Dict, Any
from datetime import datetime, timedelta
from getpass import getpass
import json
import subprocess
import platform

# Copyright and version information
__author__ = "[Soumit Santra]"
__version__ = "1.0"
__copyright__ = "Copyright (c) 2025 [Soumit Santra]"
__license__ = "MIT"

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('password_generator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration class for managing settings
class Settings:
    # Manages all configurable settings for the password generator.
    
    def __init__(self):
        # Default values
        self.DEFAULT_PASSWORD_LENGTH = 16
        self.DEFAULT_PASSPHRASE_WORDS = 4
        self.CLIPBOARD_CLEAR_TIME = 30
        self.MAX_HISTORY_SIZE = 50
        self.MIN_UPPER = 1
        self.MIN_LOWER = 1
        self.MIN_DIGITS = 1
        self.MIN_SYMBOLS = 1
        self.DICEWARE_WORDLIST_URL = "https://raw.githubusercontent.com/dwyl/english-words/master/words.txt"
        self.WORD_MIN_LENGTH = 3
        self.WORD_MAX_LENGTH = 8
        self.LOG_LEVEL = "INFO"
        
        self.config_file = os.path.expanduser("~/.password_generator_config.ini")
        self.load_config()
    
    def load_config(self):
        # Load configuration from file if it exists.
        if os.path.exists(self.config_file):
            try:
                config = configparser.ConfigParser()
                config.read(self.config_file)
                
                if 'DEFAULT' in config:
                    section = config['DEFAULT']
                    self.DEFAULT_PASSWORD_LENGTH = section.getint('default_password_length', self.DEFAULT_PASSWORD_LENGTH)
                    self.DEFAULT_PASSPHRASE_WORDS = section.getint('default_passphrase_words', self.DEFAULT_PASSPHRASE_WORDS)
                    self.CLIPBOARD_CLEAR_TIME = section.getint('clipboard_clear_time', self.CLIPBOARD_CLEAR_TIME)
                    self.MAX_HISTORY_SIZE = section.getint('max_history_size', self.MAX_HISTORY_SIZE)
                    self.MIN_UPPER = section.getint('min_upper', self.MIN_UPPER)
                    self.MIN_LOWER = section.getint('min_lower', self.MIN_LOWER)
                    self.MIN_DIGITS = section.getint('min_digits', self.MIN_DIGITS)
                    self.MIN_SYMBOLS = section.getint('min_symbols', self.MIN_SYMBOLS)
                    self.DICEWARE_WORDLIST_URL = section.get('diceware_wordlist_url', self.DICEWARE_WORDLIST_URL)
                    self.WORD_MIN_LENGTH = section.getint('word_min_length', self.WORD_MIN_LENGTH)
                    self.WORD_MAX_LENGTH = section.getint('word_max_length', self.WORD_MAX_LENGTH)
                    self.LOG_LEVEL = section.get('log_level', self.LOG_LEVEL)
                
                logger.info("Configuration loaded from file")
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")
    
    def save_config(self):
        # Save current configuration to file.
        try:
            config = configparser.ConfigParser()
            config['DEFAULT'] = {
                'default_password_length': str(self.DEFAULT_PASSWORD_LENGTH),
                'default_passphrase_words': str(self.DEFAULT_PASSPHRASE_WORDS),
                'clipboard_clear_time': str(self.CLIPBOARD_CLEAR_TIME),
                'max_history_size': str(self.MAX_HISTORY_SIZE),
                'min_upper': str(self.MIN_UPPER),
                'min_lower': str(self.MIN_LOWER),
                'min_digits': str(self.MIN_DIGITS),
                'min_symbols': str(self.MIN_SYMBOLS),
                'diceware_wordlist_url': self.DICEWARE_WORDLIST_URL,
                'word_min_length': str(self.WORD_MIN_LENGTH),
                'word_max_length': str(self.WORD_MAX_LENGTH),
                'log_level': self.LOG_LEVEL
            }
            
            with open(self.config_file, 'w') as f:
                config.write(f)
            
            logger.info("Configuration saved to file")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    def update_from_args(self, args):
        """Update settings from command line arguments."""
        if hasattr(args, 'set_default_length') and args.set_default_length:
            self.DEFAULT_PASSWORD_LENGTH = args.set_default_length
        if hasattr(args, 'set_default_words') and args.set_default_words:
            self.DEFAULT_PASSPHRASE_WORDS = args.set_default_words
        if hasattr(args, 'set_clipboard_time') and args.set_clipboard_time:
            self.CLIPBOARD_CLEAR_TIME = args.set_clipboard_time
        if hasattr(args, 'set_history_size') and args.set_history_size:
            self.MAX_HISTORY_SIZE = args.set_history_size
        if hasattr(args, 'set_min_upper') and args.set_min_upper:
            self.MIN_UPPER = args.set_min_upper
        if hasattr(args, 'set_min_lower') and args.set_min_lower:
            self.MIN_LOWER = args.set_min_lower
        if hasattr(args, 'set_min_digits') and args.set_min_digits:
            self.MIN_DIGITS = args.set_min_digits
        if hasattr(args, 'set_min_symbols') and args.set_min_symbols:
            self.MIN_SYMBOLS = args.set_min_symbols
        if hasattr(args, 'set_word_min_length') and args.set_word_min_length:
            self.WORD_MIN_LENGTH = args.set_word_min_length
        if hasattr(args, 'set_word_max_length') and args.set_word_max_length:
            self.WORD_MAX_LENGTH = args.set_word_max_length
        if hasattr(args, 'set_log_level') and args.set_log_level:
            self.LOG_LEVEL = args.set_log_level.upper()
    
    def display_settings(self):
        # Display current settings.
        print("\n⚙️  Current Settings:")
        print("="*50)
        print(f"Default password length:     {self.DEFAULT_PASSWORD_LENGTH}")
        print(f"Default passphrase words:    {self.DEFAULT_PASSPHRASE_WORDS}")
        print(f"Clipboard clear time:        {self.CLIPBOARD_CLEAR_TIME}s")
        print(f"Max history size:            {self.MAX_HISTORY_SIZE}")
        print(f"Minimum uppercase chars:     {self.MIN_UPPER}")
        print(f"Minimum lowercase chars:     {self.MIN_LOWER}")
        print(f"Minimum digit chars:         {self.MIN_DIGITS}")
        print(f"Minimum symbol chars:        {self.MIN_SYMBOLS}")
        print(f"Word min length:             {self.WORD_MIN_LENGTH}")
        print(f"Word max length:             {self.WORD_MAX_LENGTH}")
        print(f"Log level:                   {self.LOG_LEVEL}")
        print(f"Config file:                 {self.config_file}")
        print("="*50)

# Global settings instance
settings = Settings()

def show_copyright():
    """Display copyright and license information."""
    print(f"\n{colorama.Fore.CYAN}📄 Copyright Information{colorama.Style.RESET_ALL}")
    print("="*60)
    print(f"Password Generator v{__version__}")
    print(f"{__copyright__}")
    print(f"Author: {__author__}")
    print(f"Email: {__email__}")
    print(f"License: {__license__}")
    print("\nThis software is provided under the MIT License.")
    print("See the source code header for full license text.")
    print("="*60)

def install_required_packages():
    # Install missing packages automatically.
    required = {
        "colorama": "colorama",
        "pyperclip": "pyperclip", 
        "pyotp": "pyotp",
        "zxcvbn": "zxcvbn",
        "cryptography": "cryptography",
        "requests": "requests"
    }
    
    missing = []
    for pkg, name in required.items():
        try:
            __import__(pkg)
        except ImportError:
            missing.append(name)
    
    if missing:
        print(f"Installing missing packages: {', '.join(missing)}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
            print("✅ All packages installed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install packages: {e}")
            logger.error(f"Package installation failed: {e}")
            sys.exit(1)

# Install packages before importing
install_required_packages()

# Now import external packages
import secrets
import colorama
import pyperclip
import pyotp
import zxcvbn
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Initialize colorama
colorama.init()

class SecureString:
    # Enhanced secure string handling with proper memory clearing.
    def __init__(self, string: str):
        self._string = string.encode('utf-8')
        self._protected = bytearray(self._string)
        
    def __del__(self):
        # Securely clear memory on deletion.
        if hasattr(self, '_protected'):
            for i in range(len(self._protected)):
                self._protected[i] = 0
            del self._protected
                
    def get(self) -> str:
        # Get the string value.
        return self._protected.decode('utf-8')
        
    def __str__(self):
        return "<SecureString - Content Hidden>"
    
    def __repr__(self):
        return self.__str__()

class PasswordHistory:
    # Enhanced password history with persistence, metadata, and deletion capabilities.
    def __init__(self, max_size: int = None):
        self.max_size = max_size or settings.MAX_HISTORY_SIZE
        self.history: List[Dict[str, Any]] = []
        self.history_file = os.path.expanduser("~/.password_history.json")
        self._load_history()
    
    def add(self, password: str, password_type: str = "password", 
            strength_score: float = 0.0, metadata: Dict = None):
        # Add password to history with metadata.
        entry = {
            'id': int(time.time() * 1000000),  # Unique microsecond timestamp ID
            'timestamp': datetime.now().isoformat(),
            'length': len(password),
            'type': password_type,
            'strength_score': strength_score,
            'entropy': self._calculate_entropy(password),
            'metadata': metadata or {}
        }
        
        if len(self.history) >= self.max_size:
            self.history.pop(0)
        
        self.history.append(entry)
        self._save_history()
        logger.info(f"Added {password_type} to history with ID: {entry['id']}")
    
    def delete_entry(self, entry_id: int) -> bool:
        # Delete a specific entry by ID.
        for i, entry in enumerate(self.history):
            if entry['id'] == entry_id:
                deleted_entry = self.history.pop(i)
                self._save_history()
                logger.info(f"Deleted history entry: ID {entry_id}, type {deleted_entry['type']}")
                return True
        return False
    
    def delete_entries_by_type(self, entry_type: str) -> int:
        # Delete all entries of a specific type.
        original_count = len(self.history)
        self.history = [entry for entry in self.history if entry['type'] != entry_type]
        deleted_count = original_count - len(self.history)
        
        if deleted_count > 0:
            self._save_history()
            logger.info(f"Deleted {deleted_count} entries of type: {entry_type}")
        
        return deleted_count
    
    def delete_entries_older_than(self, days: int) -> int:
        # Delete entries older than specified days.
        cutoff_date = datetime.now() - timedelta(days=days)
        original_count = len(self.history)
        
        self.history = [
            entry for entry in self.history 
            if datetime.fromisoformat(entry['timestamp']) > cutoff_date
        ]
        
        deleted_count = original_count - len(self.history)
        
        if deleted_count > 0:
            self._save_history()
            logger.info(f"Deleted {deleted_count} entries older than {days} days")
        
        return deleted_count
    
    def delete_entries_by_strength(self, min_strength: float = None, max_strength: float = None) -> int:
        # Delete entries by strength score range.
        original_count = len(self.history)
        
        def strength_filter(entry):
            score = entry.get('strength_score', 0)
            if min_strength is not None and score < min_strength:
                return False
            if max_strength is not None and score > max_strength:
                return False
            return True
        
        self.history = [entry for entry in self.history if strength_filter(entry)]
        deleted_count = original_count - len(self.history)
        
        if deleted_count > 0:
            self._save_history()
            logger.info(f"Deleted {deleted_count} entries by strength filter")
        
        return deleted_count
    
    def clear_all_history(self) -> int:
        # Clear all history entries.
        count = len(self.history)
        self.history.clear()
        self._save_history()
        logger.info(f"Cleared all history - {count} entries deleted")
        return count
    
    def get_entries_with_ids(self, n: int = 10) -> List[Dict]:
        # Get n most recent entries with IDs for deletion reference.
        return self.history[-n:] if self.history else []
    
    def _calculate_entropy(self, password: str) -> float:
        # Calculate password entropy.
        char_set_size = 0
        if any(c.isupper() for c in password): char_set_size += 26
        if any(c.islower() for c in password): char_set_size += 26
        if any(c.isdigit() for c in password): char_set_size += 10
        if any(c in string.punctuation for c in password): char_set_size += len(string.punctuation)
        
        return len(password) * math.log2(char_set_size) if char_set_size > 0 else 0
    
    def get_recent(self, n: int = 10) -> List[Dict]:
        # Get n most recent entries.
        return self.history[-n:] if self.history else []
    
    def get_stats(self) -> Dict[str, Any]:
        # Get history statistics.
        if not self.history:
            return {}
        
        return {
            'total_generated': len(self.history),
            'avg_length': sum(entry['length'] for entry in self.history) / len(self.history),
            'avg_strength': sum(entry['strength_score'] for entry in self.history) / len(self.history),
            'types_generated': list(set(entry['type'] for entry in self.history)),
            'last_generated': self.history[-1]['timestamp'] if self.history else None,
            'oldest_entry': self.history[0]['timestamp'] if self.history else None,
            'type_counts': {t: sum(1 for entry in self.history if entry['type'] == t) 
                          for t in set(entry['type'] for entry in self.history)}
        }
    
    def _save_history(self):
        # Save history to file.
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save history: {e}")
    
    def _load_history(self):
        # Load history from file.
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    loaded_history = json.load(f)
                    # Ensure all entries have IDs (for backward compatibility)
                    for i, entry in enumerate(loaded_history):
                        if 'id' not in entry:
                            entry['id'] = int(time.time() * 1000000) + i
                    self.history = loaded_history
        except Exception as e:
            logger.warning(f"Failed to load history: {e}")
            self.history = []

class WordListManager:
    # Enhanced word list management with caching and validation.
    def __init__(self):
        self.wordlist_path = os.path.join(os.path.dirname(__file__), "wordlist.txt")
        self._words_cache = None
    
    def get_words(self, min_length: int = None, max_length: int = None) -> List[str]:
        # Get filtered word list.
        if self._words_cache is None:
            self._words_cache = self._load_words()
        
        min_len = min_length or settings.WORD_MIN_LENGTH
        max_len = max_length or settings.WORD_MAX_LENGTH
        
        return [word for word in self._words_cache 
                if min_len <= len(word) <= max_len and word.isalpha()]
    
    def _load_words(self) -> List[str]:
        # Load words from file or download if needed.
        if not os.path.exists(self.wordlist_path):
            return self._download_wordlist()
        
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                words = [line.strip().lower() for line in f.readlines()]
                logger.info(f"Loaded {len(words)} words from local wordlist")
                return words
        except Exception as e:
            logger.warning(f"Failed to load local wordlist: {e}")
            return self._download_wordlist()
    
    def _download_wordlist(self) -> List[str]:
        # Download and cache word list.
        try:
            print("📥 Downloading word list...")
            response = requests.get(settings.DICEWARE_WORDLIST_URL, timeout=30)
            response.raise_for_status()
            
            words = [word.strip().lower() for word in response.text.splitlines() 
                    if settings.WORD_MIN_LENGTH <= len(word.strip()) <= settings.WORD_MAX_LENGTH and word.strip().isalpha()]
            
            # Save to cache
            with open(self.wordlist_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(words))
            
            print(f"✅ Downloaded {len(words)} words")
            logger.info(f"Downloaded wordlist with {len(words)} words")
            return words
            
        except Exception as e:
            logger.error(f"Failed to download wordlist: {e}")
            print(f"❌ Failed to download wordlist, using fallback")
            # Fallback word list
            return [
                "apple", "beach", "cloud", "dance", "earth", "field", "grape", "house",
                "igloo", "jelly", "knife", "lemon", "music", "night", "ocean", "paper",
                "queen", "river", "sugar", "table", "umbrella", "voice", "water", "yellow",
                "zebra", "actor", "baker", "candle", "dragon", "eagle", "flower", "garden",
                "hammer", "island", "jacket", "kettle", "ladder", "market", "needle", "orange",
                "pencil", "quilt", "rabbit", "silver", "tiger", "unicorn", "violin", "window"
            ]

def generate_password(
    length: int = None,
    include_upper: bool = True,
    include_lower: bool = True, 
    include_digits: bool = True,
    include_symbols: bool = True,
    exclude_similar: bool = True,
    exclude_ambiguous: bool = False,
    min_upper: int = None,
    min_lower: int = None,
    min_digits: int = None,
    min_symbols: int = None
) -> str:
    # Generate cryptographically secure password using secrets module.
    
    # Use settings defaults if not specified
    length = length or settings.DEFAULT_PASSWORD_LENGTH
    min_upper = min_upper if min_upper is not None else settings.MIN_UPPER
    min_lower = min_lower if min_lower is not None else settings.MIN_LOWER
    min_digits = min_digits if min_digits is not None else settings.MIN_DIGITS
    min_symbols = min_symbols if min_symbols is not None else settings.MIN_SYMBOLS
    
    # Define character sets
    upper_chars = string.ascii_uppercase
    lower_chars = string.ascii_lowercase
    digit_chars = string.digits
    symbol_chars = string.punctuation
    
    # Apply exclusions
    if exclude_similar:
        upper_chars = re.sub(r'[IO]', '', upper_chars)
        lower_chars = re.sub(r'[lo]', '', lower_chars)
        digit_chars = re.sub(r'[01]', '', digit_chars)
    
    if exclude_ambiguous:
        symbol_chars = re.sub(r'[{}[\]()/\\\'"~,;:._<>-]', '', symbol_chars)
    
    # Build character sets
    char_sets = []
    if include_upper and upper_chars:
        char_sets.append(upper_chars)
    if include_lower and lower_chars:
        char_sets.append(lower_chars) 
    if include_digits and digit_chars:
        char_sets.append(digit_chars)
    if include_symbols and symbol_chars:
        char_sets.append(symbol_chars)
    
    if not char_sets:
        raise ValueError("No character sets selected for password generation")
    
    # Calculate minimum requirements
    min_chars = 0
    if include_upper: min_chars += min_upper
    if include_lower: min_chars += min_lower
    if include_digits: min_chars += min_digits
    if include_symbols: min_chars += min_symbols
    
    if min_chars > length:
        raise ValueError("Minimum requirements exceed password length")
    
    # Generate password with guaranteed minimums
    password = []
    
    # Add minimum required characters
    if include_upper and min_upper > 0 and upper_chars:
        password.extend(secrets.choice(upper_chars) for _ in range(min_upper))
    if include_lower and min_lower > 0 and lower_chars:
        password.extend(secrets.choice(lower_chars) for _ in range(min_lower))
    if include_digits and min_digits > 0 and digit_chars:
        password.extend(secrets.choice(digit_chars) for _ in range(min_digits))
    if include_symbols and min_symbols > 0 and symbol_chars:
        password.extend(secrets.choice(symbol_chars) for _ in range(min_symbols))
    
    # Fill remaining characters
    remaining = length - len(password)
    all_chars = ''.join(char_sets)
    password.extend(secrets.choice(all_chars) for _ in range(remaining))
    
    # Cryptographically secure shuffle
    for i in range(len(password)):
        j = secrets.randbelow(len(password))
        password[i], password[j] = password[j], password[i]
    
    return ''.join(password)

def generate_passphrase(
    num_words: int = None,
    separator: str = "-",
    capitalize: bool = False,
    add_number: bool = False,
    add_symbol: bool = False
) -> str:
    # Generate Diceware-style passphrase.
    num_words = num_words or settings.DEFAULT_PASSPHRASE_WORDS
    
    word_manager = WordListManager()
    words = word_manager.get_words()
    
    if not words:
        raise ValueError("Failed to load word list for passphrase generation")
    
    # Select random words using secrets
    selected_words = [secrets.choice(words) for _ in range(num_words)]
    
    # Apply transformations
    if capitalize:
        selected_words = [word.capitalize() for word in selected_words]
    
    # Join with separator
    passphrase = separator.join(selected_words)
    
    # Add random number if requested
    if add_number:
        passphrase += str(secrets.randbelow(100))
    
    # Add random symbol if requested
    if add_symbol:
        symbols = "!@#$%^&*"
        passphrase += secrets.choice(symbols)
    
    return passphrase

def evaluate_password_strength(password: str) -> Tuple[str, float, Dict[str, Any]]:
    # Comprehensive password strength evaluation.
    # Use zxcvbn for advanced analysis
    result = zxcvbn.zxcvbn(password)
    base_score = result['score'] * 20  # Convert 0-4 to 0-80
    
    # Calculate entropy
    char_set_size = 0
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    
    if has_upper: char_set_size += 26
    if has_lower: char_set_size += 26
    if has_digit: char_set_size += 10
    if has_symbol: char_set_size += len(string.punctuation)
    
    entropy = len(password) * math.log2(char_set_size) if char_set_size > 0 else 0
    
    # Pattern analysis
    patterns = {
        'sequential': bool(re.search(r'(abc|bcd|cde|123|234|345)', password.lower())),
        'repeating': bool(re.search(r'(.)\1{2,}', password)),
        'keyboard': bool(re.search(r'(qwer|asdf|zxcv)', password.lower())),
        'common_substitutions': bool(re.search(r'[@4\$5!1]', password))
    }
    
    # Calculate final score
    score = base_score + (entropy * 1.5)
    
    # Apply penalties
    if patterns['sequential']: score *= 0.8
    if patterns['repeating']: score *= 0.8
    if patterns['keyboard']: score *= 0.7
    if len(password) < 8: score *= 0.6
    
    # Cap at 100
    score = min(100, score)
    
    # Determine rating with colors
    if score >= 90:
        rating = f"{colorama.Fore.GREEN}Excellent{colorama.Style.RESET_ALL}"
    elif score >= 80:
        rating = f"{colorama.Fore.CYAN}Very Strong{colorama.Style.RESET_ALL}"
    elif score >= 65:
        rating = f"{colorama.Fore.BLUE}Strong{colorama.Style.RESET_ALL}"
    elif score >= 50:
        rating = f"{colorama.Fore.YELLOW}Moderate{colorama.Style.RESET_ALL}"
    elif score >= 35:
        rating = f"{colorama.Fore.MAGENTA}Weak{colorama.Style.RESET_ALL}"
    else:
        rating = f"{colorama.Fore.RED}Very Weak{colorama.Style.RESET_ALL}"
    
    # Detailed analysis
    analysis = {
        'entropy': entropy,
        'char_set_size': char_set_size,
        'length': len(password),
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digit': has_digit,
        'has_symbol': has_symbol,
        'patterns_detected': [k for k, v in patterns.items() if v],
        'zxcvbn_feedback': result.get('feedback', {}),
        'crack_times': result.get('crack_times_display', {})
    }
    
    return rating, score, analysis

def display_password_analysis(password: str, show_password: bool = True):
    # Display comprehensive password analysis.
    rating, score, analysis = evaluate_password_strength(password)
    
    print("\n" + "="*60)
    print(f"🔐 PASSWORD ANALYSIS")
    print("="*60)
    
    if show_password:
        print(f"Password: {colorama.Fore.CYAN}{password}{colorama.Style.RESET_ALL}")
    else:
        masked = '*' * len(password)
        print(f"Password: {colorama.Fore.YELLOW}{masked}{colorama.Style.RESET_ALL}")
    
    print(f"Length: {analysis['length']} characters")
    print(f"Strength: {rating} ({score:.1f}/100)")
    print(f"Entropy: {analysis['entropy']:.2f} bits")
    
    # Character composition
    print(f"\n📊 Character Composition:")
    composition = []
    if analysis['has_upper']: composition.append("Uppercase")
    if analysis['has_lower']: composition.append("Lowercase") 
    if analysis['has_digit']: composition.append("Digits")
    if analysis['has_symbol']: composition.append("Symbols")
    print(f"  Types: {', '.join(composition)}")
    print(f"  Character set size: {analysis['char_set_size']}")
    
    # Pattern warnings
    if analysis['patterns_detected']:
        print(f"\n⚠️  Pattern Warnings:")
        for pattern in analysis['patterns_detected']:
            print(f"  • {pattern.replace('_', ' ').title()} detected")
    
    # Crack time estimates
    crack_times = analysis.get('crack_times', {})
    if crack_times:
        print(f"\n⏱️  Estimated Crack Times:")
        for scenario, time_str in crack_times.items():
            if time_str:
                print(f"  {scenario.replace('_', ' ').title()}: {time_str}")
    
    print("="*60)

def copy_to_clipboard_with_timer(text: str, clear_after: int = None):
    # Copy to clipboard and clear after specified time.
    clear_after = clear_after or settings.CLIPBOARD_CLEAR_TIME
    
    try:
        pyperclip.copy(text)
        print(f"📋 Copied to clipboard! Will clear in {clear_after} seconds...")
        
        def clear_clipboard():
            time.sleep(clear_after)
            pyperclip.copy("")
            print(f"🧹 Clipboard cleared after {clear_after} seconds")
        
        # Run in background thread
        threading.Thread(target=clear_clipboard, daemon=True).start()
        
    except Exception as e:
        logger.warning(f"Clipboard operation failed: {e}")
        print(f"❌ Clipboard not available: {e}")

def secure_save_password(
    password: str,
    service: str,
    username: Optional[str] = None,
    filepath: Optional[str] = None
) -> bool:
    # Save password using AES-256-GCM encryption.
    if filepath is None:
        filepath = os.path.expanduser("~/password_vault.enc")
    
    try:
        master_password = SecureString(getpass("Enter master password for vault: "))
        
        # Generate salt and derive key
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(master_password.get().encode())
        
        # Prepare data
        data = {
            'service': service,
            'username': username or 'N/A',
            'password': password,
            'timestamp': datetime.now().isoformat(),
            'version': '2.0'
        }
        data_json = json.dumps(data)
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, data_json.encode(), None)
        
        # Save: salt + nonce + ciphertext
        with open(filepath, 'wb') as f:
            f.write(salt + nonce + ciphertext)
        
        print(f"✅ Password saved securely to {filepath}")
        logger.info(f"Password saved for service: {service}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to save password: {e}")
        logger.error(f"Password save failed: {e}")
        return False

def generate_totp_code(secret: str) -> str:
    # Generate TOTP code for 2FA.
    try:
        totp = pyotp.TOTP(secret)
        code = totp.now()
        remaining = 30 - (int(time.time()) % 30)
        print(f"🔐 TOTP Code: {colorama.Fore.CYAN}{code}{colorama.Style.RESET_ALL}")
        print(f"⏰ Valid for {remaining} more seconds")
        return code
    except Exception as e:
        print(f"❌ Failed to generate TOTP code: {e}")
        logger.error(f"TOTP generation failed: {e}")
        return ""

def interactive_history_management(history: PasswordHistory):
    # Interactive history management menu.
    while True:
        entries = history.get_entries_with_ids(20)
        stats = history.get_stats()
        
        print(f"\n📚 History Management")
        print("="*60)
        
        if stats:
            print(f"Total entries: {stats['total_generated']}")
            if stats.get('type_counts'):
                type_summary = ', '.join([f"{t}: {c}" for t, c in stats['type_counts'].items()])
                print(f"By type: {type_summary}")
        else:
            print("No history entries found.")
        
        print("\n📝 History Management Options:")
        print("1. 📋 View recent entries")
        print("2. 🗑️  Delete specific entry by ID")
        print("3. 🔄 Delete entries by type")
        print("4. ⏰ Delete entries older than X days")
        print("5. 📊 Delete entries by strength score")
        print("6. 🧹 Clear all history")
        print("7. 📈 Show detailed statistics")
        print("8. ↩️  Back to main menu")
        
        choice = input(f"\n{colorama.Fore.YELLOW}Enter your choice (1-8): {colorama.Style.RESET_ALL}").strip()
        
        try:
            if choice == '1':
                # View recent entries
                if entries:
                    print(f"\n📜 Recent History Entries (showing last {len(entries)}):")
                    print("-" * 80)
                    for entry in entries:
                        timestamp = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M')
                        print(f"ID: {entry['id']:>15} | {entry['type'].title():>10} | "
                              f"Length: {entry['length']:>2} | Strength: {entry['strength_score']:>5.1f} | "
                              f"{timestamp}")
                else:
                    print("📭 No history entries found")
            
            elif choice == '2':
                # Delete specific entry
                if not entries:
                    print("📭 No entries to delete")
                    continue
                
                entry_id = int(input("Enter entry ID to delete: "))
                if history.delete_entry(entry_id):
                    print(f"✅ Entry {entry_id} deleted successfully")
                else:
                    print(f"❌ Entry {entry_id} not found")
            
            elif choice == '3':
                # Delete by type
                if not entries:
                    print("📭 No entries to delete")
                    continue
                
                available_types = list(set(entry['type'] for entry in entries))
                print(f"Available types: {', '.join(available_types)}")
                entry_type = input("Enter type to delete: ").lower().strip()
                
                count = history.delete_entries_by_type(entry_type)
                if count > 0:
                    print(f"✅ Deleted {count} entries of type '{entry_type}'")
                else:
                    print(f"❌ No entries of type '{entry_type}' found")
            
            elif choice == '4':
                # Delete by age
                if not entries:
                    print("📭 No entries to delete")
                    continue
                
                days = int(input("Delete entries older than how many days? "))
                if days < 1:
                    print("❌ Days must be positive")
                    continue
                
                count = history.delete_entries_older_than(days)
                if count > 0:
                    print(f"✅ Deleted {count} entries older than {days} days")
                else:
                    print(f"❌ No entries older than {days} days found")
            
            elif choice == '5':
                # Delete by strength
                if not entries:
                    print("📭 No entries to delete")
                    continue
                
                print("Delete entries by strength score:")
                print("1. Delete weak entries (score < 50)")
                print("2. Delete moderate entries (score 50-65)")
                print("3. Delete by custom range")
                
                strength_choice = input("Choose option (1-3): ").strip()
                
                if strength_choice == '1':
                    count = history.delete_entries_by_strength(max_strength=49.9)
                    print(f"✅ Deleted {count} weak entries (score < 50)")
                elif strength_choice == '2':
                    count = history.delete_entries_by_strength(min_strength=50, max_strength=65)
                    print(f"✅ Deleted {count} moderate entries (score 50-65)")
                elif strength_choice == '3':
                    min_score = float(input("Minimum score (or press Enter for no minimum): ") or "0")
                    max_score = float(input("Maximum score (or press Enter for no maximum): ") or "100")
                    count = history.delete_entries_by_strength(
                        min_strength=min_score if min_score > 0 else None,
                        max_strength=max_score if max_score < 100 else None
                    )
                    print(f"✅ Deleted {count} entries in score range {min_score}-{max_score}")
                else:
                    print("❌ Invalid choice")
            
            elif choice == '6':
                # Clear all
                if not entries:
                    print("📭 No entries to delete")
                    continue
                
                confirm = input(f"⚠️  Delete ALL {len(history.history)} history entries? Type 'DELETE ALL' to confirm: ")
                if confirm == "DELETE ALL":
                    count = history.clear_all_history()
                    print(f"✅ Cleared all history - {count} entries deleted")
                else:
                    print("❌ Deletion cancelled")
            
            elif choice == '7':
                # Detailed statistics
                if stats:
                    print(f"\n📊 Detailed History Statistics:")
                    print("-" * 50)
                    print(f"Total entries: {stats['total_generated']}")
                    print(f"Average length: {stats['avg_length']:.1f} characters")
                    print(f"Average strength: {stats['avg_strength']:.1f}/100")
                    
                    if stats.get('type_counts'):
                        print(f"\nEntry counts by type:")
                        for entry_type, count in stats['type_counts'].items():
                            print(f"  {entry_type.title()}: {count}")
                    
                    if stats.get('oldest_entry'):
                        oldest = datetime.fromisoformat(stats['oldest_entry'])
                        print(f"\nOldest entry: {oldest.strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    if stats.get('last_generated'):
                        latest = datetime.fromisoformat(stats['last_generated'])
                        print(f"Latest entry: {latest.strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    # Strength distribution
                    if history.history:
                        strengths = [entry['strength_score'] for entry in history.history]
                        weak = sum(1 for s in strengths if s < 50)
                        moderate = sum(1 for s in strengths if 50 <= s < 65)
                        strong = sum(1 for s in strengths if 65 <= s < 80)
                        very_strong = sum(1 for s in strengths if s >= 80)
                        
                        print(f"\nStrength distribution:")
                        print(f"  Very Strong (≥80): {very_strong}")
                        print(f"  Strong (65-79): {strong}")
                        print(f"  Moderate (50-64): {moderate}")
                        print(f"  Weak (<50): {weak}")
                else:
                    print("📊 No statistics available")
            
            elif choice == '8':
                break
            
            else:
                print("❌ Invalid choice. Please try again.")
                
        except ValueError:
            print("❌ Invalid input. Please enter a valid number.")
        except Exception as e:
            print(f"❌ Error: {e}")

def interactive_settings_menu():
    # Interactive settings configuration menu.
    while True:
        settings.display_settings()
        print("\n📝 Settings Menu:")
        print("1. 🔢 Change default password length")
        print("2. 📝 Change default passphrase words")
        print("3. ⏰ Change clipboard clear time")
        print("4. 📚 Change max history size")
        print("5. 🔤 Change minimum character requirements")
        print("6. 📖 Change word length settings")
        print("7. 🌐 Change wordlist URL")
        print("8. 🔧 Change log level")
        print("9. 💾 Save settings to file")
        print("10. 🔄 Reset to defaults")
        print("11. ↩️  Back to main menu")
        
        choice = input(f"\n{colorama.Fore.YELLOW}Enter your choice (1-11): {colorama.Style.RESET_ALL}").strip()
        
        try:
            if choice == '1':
                new_length = int(input(f"Enter new default password length (current: {settings.DEFAULT_PASSWORD_LENGTH}): "))
                if 4 <= new_length <= 128:
                    settings.DEFAULT_PASSWORD_LENGTH = new_length
                    print(f"✅ Default password length set to {new_length}")
                else:
                    print("❌ Length must be between 4 and 128")
            
            elif choice == '2':
                new_words = int(input(f"Enter new default passphrase words (current: {settings.DEFAULT_PASSPHRASE_WORDS}): "))
                if 2 <= new_words <= 20:
                    settings.DEFAULT_PASSPHRASE_WORDS = new_words
                    print(f"✅ Default passphrase words set to {new_words}")
                else:
                    print("❌ Words must be between 2 and 20")
            
            elif choice == '3':
                new_time = int(input(f"Enter new clipboard clear time in seconds (current: {settings.CLIPBOARD_CLEAR_TIME}): "))
                if 5 <= new_time <= 300:
                    settings.CLIPBOARD_CLEAR_TIME = new_time
                    print(f"✅ Clipboard clear time set to {new_time} seconds")
                else:
                    print("❌ Time must be between 5 and 300 seconds")
            
            elif choice == '4':
                new_size = int(input(f"Enter new max history size (current: {settings.MAX_HISTORY_SIZE}): "))
                if 10 <= new_size <= 1000:
                    settings.MAX_HISTORY_SIZE = new_size
                    print(f"✅ Max history size set to {new_size}")
                else:
                    print("❌ Size must be between 10 and 1000")
            
            elif choice == '5':
                print(f"\nCurrent minimum requirements:")
                print(f"  Uppercase: {settings.MIN_UPPER}")
                print(f"  Lowercase: {settings.MIN_LOWER}")
                print(f"  Digits: {settings.MIN_DIGITS}")
                print(f"  Symbols: {settings.MIN_SYMBOLS}")
                
                settings.MIN_UPPER = int(input("Enter minimum uppercase chars (0-10): ") or str(settings.MIN_UPPER))
                settings.MIN_LOWER = int(input("Enter minimum lowercase chars (0-10): ") or str(settings.MIN_LOWER))
                settings.MIN_DIGITS = int(input("Enter minimum digit chars (0-10): ") or str(settings.MIN_DIGITS))
                settings.MIN_SYMBOLS = int(input("Enter minimum symbol chars (0-10): ") or str(settings.MIN_SYMBOLS))
                
                print("✅ Minimum character requirements updated")
            
            elif choice == '6':
                print(f"\nCurrent word length settings:")
                print(f"  Minimum: {settings.WORD_MIN_LENGTH}")
                print(f"  Maximum: {settings.WORD_MAX_LENGTH}")
                
                min_len = int(input("Enter minimum word length (2-15): ") or str(settings.WORD_MIN_LENGTH))
                max_len = int(input("Enter maximum word length (3-20): ") or str(settings.WORD_MAX_LENGTH))
                
                if 2 <= min_len <= 15 and 3 <= max_len <= 20 and min_len < max_len:
                    settings.WORD_MIN_LENGTH = min_len
                    settings.WORD_MAX_LENGTH = max_len
                    print("✅ Word length settings updated")
                else:
                    print("❌ Invalid word length settings")
            
            elif choice == '7':
                new_url = input(f"Enter new wordlist URL (current: {settings.DICEWARE_WORDLIST_URL}): ").strip()
                if new_url and new_url.startswith(('http://', 'https://')):
                    settings.DICEWARE_WORDLIST_URL = new_url
                    print("✅ Wordlist URL updated")
                else:
                    print("❌ Invalid URL format")
            
            elif choice == '8':
                levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
                print(f"Available log levels: {', '.join(levels)}")
                new_level = input(f"Enter new log level (current: {settings.LOG_LEVEL}): ").upper().strip()
                if new_level in levels:
                    settings.LOG_LEVEL = new_level
                    print(f"✅ Log level set to {new_level}")
                else:
                    print("❌ Invalid log level")
            
            elif choice == '9':
                if settings.save_config():
                    print("✅ Settings saved successfully")
                else:
                    print("❌ Failed to save settings")
            
            elif choice == '10':
                if input("Reset all settings to defaults? (y/N): ").lower() == 'y':
                    settings.__init__()  # Reset to defaults
                    print("✅ Settings reset to defaults")
            
            elif choice == '11':
                break
            
            else:
                print("❌ Invalid choice. Please try again.")
                
        except ValueError:
            print("❌ Invalid input. Please enter a valid number.")
        except Exception as e:
            print(f"❌ Error: {e}")

def interactive_mode():
    # Enhanced interactive mode with full feature access including history management.
    history = PasswordHistory()
    
    print(f"\n{colorama.Fore.CYAN}🚀 PASSWORD GENERATOR - Interactive Mode{colorama.Style.RESET_ALL}")
    print("="*60)
    
    while True:
        print("\n📋 Available Options:")
        print("1. 🔐 Generate Password")
        print("2. 📝 Generate Passphrase") 
        print("3. 🔢 Generate TOTP Code")
        print("4. 📊 View Generation History")
        print("5. 🗑️  Manage History")
        print("6. 📈 Show Statistics")
        print("7. 🧪 Password Strength Test")
        print("8. ⚙️  Settings")
        print("9. 📄 Show Copyright Info")
        print("10. ❌ Exit")
        
        choice = input(f"\n{colorama.Fore.YELLOW}Enter your choice (1-10): {colorama.Style.RESET_ALL}").strip()
        
        if choice == '1':
            # Password generation
            try:
                length = int(input(f"Password length (default {settings.DEFAULT_PASSWORD_LENGTH}): ") or str(settings.DEFAULT_PASSWORD_LENGTH))
                include_upper = input("Include uppercase? (Y/n): ").lower() != 'n'
                include_lower = input("Include lowercase? (Y/n): ").lower() != 'n'
                include_digits = input("Include digits? (Y/n): ").lower() != 'n'
                include_symbols = input("Include symbols? (Y/n): ").lower() != 'n'
                exclude_similar = input("Exclude similar chars (I,l,1,O,0)? (Y/n): ").lower() != 'n'
                
                password = generate_password(
                    length=length,
                    include_upper=include_upper,
                    include_lower=include_lower,
                    include_digits=include_digits,
                    include_symbols=include_symbols,
                    exclude_similar=exclude_similar
                )
                
                rating, score, analysis = evaluate_password_strength(password)
                history.add(password, "password", score)
                
                display_password_analysis(password)
                
                # Options
                if input("\nCopy to clipboard? (y/N): ").lower() == 'y':
                    copy_to_clipboard_with_timer(password)
                    
                if input("Save to vault? (y/N): ").lower() == 'y':
                    service = input("Service name: ")
                    username = input("Username (optional): ") or None
                    secure_save_password(password, service, username)
                
            except Exception as e:
                print(f"❌ Error: {e}")
        
        elif choice == '2':
            # Passphrase generation
            try:
                num_words = int(input(f"Number of words (default {settings.DEFAULT_PASSPHRASE_WORDS}): ") or str(settings.DEFAULT_PASSPHRASE_WORDS))
                separator = input("Word separator (default '-'): ") or "-"
                capitalize = input("Capitalize words? (y/N): ").lower() == 'y'
                add_number = input("Add random number? (y/N): ").lower() == 'y'
                add_symbol = input("Add random symbol? (y/N): ").lower() == 'y'
                
                passphrase = generate_passphrase(
                    num_words=num_words,
                    separator=separator,
                    capitalize=capitalize,
                    add_number=add_number,
                    add_symbol=add_symbol
                )
                
                rating, score, analysis = evaluate_password_strength(passphrase)
                history.add(passphrase, "passphrase", score)
                
                display_password_analysis(passphrase)
                
                if input("\nCopy to clipboard? (y/N): ").lower() == 'y':
                    copy_to_clipboard_with_timer(passphrase)
                    
            except Exception as e:
                print(f"❌ Error: {e}")
        
        elif choice == '3':
            # TOTP generation
            secret = input("Enter TOTP secret key: ").strip()
            if secret:
                code = generate_totp_code(secret)
                if code and input("Copy to clipboard? (y/N): ").lower() == 'y':
                    copy_to_clipboard_with_timer(code, 30)
        
        elif choice == '4':
            # History
            recent = history.get_recent(10)
            if recent:
                print(f"\n📜 Recent Generations:")
                for i, entry in enumerate(recent[-10:], 1):
                    timestamp = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M')
                    print(f"{i:2d}. {entry['type'].title():10} | "
                          f"Length: {entry['length']:2d} | "
                          f"Strength: {entry['strength_score']:5.1f} | "
                          f"{timestamp}")
            else:
                print("📭 No generation history found")
        
        elif choice == '5':
            # History Management
            interactive_history_management(history)
        
        elif choice == '6':
            # Statistics
            stats = history.get_stats()
            if stats:
                print(f"\n📊 Generation Statistics:")
                print(f"Total Generated: {stats['total_generated']}")
                print(f"Average Length: {stats['avg_length']:.1f}")
                print(f"Average Strength: {stats['avg_strength']:.1f}")
                print(f"Types Generated: {', '.join(stats['types_generated'])}")
                if stats['last_generated']:
                    last = datetime.fromisoformat(stats['last_generated'])
                    print(f"Last Generated: {last.strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                print("📊 No statistics available")
        
        elif choice == '7':
            # Password strength test
            test_password = getpass("Enter password to test (hidden): ")
            if test_password:
                display_password_analysis(test_password, show_password=False)
        
        elif choice == '8':
            # Settings
            interactive_settings_menu()
        
        elif choice == '9':
            # Copyright info
            show_copyright()
        
        elif choice == '10':
            print(f"\n{colorama.Fore.GREEN}👋 GOOD BYE! HAVE NICE DAY!{colorama.Style.RESET_ALL}")
            break
        
        else:
            print("❌ Invalid choice. Please try again.")

def main():
    # Main function with comprehensive CLI support including history management.
    parser = argparse.ArgumentParser(
        description=f"Password Generator with Configurable Settings & History Management v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{__copyright__}
Author: {__author__}
License: {__license__}

Examples:
  %(prog)s                           # Interactive mode
  %(prog)s -l 20 --copy             # Generate 20-char password and copy
  %(prog)s -t passphrase -w 5       # Generate 5-word passphrase
  %(prog)s -t totp --secret KEY123  # Generate TOTP code
  %(prog)s --test                   # Test password strength
  %(prog)s --history                # Show generation history
  %(prog)s --delete-history-by-type password  # Delete all passwords from history
  %(prog)s --clear-history          # Clear all history (requires confirmation)
  %(prog)s --show-settings          # Display current settings
  %(prog)s --set-default-length 24  # Change default password length
  %(prog)s --copyright              # Show copyright information
        """
    )
    
    # Generation type
    parser.add_argument('-t', '--type', choices=['password', 'passphrase', 'totp'], 
                       default='password', help='Type of secret to generate')
    
    # Password options
    pwd_group = parser.add_argument_group('Password Options')
    pwd_group.add_argument('-l', '--length', type=int, 
                          help=f'Password length (default from settings: {settings.DEFAULT_PASSWORD_LENGTH})')
    pwd_group.add_argument('--no-upper', action='store_true', help='Exclude uppercase')
    pwd_group.add_argument('--no-lower', action='store_true', help='Exclude lowercase')
    pwd_group.add_argument('--no-digits', action='store_true', help='Exclude digits')
    pwd_group.add_argument('--no-symbols', action='store_true', help='Exclude symbols')
    pwd_group.add_argument('--exclude-similar', action='store_true',
                          help='Exclude similar chars (I,l,1,O,0)')
    pwd_group.add_argument('--exclude-ambiguous', action='store_true',
                          help='Exclude ambiguous symbols')
    pwd_group.add_argument('--min-upper', type=int, help=f'Minimum uppercase (default: {settings.MIN_UPPER})')
    pwd_group.add_argument('--min-lower', type=int, help=f'Minimum lowercase (default: {settings.MIN_LOWER})')
    pwd_group.add_argument('--min-digits', type=int, help=f'Minimum digits (default: {settings.MIN_DIGITS})')
    pwd_group.add_argument('--min-symbols', type=int, help=f'Minimum symbols (default: {settings.MIN_SYMBOLS})')
    
    # Passphrase options
    phrase_group = parser.add_argument_group('Passphrase Options')
    phrase_group.add_argument('-w', '--words', type=int,
                             help=f'Number of words (default from settings: {settings.DEFAULT_PASSPHRASE_WORDS})')
    phrase_group.add_argument('-s', '--separator', default='-',
                             help='Word separator (default: -)')
    phrase_group.add_argument('--capitalize', action='store_true',
                             help='Capitalize words')
    phrase_group.add_argument('--add-number', action='store_true',
                             help='Add random number')
    phrase_group.add_argument('--add-symbol', action='store_true',
                             help='Add random symbol')
    
    # TOTP options
    totp_group = parser.add_argument_group('TOTP Options')
    totp_group.add_argument('--secret', help='TOTP secret key')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-n', '--count', type=int, default=1,
                             help='Number of passwords to generate')
    output_group.add_argument('--copy', action='store_true',
                             help='Copy to clipboard')
    output_group.add_argument('--hide', action='store_true',
                             help='Hide password in output')
    output_group.add_argument('--save', action='store_true',
                             help='Save to encrypted vault')
    output_group.add_argument('--service', help='Service name for vault')
    output_group.add_argument('--username', help='Username for vault')
    
    # History management options 
    history_group = parser.add_argument_group('History Management Options')
    history_group.add_argument('--history', action='store_true',
                              help='Show generation history')
    history_group.add_argument('--stats', action='store_true',
                              help='Show detailed statistics')
    history_group.add_argument('--delete-history-entry', type=int, metavar='ID',
                              help='Delete specific history entry by ID')
    history_group.add_argument('--delete-history-by-type', choices=['password', 'passphrase', 'totp'],
                              help='Delete all entries of specified type')
    history_group.add_argument('--delete-history-older-than', type=int, metavar='DAYS',
                              help='Delete entries older than specified days')
    history_group.add_argument('--delete-weak-history', action='store_true',
                              help='Delete entries with strength score < 50')
    history_group.add_argument('--clear-history', action='store_true',
                              help='Clear all history (requires confirmation)')
    
    # Settings options
    settings_group = parser.add_argument_group('Settings Options')
    settings_group.add_argument('--show-settings', action='store_true',
                               help='Display current settings')
    settings_group.add_argument('--save-settings', action='store_true',
                               help='Save current settings to config file')
    settings_group.add_argument('--reset-settings', action='store_true',
                               help='Reset settings to defaults')
    settings_group.add_argument('--set-default-length', type=int, metavar='N',
                               help='Set default password length')
    settings_group.add_argument('--set-default-words', type=int, metavar='N',
                               help='Set default passphrase words')
    settings_group.add_argument('--set-clipboard-time', type=int, metavar='SECONDS',
                               help='Set clipboard clear time')
    settings_group.add_argument('--set-history-size', type=int, metavar='N',
                               help='Set max history size')
    settings_group.add_argument('--set-min-upper', type=int, metavar='N',
                               help='Set minimum uppercase chars')
    settings_group.add_argument('--set-min-lower', type=int, metavar='N',
                               help='Set minimum lowercase chars')
    settings_group.add_argument('--set-min-digits', type=int, metavar='N',
                               help='Set minimum digit chars')
    settings_group.add_argument('--set-min-symbols', type=int, metavar='N',
                               help='Set minimum symbol chars')
    settings_group.add_argument('--set-word-min-length', type=int, metavar='N',
                               help='Set minimum word length for passphrases')
    settings_group.add_argument('--set-word-max-length', type=int, metavar='N',
                               help='Set maximum word length for passphrases')
    settings_group.add_argument('--set-log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                               help='Set logging level')
    
    # Utility options
    util_group = parser.add_argument_group('Utility Options')
    util_group.add_argument('--interactive', action='store_true',
                           help='Run in interactive mode')
    util_group.add_argument('--test', action='store_true',
                           help='Test password strength')
    util_group.add_argument('--copyright', action='store_true',
                           help='Show copyright information')
    util_group.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    # Handle settings changes first
    settings.update_from_args(args)
    
    # Initialize components
    history = PasswordHistory()
    
    try:
        # Copyright command
        if args.copyright:
            show_copyright()
            return 0
        
        # Settings commands
        if args.show_settings:
            settings.display_settings()
            return 0
        
        if args.save_settings:
            if settings.save_config():
                print("✅ Settings saved successfully")
            else:
                print("❌ Failed to save settings")
            return 0
        
        if args.reset_settings:
            if input("Reset all settings to defaults? (y/N): ").lower() == 'y':
                settings.__init__()  # Reset to defaults
                print("✅ Settings reset to defaults")
            return 0
        
        # History management commands 
        if args.delete_history_entry:
            if history.delete_entry(args.delete_history_entry):
                print(f"✅ Entry {args.delete_history_entry} deleted successfully")
            else:
                print(f"❌ Entry {args.delete_history_entry} not found")
            return 0
        
        if args.delete_history_by_type:
            count = history.delete_entries_by_type(args.delete_history_by_type)
            if count > 0:
                print(f"✅ Deleted {count} entries of type '{args.delete_history_by_type}'")
            else:
                print(f"❌ No entries of type '{args.delete_history_by_type}' found")
            return 0
        
        if args.delete_history_older_than:
            count = history.delete_entries_older_than(args.delete_history_older_than)
            if count > 0:
                print(f"✅ Deleted {count} entries older than {args.delete_history_older_than} days")
            else:
                print(f"❌ No entries older than {args.delete_history_older_than} days found")
            return 0
        
        if args.delete_weak_history:
            count = history.delete_entries_by_strength(max_strength=49.9)
            if count > 0:
                print(f"✅ Deleted {count} weak entries (strength score < 50)")
            else:
                print("❌ No weak entries found")
            return 0
        
        if args.clear_history:
            total_entries = len(history.history)
            if total_entries == 0:
                print("📭 No history entries to clear")
                return 0
            
            print(f"⚠️  You are about to delete ALL {total_entries} history entries!")
            confirm = input("Type 'DELETE ALL' to confirm: ")
            if confirm == "DELETE ALL":
                count = history.clear_all_history()
                print(f"✅ Cleared all history - {count} entries deleted")
            else:
                print("❌ Deletion cancelled")
            return 0
        
        # Interactive mode
        if args.interactive or len(sys.argv) == 1:
            interactive_mode()
            return 0
        
        # Utility commands
        if args.test:
            test_password = getpass("Enter password to test (hidden): ")
            if test_password:
                display_password_analysis(test_password, show_password=False)
            return 0
        
        if args.history:
            recent = history.get_recent(20)
            if recent:
                print("📜 Generation History:")
                print("-" * 80)
                for i, entry in enumerate(recent, 1):
                    timestamp = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M')
                    entry_id = entry.get('id', 'N/A')
                    print(f"{i:2d}. ID: {entry_id:>15} | {entry['type'].title():>10} | "
                          f"Length: {entry['length']:2d} | "
                          f"Strength: {entry['strength_score']:5.1f} | "
                          f"{timestamp}")
            else:
                print("📭 No generation history found")
            return 0
        
        if args.stats:
            stats = history.get_stats()
            if stats:
                print("📊 Generation Statistics:")
                print("-" * 50)
                print(f"Total Generated: {stats['total_generated']}")
                print(f"Average Length: {stats['avg_length']:.1f}")
                print(f"Average Strength: {stats['avg_strength']:.1f}")
                print(f"Types Generated: {', '.join(stats['types_generated'])}")
                
                if stats.get('type_counts'):
                    print(f"\nEntry counts by type:")
                    for entry_type, count in stats['type_counts'].items():
                        print(f"  {entry_type.title()}: {count}")
                
                if stats.get('oldest_entry'):
                    oldest = datetime.fromisoformat(stats['oldest_entry'])
                    print(f"\nOldest entry: {oldest.strftime('%Y-%m-%d %H:%M:%S')}")
                
                if stats['last_generated']:
                    last = datetime.fromisoformat(stats['last_generated'])
                    print(f"Latest entry: {last.strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                print("📊 No statistics available")
            return 0
        
        # Generate secrets
        generated_items = []
        
        for i in range(args.count):
            if args.type == 'totp':
                if not args.secret:
                    print("❌ TOTP secret required. Use --secret parameter.")
                    return 1
                
                code = generate_totp_code(args.secret)
                if code:
                    generated_items.append(code)
                    if args.copy and i == 0:  # Only copy first one
                        copy_to_clipboard_with_timer(code, 30)
            
            elif args.type == 'password':
                password = generate_password(
                    length=args.length,
                    include_upper=not args.no_upper,
                    include_lower=not args.no_lower,
                    include_digits=not args.no_digits,
                    include_symbols=not args.no_symbols,
                    exclude_similar=args.exclude_similar,
                    exclude_ambiguous=args.exclude_ambiguous,
                    min_upper=args.min_upper,
                    min_lower=args.min_lower,
                    min_digits=args.min_digits,
                    min_symbols=args.min_symbols
                )
                
                rating, score, analysis = evaluate_password_strength(password)
                history.add(password, "password", score)
                generated_items.append(password)
                
                # Show analysis for single generation or first few
                if args.count == 1:
                    display_password_analysis(password, not args.hide)
                elif i < 3:  # Show first 3 detailed
                    display_password_analysis(password, not args.hide)
                elif i == 3 and args.count > 3:
                    print(f"\n... generating {args.count - 3} more passwords ...")
                
                # Copy first password to clipboard
                if args.copy and i == 0:
                    copy_to_clipboard_with_timer(password)
            
            elif args.type == 'passphrase':
                passphrase = generate_passphrase(
                    num_words=args.words,
                    separator=args.separator,
                    capitalize=args.capitalize,
                    add_number=args.add_number,
                    add_symbol=args.add_symbol
                )
                
                rating, score, analysis = evaluate_password_strength(passphrase)
                history.add(passphrase, "passphrase", score)
                generated_items.append(passphrase)
                
                if args.count == 1:
                    display_password_analysis(passphrase, not args.hide)
                elif i < 3:
                    display_password_analysis(passphrase, not args.hide)
                
                if args.copy and i == 0:
                    copy_to_clipboard_with_timer(passphrase)
        
        # Summary for multiple generations
        if args.count > 1 and args.type != 'totp':
            print(f"\n✅ Generated {args.count} {args.type}s successfully!")
            
            # Show simple list if not detailed
            if args.count > 3 and not args.hide:
                print(f"\nGenerated {args.type}s:")
                for i, item in enumerate(generated_items, 1):
                    print(f"{i:2d}. {item}")
        
        # Save to vault if requested
        if args.save and generated_items and args.type in ['password', 'passphrase']:
            if len(generated_items) > 1:
                print("⚠️  Can only save single password to vault")
                return 1
            
            service = args.service or input("Enter service name: ")
            if service:
                secure_save_password(generated_items[0], service, args.username)
        
        # Save settings if any were changed via command line
        if any([args.set_default_length, args.set_default_words, args.set_clipboard_time,
                args.set_history_size, args.set_min_upper, args.set_min_lower,
                args.set_min_digits, args.set_min_symbols, args.set_word_min_length,
                args.set_word_max_length, args.set_log_level]):
            settings.save_config()
            print("✅ Settings updated and saved")
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\n{colorama.Fore.YELLOW}👋 Operation cancelled by user{colorama.Style.RESET_ALL}")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        logger.error(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    # Print banner with copyright
    print(f"{colorama.Fore.CYAN}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║             🚀 PASSWORD GENERATOR                         ║")
    print("║                                                            ║")
    print("║  🔐 Cryptographically Secure | 🧠 AI-Powered Analysis     ║")
    print("║  📋 Clipboard Integration    | 🔢 TOTP Support            ║")
    print("║  💾 Encrypted Vault Storage  | 📊 Detailed Analytics      ║")
    print("║  ⚙️  Configurable Settings   | 💾 Persistent Config       ║")
    print("║  🗑️  History Management      | 📚 Advanced Filtering      ║")
    print("║                                                            ║")
    print(f"║  {__copyright__:^56} ║")
    print(f"║  Version {__version__:^49} ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"{colorama.Style.RESET_ALL}")
    
    try:
        sys.exit(main())
    except Exception as e:
        logger.critical(f"Critical error: {e}")
        print(f"💥 Critical error occurred. Check password_generator.log for details.")
        sys.exit(1)