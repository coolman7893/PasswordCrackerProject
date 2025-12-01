# Password Cracker

A password cracking tool that demonstrates hashing, dictionary attacks, brute-force attacks, and hybrid attacks using Python.

## Features

- **Hash Passwords**: Create hashes using MD5, SHA-1, SHA-256, and SHA-512
- **Dictionary Attack**: Crack hashes by checking words from a wordlist file
- **Brute-Force Attack**: Try all character combinations up to a set length
- **Hybrid Attack**: Combine dictionary words with mutations (substitutions, numbers, special characters)
- **Auto-Detection**: Automatically detects hash type from hash length

## Installation
There are no external libraries used but 
Python 3.6+ is required.

## Usage

### Get Help

```bash
python password_cracker.py -h
```

For specific commands:
```bash
python password_cracker.py hash -h
python password_cracker.py crack -h
```

---

## Examples

### 1. Hash a Password

Hash a password using any supported algorithm:

```bash
python password_cracker.py hash -p "mypassword" -a sha256
```

Output:
```
Password: mypassword
Algorithm: sha256
Hash: 8d969eef6ecad3c29a3a873fba6d65e65a847f2427f19dd4a05f65eca8e0bb01
```

Supported algorithms: `md5`, `sha1`, `sha256`

---

### 2. Dictionary Attack

Cracks a hash by checking words from a wordlist file.

First, create a hash:
```bash
python password_cracker.py hash -p "password" -a sha256
```

Then crack it:
```bash
python password_cracker.py crack -H "5e884898da28047151d0e56f8dc62927acdb8aab2c6b899ae4a06d1df849f33f" -d wordlist.txt
```

The algorithm is automatically detected from the hash length. You can also specify it manually:
```bash
python password_cracker.py crack -H "5e884898da28047151d0e56f8dc62927acdb8aab2c6b899ae4a06d1df849f33f" -a sha256 -d wordlist.txt
```

---

### 3. Brute-Force Attack

Tries all possible character combinations up to a maximum length.
(Default max length is to be set in `configuration.py`.)

```bash
python password_cracker.py hash -p "abc" -a md5
```

Crack it with brute-force:
```bash
python password_cracker.py crack -H "900150983cd24fb0d6963f7d28e17f72" -b
```


---

### 4. Hybrid Attack

Tries dictionary words with mutations. Mutations include:
- Capitalization (ex. password, Password, PASSWORD)
- Character substitutions (ex. a→@, e→3, s→$)
- Numbers appended (ex. password1, password2024)
- Special characters appended (ex. password!, password@)

```bash
python password_cracker.py crack -H "target_hash_here" -hy wordlist.txt
```

---

## Configuration

Edit `configuration.py` to change:
- `MAX_BRUTE_FORCE_LENGTH`: Maximum password length to try in brute-force attacks
- `DEFAULT_CHARSET`: Characters used in brute-force 
- `ALLOWED_HASH_ALGORITHMS`: Which hash algorithms are allowed

---

## Hash Length Detection

When you don't specify an algorithm, it's detected from the hash length:
- **32 characters** → MD5
- **40 characters** → SHA-1
- **64 characters** → SHA-256

These are the only schemes we are covering in our project

---

## Files

- `password_cracker.py` - Main entry point, handles command-line arguments
- `hash_utils.py` - Hashing functions
- `dictionary_attack.py` - Dictionary attack implementation
- `brute_force_attack.py` - Brute-force attack implementation
- `hybrid_attack.py` - Hybrid attack implementation
- `multiprocessing_utils.py` - Multiprocessing setup and utilities
- `configuration.py` - Configuration settings

---

## How It Works

All attacks use Python's `multiprocessing` to split work across multiple CPU cores, making them run faster. The code keeps track of how many passwords were tried and how long the attack took. Once a password is found a flag is set and the search stops. 