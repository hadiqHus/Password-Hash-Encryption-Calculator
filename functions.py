# functions.py
import hashlib
import string
import random
import os

def hash_password(password, algorithm):
    """Hash the password using the specified algorithm."""
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(password.encode('utf-8'))
    return hash_obj.hexdigest()

def generate_random_password(length=12):
    """Generate a random password of specified length."""
    characters = string.ascii_letters + string.digits + string.punctuation
    random_password = ''.join(random.choice(characters) for _ in range(length))
    return random_password

def check_password_strength(password):
    """Check the strength of the entered password."""
    if not password:
        return "Weak"
    
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    strength = length / 12
    strength += has_upper
    strength += has_lower
    strength += has_digit
    strength += has_special
    
    if strength < 2:
        return "Weak"
    elif strength < 4:
        return "Moderate"
    else:
        return "Strong"

def save_hash_to_file(hashed_password):
    """Save the generated hash to a file."""
    if not hashed_password:
        raise ValueError("No hashed password to save")

    with open("hashed_passwords.txt", "a") as file:
        file.write(f"{hashed_password}\n")

def load_hashes_from_file():
    """Load hashes from the file."""
    if not os.path.exists("hashed_passwords.txt"):
        return []

    with open("hashed_passwords.txt", "r") as file:
        hashes = [line.strip() for line in file]
    return hashes

def compare_hash_function(plain_password, hashed_password, algorithm):
    """Compare the entered password with the hashed password using the specified algorithm."""
    generated_hash = hash_password(plain_password, algorithm)
    return generated_hash == hashed_password

def copy_to_clipboard(root, text):
    """Copy the given text to the clipboard."""
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()  # Now it stays on the clipboard after the window is closed
