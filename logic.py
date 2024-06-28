# logic.py
import hashlib

def hash_password(password: str, algorithm: str) -> str:
    """
    Hash the given password using the specified algorithm.

    :param password: Password to be hashed.
    :param algorithm: Hashing algorithm to be used (e.g., 'sha256', 'sha512').
    :return: Hexadecimal representation of the hashed password.
    """
    hash_func = hashlib.new(algorithm)
    hash_func.update(password.encode('utf-8'))
    return hash_func.hexdigest()
