import tkinter as tk
from tkinter import ttk, messagebox
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

def calculate_hash():
    password = password_entry.get()
    algorithm = algorithm_combobox.get()

    if not password:
        messagebox.showerror("Error", "Please enter a password")
        return

    if not algorithm:
        messagebox.showerror("Error", "Please choose a hashing algorithm")
        return

    hashed_password = hash_password(password, algorithm)
    result_var.set(hashed_password)

# Create the main window
root = tk.Tk()
root.title("Password Hash Encryption Calculator")

# Create the GUI elements
tk.Label(root, text="Enter Password:").grid(row=0, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show='*', width=30)
password_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Choose Algorithm:").grid(row=1, column=0, padx=10, pady=10)
algorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
algorithm_combobox = ttk.Combobox(root, values=algorithms, state="readonly", width=27)
algorithm_combobox.grid(row=1, column=1, padx=10, pady=10)

tk.Button(root, text="Calculate Hash", command=calculate_hash).grid(row=2, column=0, columnspan=2, padx=10, pady=10)

tk.Label(root, text="Hashed Password:").grid(row=3, column=0, padx=10, pady=10)
result_var = tk.StringVar()
result_entry = tk.Entry(root, textvariable=result_var, width=30, state='readonly')
result_entry.grid(row=3, column=1, padx=10, pady=10)

# Start the main event loop
root.mainloop()
