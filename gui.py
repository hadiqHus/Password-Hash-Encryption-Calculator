# gui.py
import tkinter as tk
from tkinter import ttk, messagebox
from functions import (
    hash_password, 
    generate_random_password, 
    check_password_strength, 
    save_hash_to_file, 
    load_hashes_from_file,
    compare_hash_function,
    copy_to_clipboard
)
from themes import themes

class PasswordHashGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Password Hash Encryption Calculator")
        self.geometry("1024x600")  # Adjust the window size to accommodate the sidebar
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        # Define custom styles
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TLabelFrame", background="#f0f0f0", font=("Arial", 10, "bold"))
        self.style.configure("TButton", background="#0078d7", foreground="#ffffff", font=("Arial", 10), padding=6)
        self.style.map("TButton",
                       background=[("active", "#005a9e")],
                       foreground=[("active", "#ffffff")])
        self.style.configure("TEntry", padding=5, font=("Arial", 10))
        self.style.configure("TCombobox", padding=5, font=("Arial", 10))

        self.theme_styles = themes

        # Create the GUI elements
        self.create_widgets()

        # Set the initial theme
        self.set_theme("Light")

        # Load hashes from file
        self.load_hashes_from_file()

    def create_widgets(self):
        # Create sidebar frame
        sidebar_frame = ttk.Frame(self, width=200, relief='raised')
        sidebar_frame.pack(side='left', fill='y')

        # Create main frame
        main_frame = ttk.Frame(self, padding="20 10 20 10")
        main_frame.pack(side='right', fill='both', expand=True)

        # Add sidebar buttons
        sidebar_buttons = [
            ("Save Hash", self.save_hash_to_file),
            ("Compare Hash", self.compare_hash),
            ("Generate Random Password", self.generate_random_password),
            ("Copy Hash to Clipboard", self.copy_to_clipboard),
            ("Clear Fields", self.clear_fields)
        ]

        for text, command in sidebar_buttons:
            btn = ttk.Button(sidebar_frame, text=text, command=command)
            btn.pack(fill='x', padx=10, pady=5)

        # Theme selection
        theme_frame = ttk.Frame(main_frame, padding="10 10 10 10")
        theme_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=10, pady=10)

        self.add_label(theme_frame, "Select Theme:", 0, 0)
        self.theme_combobox = ttk.Combobox(theme_frame, values=list(self.theme_styles.keys()), state="readonly", width=27)
        self.theme_combobox.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        self.theme_combobox.bind("<<ComboboxSelected>>", self.change_theme)

        # Password entry
        input_frame = ttk.Frame(main_frame, padding="10 10 10 10")
        input_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=10, pady=10)

        self.add_label(input_frame, "Enter Password:", 0, 0)
        self.password_entry = ttk.Entry(input_frame, show='*', width=30)
        self.password_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        self.add_label(input_frame, "Choose Algorithm:", 1, 0)
        algorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
        self.algorithm_combobox = ttk.Combobox(input_frame, values=algorithms, state="readonly", width=27)
        self.algorithm_combobox.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        self.calc_button = ttk.Button(input_frame, text="Calculate Hash", command=self.calculate_hash)
        self.calc_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

        # Hashed password result
        result_frame = ttk.Frame(main_frame, padding="10 10 10 10")
        result_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), padx=10, pady=10)

        self.add_label(result_frame, "Hashed Password:", 0, 0)
        self.result_var = tk.StringVar()
        self.result_entry = ttk.Entry(result_frame, textvariable=self.result_var, width=30, state='readonly')
        self.result_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        # Password strength
        self.add_label(result_frame, "Password Strength:", 1, 0)
        self.strength_bar = ttk.Progressbar(result_frame, orient="horizontal", length=200, mode="determinate")
        self.strength_bar.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        self.password_entry.bind("<KeyRelease>", self.update_password_strength)

        # Hash listbox
        listbox_frame = ttk.Frame(main_frame, padding="10 10 10 10")
        listbox_frame.grid(row=0, column=1, rowspan=3, padx=10, pady=10, sticky=(tk.N, tk.S, tk.E, tk.W))
        
        self.hash_listbox = tk.Listbox(listbox_frame, width=50, height=20, font=("Arial", 10))
        self.hash_listbox.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        self.hash_listbox.bind("<Double-Button-1>", self.on_hash_double_click)

        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=self.hash_listbox.yview)
        self.hash_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

    def add_label(self, parent, text, row, column):
        """Helper function to add a label to the grid."""
        label = ttk.Label(parent, text=text)
        label.grid(row=row, column=column, padx=10, pady=10, sticky="w")

    def change_theme(self, event):
        """Change the theme based on user selection."""
        selected_theme = self.theme_combobox.get()
        self.set_theme(selected_theme)

    def set_theme(self, theme_name):
        """Apply the selected theme to the GUI."""
        style = self.theme_styles[theme_name]
        self.configure(bg=style["bg"])
        
        s = ttk.Style()
        s.configure('TLabel', background=style["bg"], foreground=style["fg"])
        s.configure('TFrame', background=style["bg"])
        s.configure('TLabelFrame', background=style["bg"], foreground=style["fg"])
        s.configure('TEntry', fieldbackground=style["entry_bg"], foreground=style["entry_text_fg"])
        s.configure('TCombobox', fieldbackground=style["entry_bg"], foreground=style["entry_fg"], background=style["entry_bg"])
        s.configure('TButton', background=style["button_bg"], foreground=style["button_fg"], highlightthickness=0, borderwidth=1)
        s.configure('TProgressbar', troughcolor=style["entry_bg"], background=style["button_bg"])

        if theme_name == "Dark":
            self.calc_button.configure(style='Dark.TButton')
            s.configure('Dark.TButton', background=style["button_bg"], foreground=style["fg"], borderwidth=1)
        else:
            self.calc_button.configure(style='TButton')

    def calculate_hash(self):
        """Calculate the hash of the entered password using the selected algorithm."""
        password = self.password_entry.get()
        algorithm = self.algorithm_combobox.get()

        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return

        if not algorithm:
            messagebox.showerror("Error", "Please choose a hashing algorithm")
            return

        hashed_password = hash_password(password, algorithm)
        self.result_var.set(hashed_password)

    def save_hash_to_file(self):
        """Save the generated hash to a file."""
        hashed_password = self.result_var.get()
        if not hashed_password:
            messagebox.showerror("Error", "No hashed password to save")
            return

        try:
            save_hash_to_file(hashed_password)
            messagebox.showinfo("Success", "Hashed password saved to file")
            self.load_hashes_from_file()
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def compare_hash(self):
        """Compare the entered password with the selected hash."""
        plain_password = self.password_entry.get()
        hashed_password = self.result_var.get()
        algorithm = self.algorithm_combobox.get()

        # Check if the plain password is entered
        if not plain_password:
            messagebox.showerror("Error", "Please enter a password to compare.")
            return

        # Check if the hashed password is provided
        if not hashed_password:
            messagebox.showerror("Error", "Please calculate or select a hash to compare.")
            return

        # Check if an algorithm is selected
        if not algorithm:
            messagebox.showerror("Error", "Please choose a hashing algorithm.")
            return

        if compare_hash_function(plain_password, hashed_password, algorithm):
            messagebox.showinfo("Match", "The password matches the hash")
        else:
            messagebox.showinfo("No Match", "The password does not match the hash")

    def generate_random_password(self):
        """Generate a random password and insert it into the password entry field."""
        random_password = generate_random_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, random_password)

    def update_password_strength(self, event):
        """Update the password strength label as the user types."""
        password = self.password_entry.get()
        strength = check_password_strength(password)

        if strength == "Weak":
            self.strength_bar['value'] = 25
        elif strength == "Moderate":
            self.strength_bar['value'] = 50
        elif strength == "Strong":
            self.strength_bar['value'] = 75
        elif strength == "Very Strong":
            self.strength_bar['value'] = 100

    def copy_to_clipboard(self):
        """Copy the hashed password to the clipboard."""
        hashed_password = self.result_var.get()
        if not hashed_password:
            messagebox.showerror("Error", "No hashed password to copy")
            return

        copy_to_clipboard(self, hashed_password)
        messagebox.showinfo("Success", "Hashed password copied to clipboard")

    def clear_fields(self):
        """Clear the password entry and result fields."""
        self.password_entry.delete(0, tk.END)
        self.result_var.set("")
        self.strength_bar['value'] = 0

    def load_hashes_from_file(self):
        """Load hashes from the file and populate the listbox."""
        hashes = load_hashes_from_file()
        self.hash_listbox.delete(0, tk.END)
        for h in hashes:
            self.hash_listbox.insert(tk.END, h)

    def on_hash_double_click(self, event):
        """Handle double-click event on a hash in the listbox."""
        selected_index = self.hash_listbox.curselection()
        if not selected_index:
            return

        selected_hash = self.hash_listbox.get(selected_index)
        response = messagebox.askyesno("Compare Hash", f"Do you want to compare this hash?\n{selected_hash}")
        if response:
            self.result_var.set(selected_hash)
            self.compare_hash()

    def select_theme(self):
        """Select and change the theme."""
        selected_theme = self.theme_combobox.get()
        self.set_theme(selected_theme)

if __name__ == '__main__':
    app = PasswordHashGUI()
    app.mainloop()
