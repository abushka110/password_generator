import tkinter as tk
from tkinter import ttk
import string
import secrets

def contains_upper(password: str) -> bool:
    """Checks whether a password contains uppercase characters"""
    return any(char.isupper() for char in password)

def contains_symbols(password: str) -> bool:
    """Checks whether a password contains symbols"""
    return any(char in string.punctuation for char in password)

def generate_password(length: int = 10, symbols: bool = True, uppercase: bool = True, numbers: bool = True):
    """Generates a password based on the users specifications"""
    combination = string.ascii_lowercase
    
    if symbols:
        combination += string.punctuation

    if uppercase:
        combination += string.ascii_uppercase

    if numbers:
        combination += string.digits
    
    combination_length = len(combination)
    new_password = ''.join(combination[secrets.randbelow(combination_length)] for _ in range(length))

    return new_password

def update_password():
    length = pass_length.get()
    symbols = include_symbols_var.get()
    uppercase = include_uppercase_var.get()
    numbers = include_numbers_var.get()
    new_password = generate_password(length, symbols, uppercase, numbers)
    password_var.set(new_password)

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(password_var.get())
    root.update()  # Keep the clipboard content after the app is closed

# Initialize the main window
root = tk.Tk()
root.title("Password Generator")
root.geometry("600x400")  # Adjust size as needed

# Create a frame inside the main window
frame = ttk.Frame(root)
frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.8, relheight=0.7)

# Password field
password_var = tk.StringVar()
password_var.set(generate_password())
password_field = ttk.Entry(frame, textvariable=password_var, font=("Helvetica", 14))
password_field.place(relwidth=1, relheight=0.25)

# Password length label
length_label = ttk.Label(frame, text="PASSWORD LENGTH")
length_label.place(relwidth=1, rely=0.25, relheight=0.3, y=frame.winfo_height() * 0.25)

# Password length slider and input field
pass_length = tk.IntVar(value=10)
length_slider = ttk.Scale(frame, from_=2, to_=100, orient=tk.HORIZONTAL, variable=pass_length, command=lambda _: length_entry_var.set(pass_length.get()))
length_slider.place(relwidth=0.875, relheight=0.3, rely=0.55)
length_entry_var = tk.StringVar(value='10')
length_entry = ttk.Entry(frame, textvariable=length_entry_var, width=5)
length_entry.place(relx=0.875, rely=0.55, relheight=0.3, anchor='w')
length_entry_var.trace_add("write", lambda *args: pass_length.set(int(length_entry_var.get())))

# Check buttons for options
include_uppercase_var = tk.BooleanVar(value=True)
include_symbols_var = tk.BooleanVar(value=True)
include_numbers_var = tk.BooleanVar(value=True)

uppercase_check = ttk.Checkbutton(frame, text="Uppercase", variable=include_uppercase_var)
uppercase_check.place(relwidth=1, rely=0.85, anchor='w')

symbols_check = ttk.Checkbutton(frame, text="Special signs", variable=include_symbols_var)
symbols_check.place(relwidth=1, rely=0.9, anchor='w')

numbers_check = ttk.Checkbutton(frame, text="Numbers", variable=include_numbers_var)
numbers_check.place(relwidth=1, rely=0.95, anchor='w')

# Generate button
generate_button = ttk.Button(frame, text="Generate", command=update_password)
generate_button.place(relwidth=1, rely=0.95, anchor='s')

# Copy button
copy_button = ttk.Button(frame, text="Copy", command=copy_to_clipboard)
copy_button.place(relwidth=1, rely=1, anchor='s')

root.mainloop()
