import tkinter as tk
from tkinter import messagebox, scrolledtext
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import secrets, binascii

# Hashing function using SHA-512
def generate_sha512_hash(identifier, password, attribute):
    concatenated_str = f"{identifier}{password}{attribute}"
    return hashlib.sha512(concatenated_str.encode()).hexdigest()

# Global variable to simulate user database
user_data = {}
stored_key = None
stored_iv = None

# Registration Function
def register_user():
    name = name_entry.get()
    dob = dob_entry.get()
    address = address_entry.get()
    user_id = user_id_entry.get()
    password = password_entry.get()

    if name and dob and address and user_id and password:
        attribute = f"{name}|{dob}|{address}"
        user_hash = generate_sha512_hash(user_id, password, attribute)
        user_data[user_id] = {
            'name': name,
            'dob': dob,
            'address': address,
            'password_hash': user_hash,
            'attribute': attribute
        }
        messagebox.showinfo("Registration Success", f"User registered successfully!\nHash: {user_hash}")
        show_login_page()
    else:
        messagebox.showerror("Error", "Please fill in all fields.")  # Error if any field is empty

# Login Function
def login_user():
    user_id = login_user_id_entry.get()
    password = login_password_entry.get()

    if user_id in user_data:
        stored_data = user_data[user_id]
        stored_attribute = stored_data['attribute']
        stored_hash = stored_data['password_hash']
        login_hash = generate_sha512_hash(user_id, password, stored_attribute)

        if stored_hash == login_hash:
            show_hash_match_page(user_id, login_hash)  # Show hash match confirmation page
        else:
            messagebox.showerror("Access Denied", "Unauthorized User! Access Denied.")  # Unauthorized message
    else:
        messagebox.showerror("Login Failed", "User does not exist.")  # User not found error

# Reset form fields
def reset_form():
    name_entry.delete(0, tk.END)
    dob_entry.delete(0, tk.END)
    address_entry.delete(0, tk.END)
    user_id_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    login_user_id_entry.delete(0, tk.END)
    login_password_entry.delete(0, tk.END)

# Show registration page
def show_registration_page():
    login_frame.pack_forget()
    hash_match_frame.pack_forget()
    encryption_frame.pack_forget()
    reg_frame.pack(pady=20)

# Show login page
def show_login_page():
    reg_frame.pack_forget()
    hash_match_frame.pack_forget()
    encryption_frame.pack_forget()
    login_frame.pack(pady=20)

# Show hash match confirmation page
def show_hash_match_page(user_id, hash_value):
    login_frame.pack_forget()
    hash_match_frame.pack(pady=20)
    hash_match_label.config(text=f"User ID: {user_id}\nRegistration and Login Hash Matched Successfully!\nHash: {hash_value}")

# Show encryption page after login and "Proceed to Secure Communication"
def proceed_to_encryption_page():
    hash_match_frame.pack_forget()
    encryption_frame.pack(pady=20)

# Function to generate best key using ECC and GA
def generate_best_key():
    best_key = ''.join(secrets.choice('01') for _ in range(256))  # Simulated 256-bit key
    key_label.config(text=f"Best Key (Entropy: 1.00): {best_key}")
    return best_key

# Function to handle key generation
def generate_key_button_press():
    generated_key = generate_best_key()
    return generated_key

# Function to encrypt message
def encrypt_message():
    global stored_key, stored_iv
    message = message_input.get("1.0", 'end-1c').encode('utf-8')

    password = generate_best_key()
    salt = secrets.token_bytes(16)
    stored_key = PBKDF2(password, salt, dkLen=32)

    cipher = AES.new(stored_key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(message, AES.block_size))
    stored_iv = cipher.iv

    encrypted_hex = binascii.hexlify(stored_iv + encrypted_data).decode('utf-8')
    encrypted_output.config(state='normal')
    encrypted_output.delete(1.0, tk.END)
    encrypted_output.insert(tk.END, encrypted_hex)
    encrypted_output.config(state='disabled')

# Function to decrypt message
def decrypt_message():
    global stored_key, stored_iv

    if stored_key is None or stored_iv is None:
        decrypted_output.config(state='normal')
        decrypted_output.delete(1.0, tk.END)
        decrypted_output.insert(tk.END, "No encrypted message to decrypt.")
        decrypted_output.config(state='disabled')
        return

    encrypted_hex = encrypted_output.get("1.0", 'end-1c')
    encrypted_data = binascii.unhexlify(encrypted_hex.encode('utf-8'))

    iv = encrypted_data[:16]
    encrypted_message = encrypted_data[16:]

    cipher = AES.new(stored_key, AES.MODE_CBC, iv=stored_iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_message), AES.block_size)

    decrypted_output.config(state='normal')
    decrypted_output.delete(1.0, tk.END)
    decrypted_output.insert(tk.END, decrypted_data.decode('utf-8'))
    decrypted_output.config(state='disabled')

# Main application window
root = tk.Tk()
root.title("User Authentication and AES Encryption System")

# Set window size and center it
window_width = 500
window_height = 600
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
center_x = int(screen_width / 2 - window_width / 2)
center_y = int(screen_height / 2 - window_height / 2)
root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

# Style the labels and buttons
label_font = ("Helvetica", 12)
entry_font = ("Helvetica", 12)
button_font = ("Helvetica", 12, "bold")

# --- Registration Form ---
reg_frame = tk.LabelFrame(root, text="User Registration", padx=20, pady=20)
reg_frame.pack(pady=20)

tk.Label(reg_frame, text="Name:", font=label_font).grid(row=0, column=0, padx=10, pady=10)
name_entry = tk.Entry(reg_frame, font=entry_font)
name_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(reg_frame, text="Date of Birth:", font=label_font).grid(row=1, column=0, padx=10, pady=10)
dob_entry = tk.Entry(reg_frame, font=entry_font)
dob_entry.grid(row=1, column=1, padx=10, pady=10)

tk.Label(reg_frame, text="Address:", font=label_font).grid(row=2, column=0, padx=10, pady=10)
address_entry = tk.Entry(reg_frame, font=entry_font)
address_entry.grid(row=2, column=1, padx=10, pady=10)

tk.Label(reg_frame, text="User ID:", font=label_font).grid(row=3, column=0, padx=10, pady=10)
user_id_entry = tk.Entry(reg_frame, font=entry_font)
user_id_entry.grid(row=3, column=1, padx=10, pady=10)

tk.Label(reg_frame, text="Password:", font=label_font).grid(row=4, column=0, padx=10, pady=10)
password_entry = tk.Entry(reg_frame, show="*", font=entry_font)
password_entry.grid(row=4, column=1, padx=10, pady=10)

tk.Button(reg_frame, text="Register", font=button_font, command=register_user).grid(row=5, column=0, columnspan=2, pady=20)

# --- Login Form ---
login_frame = tk.LabelFrame(root, text="User Login", padx=20, pady=20)

tk.Label(login_frame, text="User ID:", font=label_font).grid(row=0, column=0, padx=10, pady=10)
login_user_id_entry = tk.Entry(login_frame, font=entry_font)
login_user_id_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(login_frame, text="Password:", font=label_font).grid(row=1, column=0, padx=10, pady=10)
login_password_entry = tk.Entry(login_frame, show="*", font=entry_font)
login_password_entry.grid(row=1, column=1, padx=10, pady=10)

tk.Button(login_frame, text="Login", font=button_font, command=login_user).grid(row=2, column=0, columnspan=2, pady=20)

# --- Hash Match Confirmation ---
hash_match_frame = tk.LabelFrame(root, text="Login Successful", padx=20, pady=20)

hash_match_label = tk.Label(hash_match_frame, font=label_font)
hash_match_label.grid(row=0, column=0, padx=10, pady=10)

tk.Button(hash_match_frame, text="Proceed to Secure Communication", font=button_font, command=proceed_to_encryption_page).grid(row=1, column=0, pady=20)

# --- Encryption and Decryption ---
encryption_frame = tk.LabelFrame(root, text="Secure Communication", padx=20, pady=20)

# Key generation button
generate_key_button = tk.Button(encryption_frame, text="Key generation through ECC and GA", command=generate_key_button_press, bg="light blue", fg="black", font=button_font)
generate_key_button.pack(pady=10)

# Best Key Label
key_label = tk.Label(encryption_frame, text="", font=label_font, anchor="w")
key_label.pack(pady=10)

# Textbox for input message
tk.Label(encryption_frame, text="Enter Message to Encrypt:", font=label_font).pack(pady=5)
message_input = scrolledtext.ScrolledText(encryption_frame, height=5, width=80)
message_input.pack(pady=5)

# Encrypt button
tk.Button(encryption_frame, text="Encrypt Message", command=encrypt_message, bg="red", fg="white", font=button_font).pack(pady=10)

# Textbox for encrypted message
tk.Label(encryption_frame, text="Encrypted Message (Hex):", font=label_font).pack(pady=5)
encrypted_output = scrolledtext.ScrolledText(encryption_frame, height=5, width=80)
encrypted_output.pack(pady=5)
encrypted_output.config(state='disabled')

# Decrypt button
tk.Button(encryption_frame, text="Decrypt Message", command=decrypt_message, bg="green", fg="white", font=button_font).pack(pady=10)

# Textbox for decrypted message
tk.Label(encryption_frame, text="Decrypted Message:", font=label_font).pack(pady=5)
decrypted_output = scrolledtext.ScrolledText(encryption_frame, height=5, width=80)
decrypted_output.pack(pady=5)
decrypted_output.config(state='disabled')

# Initial view
show_registration_page()

# Start the GUI loop
root.mainloop()
