import tkinter as tk
from tkinter import simpledialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

def decrypt_data():
    password = simpledialog.askstring("Password", "Enter password:", show='*')
    if password == "Password":  # Ensure exact match, case-sensitive
        with open("log.txt", 'r') as f:
            encrypted_lines = f.readlines()
        
        key = b'PasswordPassword'  # Must match encryption key
        decrypted_text = ''
        
        for line in encrypted_lines:
            try:
                line = line.strip()
                iv = base64.b64decode(line)[:16]
                ct = base64.b64decode(line)[16:]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(ct), AES.block_size)
                decrypted_text += pt.decode()
            except Exception as e:
                decrypted_text += f"[Decryption Error: {str(e)}]\n"

        # Write decrypted text to file
        with open("decrypted_text.txt", 'w') as decrypted_file:
            decrypted_file.write(decrypted_text)

        messagebox.showinfo("Success", "Decryption completed. Check 'decrypted_text.txt' for results.")
    else:
        messagebox.showerror("Error", "Incorrect password")

# Main window
root = tk.Tk()
root.title("Log Decryptor")
root.geometry("500x250")  # Set initial size of the main window
root.resizable(False, False)  # Prevent resizing

# Center the button
button = tk.Button(root, text="Decrypt Log", command=decrypt_data)
button.pack(expand=True)

# Set icon if you have one
# root.iconbitmap('path_to_your_icon.ico')

root.mainloop()
