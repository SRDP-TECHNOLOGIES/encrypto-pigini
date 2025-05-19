import tkinter as tk
from tkinter import messagebox
import subprocess
import sys
import random

try:
    import pyperclip
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyperclip"])
    import pyperclip

SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
SBOX_INV = [SBOX.index(x) for x in range(16)]
PBOX = [
    0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
    4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
    8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
]
PBOX_INV = [PBOX.index(x) for x in range(64)]
ROUND_KEYS = []

def generate_round_keys80(key):
    global ROUND_KEYS
    ROUND_KEYS = []
    for round_counter in range(32):
        ROUND_KEYS.append(key >> 16)
        key = ((key & (2**80 - 1)) << 61 | key >> 19) & (2**80 - 1)
        sbox_in = (key >> 76) & 0xF
        key = (key & ~(0xF << 76)) | (SBOX[sbox_in] << 76)
        key ^= round_counter << 15

def add_round_key(state, round_key):
    return state ^ round_key

def sbox_layer(state):
    return int(''.join(f"{SBOX[(state >> (4 * i)) & 0xF]:04b}" for i in reversed(range(16))), 2)

def sbox_layer_inv(state):
    return int(''.join(f"{SBOX_INV[(state >> (4 * i)) & 0xF]:04b}" for i in reversed(range(16))), 2)

def pbox_layer(state):
    bits = f"{state:064b}"
    return int(''.join(bits[PBOX[i]] for i in range(64)), 2)

def pbox_layer_inv(state):
    bits = f"{state:064b}"
    return int(''.join(bits[PBOX_INV[i]] for i in range(64)), 2)

def present_encrypt80(plain, key):
    generate_round_keys80(key)
    state = plain
    for i in range(31):
        state = add_round_key(state, ROUND_KEYS[i])
        state = sbox_layer(state)
        state = pbox_layer(state)
    return add_round_key(state, ROUND_KEYS[31])

def present_decrypt80(cipher, key):
    generate_round_keys80(key)
    state = add_round_key(cipher, ROUND_KEYS[31])
    for i in reversed(range(31)):
        state = pbox_layer_inv(state)
        state = sbox_layer_inv(state)
        state = add_round_key(state, ROUND_KEYS[i])
    return state

def pad_text_to_blocks(text):
    data = text.encode('utf-8')
    blocks = []
    for i in range(0, len(data), 8):
        block = data[i:i+8].ljust(8, b'\x00')
        blocks.append(int.from_bytes(block, 'big'))
    return blocks

def unpad_blocks_to_text(blocks):
    data = b''.join(b.to_bytes(8, 'big') for b in blocks)
    try:
        return data.rstrip(b'\x00').decode('utf-8')
    except:
        return data.hex()

def generate_random_key():
    return ''.join(random.choices('0123456789ABCDEF', k=20))

def enable_copy_paste(widget):
    widget.bind("<Control-c>", lambda e: widget.event_generate("<<Copy>>"))
    widget.bind("<Control-v>", lambda e: widget.event_generate("<<Paste>>"))
    widget.bind("<Control-x>", lambda e: widget.event_generate("<<Cut>>"))

class PresentCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Pig")

        for i in range(10):
            root.grid_rowconfigure(i, weight=1)
        root.grid_columnconfigure(1, weight=1)

        tk.Label(root, text="Text to Encrypt:").grid(row=0, column=0, sticky="nw", padx=10, pady=5)
        self.input_text = tk.Text(root, height=4, wrap="word")
        self.input_text.grid(row=0, column=1, sticky="nsew", padx=10, pady=5)
        enable_copy_paste(self.input_text)

        tk.Button(root, text="Paste to Encrypt", command=self.paste_to_encrypt).grid(row=0, column=2, sticky="n", padx=5, pady=5)

        tk.Label(root, text="Text to Decrypt (hex):").grid(row=1, column=0, sticky="nw", padx=10, pady=5)
        self.decrypt_text = tk.Text(root, height=4, wrap="word")
        self.decrypt_text.grid(row=1, column=1, sticky="nsew", padx=10, pady=5)
        enable_copy_paste(self.decrypt_text)

        tk.Button(root, text="Paste to Decrypt", command=self.paste_to_decrypt).grid(row=1, column=2, sticky="n", padx=5, pady=5)

        tk.Label(root, text="Key (hex, 80-bit):").grid(row=2, column=0, sticky="nw", padx=10, pady=5)
        self.key_entry = tk.Entry(root)
        self.key_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=5)
        enable_copy_paste(self.key_entry)

        key_button_frame = tk.Frame(root)
        key_button_frame.grid(row=3, column=1, sticky="e", padx=10)
        tk.Button(key_button_frame, text="Copy Key", command=self.copy_key).pack(side="right", padx=5)
        tk.Button(key_button_frame, text="Generate Key", command=self.generate_key).pack(side="right", padx=5)

        button_frame = tk.Frame(root)
        button_frame.grid(row=4, column=0, columnspan=2, pady=5)
        tk.Button(button_frame, text="Encrypt", command=self.encrypt).pack(side="left", padx=5)
        tk.Button(button_frame, text="Decrypt", command=self.decrypt).pack(side="left", padx=5)
        tk.Button(button_frame, text="Copy Result", command=self.copy_result).pack(side="left", padx=5)
        tk.Button(button_frame, text="Clear All", command=self.clear_all).pack(side="left", padx=5)

        tk.Label(root, text="Result:").grid(row=5, column=0, sticky="nw", padx=10)
        self.result_text = tk.Text(root, height=4, wrap="word")
        self.result_text.grid(row=5, column=1, sticky="nsew", padx=10, pady=5)
        self.result_text.configure(state='normal')
        enable_copy_paste(self.result_text)

        self.status = tk.Label(root, text="Ready", anchor="w")
        self.status.grid(row=6, column=0, columnspan=3, sticky="we", padx=10, pady=2)

    def paste_to_encrypt(self):
        self.input_text.insert(tk.END, pyperclip.paste())

    def paste_to_decrypt(self):
        self.decrypt_text.insert(tk.END, pyperclip.paste())

    def encrypt(self):
        text = self.input_text.get("1.0", tk.END).strip()
        key_hex = self.key_entry.get()
        try:
            blocks = pad_text_to_blocks(text)
            key = int(key_hex, 16)
            if key.bit_length() > 80:
                raise ValueError("Key is longer than 80 bits")
            encrypted_blocks = [present_encrypt80(b, key) for b in blocks]
            result = ''.join(f"{b:016X}" for b in encrypted_blocks)
            self.show_result(result)
            self.set_status("Encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            self.set_status("Encryption failed.")

    def decrypt(self):
        hex_text = self.decrypt_text.get("1.0", tk.END).strip()
        key_hex = self.key_entry.get()
        try:
            if len(hex_text) % 16 != 0:
                raise ValueError("Hex input length must be multiple of 16")
            blocks = [int(hex_text[i:i+16], 16) for i in range(0, len(hex_text), 16)]
            key = int(key_hex, 16)
            if key.bit_length() > 80:
                raise ValueError("Key is longer than 80 bits")
            decrypted_blocks = [present_decrypt80(b, key) for b in blocks]
            result = unpad_blocks_to_text(decrypted_blocks)
            self.show_result(result)
            self.set_status("Decrypted successfully.")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            self.set_status("Decryption failed.")

    def show_result(self, content):
        self.result_text.configure(state='normal')
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, content)
        self.result_text.configure(state='disabled')

    def copy_result(self):
        try:
            content = self.result_text.get("1.0", tk.END).strip()
            if content:
                pyperclip.copy(content)
                messagebox.showinfo("Copied", "Result copied to clipboard!")
                self.set_status("Result copied.")
        except Exception as e:
            messagebox.showerror("Clipboard Error", str(e))

    def copy_key(self):
        try:
            key = self.key_entry.get().strip()
            if key:
                pyperclip.copy(key)
                messagebox.showinfo("Copied", "Key copied to clipboard!")
                self.set_status("Key copied.")
        except Exception as e:
            messagebox.showerror("Clipboard Error", str(e))

    def generate_key(self):
        key = generate_random_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)
        self.set_status("Random key generated.")

    def clear_all(self):
        self.input_text.delete("1.0", tk.END)
        self.decrypt_text.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.result_text.configure(state='normal')
        self.result_text.delete("1.0", tk.END)
        self.result_text.configure(state='disabled')
        self.set_status("Cleared all fields.")

    def set_status(self, message):
        self.status.config(text=message)

if __name__ == '__main__':
    root = tk.Tk()
    app = PresentCipherApp(root)
    root.geometry("750x520")
    root.minsize(500, 400)
    root.mainloop()
