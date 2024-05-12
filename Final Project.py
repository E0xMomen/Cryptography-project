import tkinter as tk
from tkinter import scrolledtext, Text
import pyDes
import base64

# Define the alphabet
alphabet = "abcdefghijklmnopqrstuvwxyz"

# Fixed key for the monoalphabetic cipher
monoalphabetic_key = "qwertyuiopasdfghjklzxcvbnm"

def monoalphabetic_encrypt(plaintext, key):
    """
    Encrypts the plaintext using the monoalphabetic cipher with the given key.
    """
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            # Map the plaintext character to the corresponding key character
            index = alphabet.index(char.lower())
            if char.isupper():
                ciphertext += key[index].upper()
            else:
                ciphertext += key[index]
        else:
            # Leave non-alphabetic characters unchanged
            ciphertext += char
    return ciphertext

def monoalphabetic_decrypt(ciphertext, key):
    """
    Decrypts the ciphertext using the monoalphabetic cipher with the given key.
    """
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            # Map the ciphertext character to the corresponding plaintext character
            index = key.index(char.lower())
            if char.isupper():
                plaintext += alphabet[index].upper()
            else:
                plaintext += alphabet[index]
        else:
            # Leave non-alphabetic characters unchanged
            plaintext += char
    return plaintext

def vigenere_encrypt(plaintext, key):
    """
    Encrypts the plaintext using the Vigenère cipher with the given key.
    """
    ciphertext = ""
    key_length = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = alphabet.index(key[i % key_length].lower())
            if char.isupper():
                ciphertext += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                ciphertext += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        else:
            ciphertext += char
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    """
    Decrypts the ciphertext using the Vigenère cipher with the given key.
    """
    plaintext = ""
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = alphabet.index(key[i % key_length].lower())
            if char.isupper():
                plaintext += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                plaintext += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
        else:
            plaintext += char
    return plaintext

def des_encrypt(plaintext, key):
    """
    Encrypts the plaintext using the DES algorithm with the given key.
    """
    ob = pyDes.des(key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    encrypted_data = ob.encrypt(plaintext)
    return base64.b64encode(encrypted_data).decode('utf-8')

def des_decrypt(ciphertext, key):
    """
    Decrypts the ciphertext using the DES algorithm with the given key.
    """
    key_bytes = key.encode('utf-8')  # Encode key to bytes
    ob = pyDes.des(key_bytes, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    ciphertext_bytes = base64.b64decode(ciphertext)
    plaintext_bytes = ob.decrypt(ciphertext_bytes)
    return plaintext_bytes.decode('utf-8')  # Decode plaintext bytes to string

def encrypt_text():
    plaintext = input_text.get("1.0", "end-1c")
    if cipher_var.get() == 0:  # Monoalphabetic cipher
        encrypted_text = monoalphabetic_encrypt(plaintext, monoalphabetic_key)
    elif cipher_var.get() == 1:  # Vigenère cipher
        encrypted_text = vigenere_encrypt(plaintext, key_entry.get())
    else:  # DES encryption
        encrypted_text = des_encrypt(plaintext, des_key_entry.get())
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Ciphertext: " + encrypted_text)

def decrypt_text():
    ciphertext = input_text.get("1.0", "end-1c")
    if cipher_var.get() == 0:  # Monoalphabetic cipher
        decrypted_text = monoalphabetic_decrypt(ciphertext, monoalphabetic_key)
    elif cipher_var.get() == 1:  # Vigenère cipher
        decrypted_text = vigenere_decrypt(ciphertext, key_entry.get())
    else:  # DES decryption
        decrypted_text = des_decrypt(ciphertext, des_key_entry.get())
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Plaintext: " + decrypted_text)

# Create GUI window
root = tk.Tk()
root.title("Cipher Selection")

# Cipher Selection Radio Button
cipher_var = tk.IntVar()
monoalphabetic_radio = tk.Radiobutton(root, text="Monoalphabetic Cipher", variable=cipher_var, value=0)
monoalphabetic_radio.grid(row=0, column=0, padx=10, pady=5)
vigenere_radio = tk.Radiobutton(root, text="Vigenère Cipher", variable=cipher_var, value=1)
vigenere_radio.grid(row=0, column=1, padx=10, pady=5)
des_radio = tk.Radiobutton(root, text="DES Encryption", variable=cipher_var, value=2)
des_radio.grid(row=0, column=2, padx=10, pady=5)
cipher_var.set(0)  # Set default value to Monoalphabetic Cipher

# Input Text Area
input_text = scrolledtext.ScrolledText(root, width=50, height=10, wrap=tk.WORD)
input_text.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# Key Label and Entry for Vigenère Cipher
key_label = tk.Label(root, text="Vigenère Key:")
key_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
key_entry = tk.Entry(root)
key_entry.grid(row=2, column=1, padx=10, pady=5)

# Key Label and Entry for DES Encryption
des_key_label = tk.Label(root, text="DES Key:")
des_key_label.grid(row=3, column=0, padx=10, pady=5, sticky="e")
des_key_entry = tk.Entry(root)
des_key_entry.grid(row=3, column=1, padx=10, pady=5)

# Encrypt and Decrypt Buttons
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text)
encrypt_button.grid(row=4, column=0, padx=10, pady=5)
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text)
decrypt_button.grid(row=4, column=1, padx=10, pady=5)

# Output Text Area
output_text = Text(root, width=50, height=1)
output_text.grid(row=5, column=0, columnspan=3, padx=10, pady=5)

root.mainloop()
