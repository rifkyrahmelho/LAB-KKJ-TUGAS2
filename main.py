from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# Fungsi untuk mengenkripsi pesan
def encrypt_message(message, key, mode):
    cipher = AES.new(key, mode)  # Menggunakan mode yang dipilih
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv if mode == AES.MODE_CBC else b''  # Hanya CBC yang membutuhkan IV
    return iv + ct_bytes  # Gabungkan IV dan ciphertext jika mode CBC

# Fungsi untuk mendekripsi pesan
def decrypt_message(ciphertext, key, mode):
    iv = ciphertext[:AES.block_size] if mode == AES.MODE_CBC else b''  # Ambil IV jika mode CBC
    ct = ciphertext[AES.block_size:]  # Ambil ciphertext
    cipher = AES.new(key, mode, iv) if iv else AES.new(key, mode)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# Fungsi untuk menampilkan hasil dengan format yang lebih menarik
def print_hex(message):
    return binascii.hexlify(message).decode('utf-8').upper()

# Menu utama
def main():
    print("Selamat datang di Program Kriptografi AES!")
    print("Pilih mode enkripsi:")
    print("1. CBC (Cipher Block Chaining)")
    print("2. ECB (Electronic Codebook)")

    mode_choice = input("Masukkan pilihan mode (1/2): ")
    
    if mode_choice == '1':
        mode = AES.MODE_CBC
    elif mode_choice == '2':
        mode = AES.MODE_ECB
    else:
        print("Pilihan tidak valid. Menggunakan mode CBC secara default.")
        mode = AES.MODE_CBC

    # Menghasilkan key acak (16 byte untuk AES-128)
    key = get_random_bytes(16)

    # Input pesan dari pengguna
    message = input("Masukkan pesan yang ingin dienkripsi: ")

    # Enkripsi pesan
    ciphertext = encrypt_message(message, key, mode)
    print(f"\nCiphertext (Hex): {print_hex(ciphertext)}")

    # Dekripsi pesan
    decrypted_message = decrypt_message(ciphertext, key, mode)
    print(f"\nPesan yang didekripsi: {decrypted_message}")

if __name__ == "__main__":
    main()
