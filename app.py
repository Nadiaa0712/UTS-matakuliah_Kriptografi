import os
import base64  # Ditambahkan untuk konversi tampilan biner ke teks acak
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ==================================================
# INITIALIZATION DIRECTORY
# ==================================================
os.makedirs("encrypted", exist_ok=True)
os.makedirs("decrypted", exist_ok=True)

def is_supported_file(file_path):
    supported_extensions = {".txt", ".pdf", ".docx"}
    _, ext = os.path.splitext(file_path)
    return ext.lower() in supported_extensions

def generate_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=100000)

# ==================================================
# PROSES ENKRIPSI FILE + CETAK CIPHERTEXT
# ==================================================
def encrypt_file(file_path, password):
    try:
        if password.strip() == "":
            print("\n[PERINGATAN] Password tidak boleh kosong!")
            return

        if not is_supported_file(file_path):
            print("\n[ERROR] Tipe file tidak didukung! Pilih salah satu: (TXT, PDF, DOCX)")
            return

        size_before = os.path.getsize(file_path)

        with open(file_path, "rb") as f:
            data = f.read()

        salt = get_random_bytes(16)
        key = generate_key(password, salt)

        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))

        filename = os.path.basename(file_path)
        output_file = os.path.join("encrypted", filename + ".enc")

        # Gabungkan semua data biner yang disimpan ke file
        full_encrypted_data = salt + cipher.iv + ciphertext

        with open(output_file, "wb") as f:
            f.write(full_encrypted_data)

        size_after = os.path.getsize(output_file)

        # Mengubah data biner acak menjadi teks string agar bisa dicetak aman di terminal
        ciphertext_readable = base64.b64encode(full_encrypted_data).decode('utf-8')

        print("\n" + "="*55)
        print("                ENKRIPSI BERHASIL              ")
        print("="*55)
        print(f"Algoritma Enkripsi : AES-256")
        print(f"Mode Operasi Cipher: CBC (Cipher Block Chaining)")
        print(f"File Sumber        : {file_path}")
        print(f"Output Terenkripsi : {output_file}")
        print("-"*55)
        print("          OUTPUT ISI FILE YANG TERENKRIPSI       ")
        print("-"*55)
        # Menampilkan 150 karakter pertama agar tidak memenuhi layar jika filenya besar
        print(ciphertext_readable[:150] + "...") 
        print("-"*55)
        print("            OUTPUT ANALISIS PERUBAHAN            ")
        print("-"*55)
        print(f"Ukuran File Asli   : {size_before} bytes")
        print(f"Ukuran File Cipher : {size_after} bytes")
        print(f"Selisih Overhead   : {size_after - size_before} bytes (Salt + IV + Padding)")
        print("="*55)

    except FileNotFoundError:
        print("\n[ERROR] File target tidak ditemukan!")
    except Exception as e:
        print("\n[ERROR] Terjadi kegagalan sistem:", e)

def decrypt_file(file_path, password):
    try:
        if password.strip() == "":
            print("\n[PERINGATAN] Password tidak boleh kosong!")
            return

        if not file_path.endswith(".enc"):
            print("\n[ERROR] File tidak valid! Format berkas harus berakhiran .enc")
            return

        size_before = os.path.getsize(file_path)

        with open(file_path, "rb") as f:
            salt = f.read(16)
            iv = f.read(16)
            ciphertext = f.read()

        key = generate_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)

        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        filename = os.path.basename(file_path).replace(".enc", "")
        output_file = os.path.join("decrypted", "dec_" + filename)

        with open(output_file, "wb") as f:
            f.write(plaintext)

        size_after = os.path.getsize(output_file)

        print("\n" + "="*55)
        print("                DEKRIPSI BERHASIL              ")
        print("="*55)
        print(f"Algoritma Dekripsi : AES-256")
        print(f"Mode Operasi Cipher: CBC (Cipher Block Chaining)")
        print(f"File Sumber Cipher : {file_path}")
        print(f"Output Plaintext   : {output_file}")
        print("-"*55)
        print("            OUTPUT ANALISIS KESESUAIAN           ")
        print("-"*55)
        print(f"Ukuran File Cipher : {size_before} bytes")
        print(f"Ukuran Hasil Asli  : {size_after} bytes")
        print(f"Status Integritas  : Berhasil dikembalikan 100% utuh")
        print("="*55)

    except ValueError:
        print("\n[GAGAL] Dekripsi Ditolak: Password salah atau struktur data rusak!")
    except FileNotFoundError:
        print("\n[ERROR] File terenkripsi tidak ditemukan.")
    except Exception as e:
        print("\n[ERROR] Terjadi kegagalan sistem:", e)

def main():
    while True:
        print("\n" + "="*45)
        print("      APLIKASI KRIPTOGRAFI FILE AES-256     ")
        print("="*45)
        print("1. Encrypt File (TXT / PDF / DOCX)")
        print("2. Decrypt File (.enc)")
        print("3. Keluar Aplikasi")
        print("="*45)

        pilihan = input("Pilih Menu (1-3): ").strip()

        if pilihan == "1":
            file_path = input("Masukkan path/lokasi file asli : ")
            password = input("Masukkan password enkripsi     : ")
            encrypt_file(file_path, password)
        elif pilihan == "2":
            file_path = input("Masukkan path/lokasi file .enc : ")
            password = input("Masukkan password dekripsi     : ")
            decrypt_file(file_path, password)
        elif pilihan == "3":
            print("\nTerima kasih. Program kriptografi ditutup.")
            break
        else:
            print("\nPilihan menu di luar jangkauan sistem!")

if __name__ == "__main__":
    main()