from app import encrypt_file, decrypt_file

if __name__ == '__main__':
    sample = 'data/pesan.txt'
    password = 'rahasia123'
    encrypt_file(sample, password)
    decrypt_file('encrypted/pesan.txt.enc', password)
