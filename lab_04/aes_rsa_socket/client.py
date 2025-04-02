from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# Khởi tạo client socket và kết nối đến server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Tạo cặp khóa RSA cho client
client_key = RSA.generate(2048)

# Nhận khóa công khai của server
server_public_key = RSA.import_key(client_socket.recv(2048))

# Gửi khóa công khai của client đến server
client_socket.send(client_key.publickey().exportKey(format='PEM'))

# Nhận khóa AES đã mã hóa từ server
encrypted_aes_key = client_socket.recv(256)  # Đọc đúng kích thước RSA block

# Giải mã khóa AES bằng khóa private của client
cipher_rsa = PKCS1_OAEP.new(client_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

# Hàm mã hóa tin nhắn bằng AES
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# Hàm giải mã tin nhắn AES
def decrypt_message(key, encrypted_message):
    try:
        iv = encrypted_message[:AES.block_size]
        ciphertext = encrypted_message[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_message.decode()
    except Exception as e:
        print(f"⚠️ Lỗi giải mã: {e}")
        return None

# Hàm nhận tin nhắn từ server
def receive_messages():
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break  # Nếu mất kết nối thì thoát
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            if decrypted_message:
                print("📩 Tin nhắn nhận được:", decrypted_message)
        except Exception as e:
            print(f"⚠️ Lỗi khi nhận tin nhắn: {e}")
            break

# Khởi động luồng nhận tin nhắn
receive_thread = threading.Thread(target=receive_messages, daemon=True)
receive_thread.start()

# Vòng lặp gửi tin nhắn
while True:
    try:
        message = input("✉️ Nhập tin nhắn ('exit' để thoát): ")
        encrypted_message = encrypt_message(aes_key, message)
        client_socket.send(encrypted_message)

        if message.lower() == "exit":
            break  # Thoát vòng lặp nếu nhập 'exit'

    except Exception as e:
        print(f"⚠️ Lỗi khi gửi tin nhắn: {e}")
        break

# Đóng kết nối khi thoát
client_socket.close()
print("❌ Đã đóng kết nối.")