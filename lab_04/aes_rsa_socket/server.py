from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# Khởi tạo server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)

# Tạo cặp khóa RSA
server_key = RSA.generate(2048)

clients = []  # Danh sách client kết nối

# Hàm mã hóa tin nhắn bằng AES
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))  # Chuyển str -> bytes
    return cipher.iv + ciphertext  # Trả về IV + ciphertext

# Hàm giải mã tin nhắn AES
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]  # Lấy IV từ đầu dữ liệu
    ciphertext = encrypted_message[AES.block_size:]  # Lấy phần mã hóa
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)  # Giải mã và bỏ padding
    return decrypted_message.decode()  # Chuyển bytes -> str

# Xử lý client
def handle_client(client_socket, client_address):
    print(f"🔗 Kết nối từ {client_address}")

    # Gửi khóa công khai của server cho client
    client_socket.send(server_key.publickey().exportKey(format='PEM'))

    # Nhận khóa công khai của client
    client_received_key = RSA.import_key(client_socket.recv(2048))

    # Tạo khóa AES ngẫu nhiên
    aes_key = get_random_bytes(16)

    # Mã hóa khóa AES bằng RSA của client
    cipher_rsa = PKCS1_OAEP.new(client_received_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    client_socket.send(encrypted_aes_key)  # Gửi khóa AES đã mã hóa

    # Thêm client vào danh sách
    clients.append((client_socket, aes_key))

    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break  # Nếu không có dữ liệu thì ngắt kết nối

            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print(f"📩 Nhận từ {client_address}: {decrypted_message}")

            # Gửi tin nhắn tới tất cả client khác
            for client, key in clients:
                if client != client_socket:
                    encrypted_response = encrypt_message(key, decrypted_message)
                    client.send(encrypted_response)

            if decrypted_message.lower() == "exit":
                break  # Nếu nhận "exit" thì đóng kết nối

        except Exception as e:
            print(f"⚠️ Lỗi từ {client_address}: {e}")
            break

    # Loại bỏ client và đóng socket
    clients.remove((client_socket, aes_key))
    client_socket.close()
    print(f"❌ Ngắt kết nối từ {client_address}")

# Chấp nhận và xử lý client
print("🚀 Server đang chạy trên cổng 12345...")
while True:
    client_socket, client_address = server_socket.accept()
    client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    client_thread.start()