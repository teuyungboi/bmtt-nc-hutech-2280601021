import hashlib

def calculate_sha256_hash(data):
    sha256_hash = hashlib.sha256(data.encode('utf-8'))  # Chuyển đổi độ dài dữ liệu thành bytes và cập nhật vào đối tượng hash
    return sha256_hash.hexdigest()  # Trả về biểu diễn hex chuỗi hash

data_to_hash = input("Nhập dữ liệu để hash (SHA-256): ")
hash_value = calculate_sha256_hash(data_to_hash)
print("GIÁ TRỊ HASH SHA-256:", hash_value)