import hashlib

def left_rotate(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

def md5(message):
    # Khởi tạo các biến ban đầu
    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476

    # Tiến hành lưu chiều dài ban đầu (len(message))
    original_length = len(message) * 8  # Chuyển độ dài thành bit
    message += b'\x80'  # Thêm bit 1 vào cuối (padding)
    while len(message) % 64 != 56:  # Đệm thêm 0 để độ dài block = 512 bit - 64 bit
        message += b'\x00'
    # Thêm chiều dài ban đầu vào block cuối (64 bit)
    message += int.to_bytes(original_length, 8, 'little')

    # Chia chuỗi thành các block 512-bit (64 bytes)
    for i in range(0, len(message), 64):
        words = [int.from_bytes(message[j:j+4], 'little') for j in range(i, i+64, 4)]
        a0, b0, c0, d0 = a, b, c, d  # Lưu giá trị ban đầu của a, b, c, d

        # 4 vòng lặp chính, mỗi vòng 16 bước
        for j in range(64):
            if j < 16:
                f = (b & c) | ((~b) & d)
                g = j
            elif j < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * j + 1) % 16
            elif j < 48:
                f = b ^ c ^ d
                g = (3 * j + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * j) % 16

            temp = d
            d = c
            c = b
            b = b + left_rotate((a + f + 0x5A827999 + words[g]) & 0xFFFFFFFF, 3)
            a = temp

        # Cộng giá trị sau mỗi vòng vào a, b, c, d
        a = (a + a0) & 0xFFFFFFFF
        b = (b + b0) & 0xFFFFFFFF
        c = (c + c0) & 0xFFFFFFFF
        d = (d + d0) & 0xFFFFFFFF

    # Trả về giá trị băm dưới dạng hex
    return '{:08x}{:08x}{:08x}{:08x}'.format(a, b, c, d)

input_string = input("Nhập chuỗi cần băm: ")
md5_hash = md5(input_string.encode('utf-8'))
print("Mã băm MD5 của chuỗi '{}' là: {}".format(input_string, md5_hash))