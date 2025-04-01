from flask import Flask, request, jsonify
from rsa_cipher import RSAcipher

app = Flask(__name__)

# THUẬT TOÁN MÃ HÓA
rsa_cipher = RSAcipher()

@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    return jsonify({'message': 'Tạo khóa thành công'})

@app.route('/api/rsa/encrypt', methods=['POST'])
def rsa_encrypt():
    data = request.get_json()
    message = data['message']
    key_type = data['key_type']  # public_key | private_key
    public_key, private_key = rsa_cipher.load_keys()
    if key_type == 'public_key':
        key = public_key
    elif key_type == 'private_key':
        key = private_key
    else:
        return jsonify({'error': 'Loại khóa không hợp lệ'})

    encrypted_message = rsa_cipher.encrypt(message, key)
    encrypted_hex = encrypted_message.hex()
    return jsonify({'encrypted_message': encrypted_hex})

@app.route('/api/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    data = request.get_json()
    ciphertext_hex = data['ciphertext']
    key_type = data['key_type']  # public_key | private_key
    ciphertext = bytes.fromhex(ciphertext_hex)
    public_key, private_key = rsa_cipher.load_keys()
    if key_type == 'public_key':
        key = public_key
    elif key_type == 'private_key':
        key = private_key
    else:
        return jsonify({'error': 'Loại khóa không hợp lệ'})

    decrypted_message = rsa_cipher.decrypt(ciphertext, key)
    return jsonify({'decrypted_message': decrypted_message})

@app.route('/api/rsa/sign', methods=['POST'])
def rsa_sign():
    data = request.get_json()
    message = data['message']
    private_key = rsa_cipher.load_keys()[1]  # private_key
    signature = rsa_cipher.sign(message, private_key)
    signature_hex = signature.hex()
    return jsonify({'signature': signature_hex})

@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify():
    data = request.get_json()
    message = data['message']
    signature_hex = data['signature']
    signature = bytes.fromhex(signature_hex)
    public_key = rsa_cipher.load_keys()[0]  # public_key
    is_verified = rsa_cipher.verify(message, signature, public_key)
    return jsonify({'is_verified': is_verified})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)  # Thay 0.0.0.0 thành 127.0.0.1