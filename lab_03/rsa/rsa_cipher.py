import sys
import rsa
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui_rsa import Ui_MainWindow

# Thêm lớp RSAcipher vào main.py
class RSAcipher:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        """Tạo cặp khóa RSA mới."""
        (self.public_key, self.private_key) = rsa.newkeys(2048)

    def load_keys(self):
        """Tải cặp khóa RSA, nếu chưa có thì tạo mới."""
        if not self.public_key or not self.private_key:
            self.generate_keys()
        return self.public_key, self.private_key

    def encrypt(self, message, key):
        """Mã hóa một thông điệp bằng khóa được cung cấp."""
        return rsa.encrypt(message.encode('utf-8'), key)

    def decrypt(self, ciphertext, key):
        """Giải mã một thông điệp bằng khóa được cung cấp."""
        return rsa.decrypt(ciphertext, key).decode('utf-8')

    def sign(self, message, private_key):
        """Ký một thông điệp bằng khóa riêng."""
        return rsa.sign(message.encode('utf-8'), private_key, 'SHA-256')

    def verify(self, message, signature, public_key):
        """Xác minh chữ ký của một thông điệp bằng khóa công khai."""
        try:
            rsa.verify(message.encode('utf-8'), signature, public_key)
            return True
        except rsa.VerificationError:
            return False

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        # Khởi tạo đối tượng RSAcipher
        self.rsa_cipher = RSAcipher()

        # Ánh xạ các nút và trường nhập liệu từ ui_rsa.py
        self.ui.btn_gen_keys = self.ui.pushButton_5
        self.ui.btn_encrypt = self.ui.pushButton
        self.ui.btn_decrypt = self.ui.pushButton_2
        self.ui.btn_sign = self.ui.pushButton_4
        self.ui.btn_verify = self.ui.pushButton_3
        self.ui.txt_plain_text = self.ui.textEdit
        self.ui.txt_cipher_text = self.ui.textEdit_2
        self.ui.txt_info = self.ui.textEdit_3
        self.ui.txt_sign = self.ui.textEdit_4

        self.ui.btn_gen_keys.clicked.connect(self.call_api_gen_keys)
        self.ui.btn_encrypt.clicked.connect(self.call_api_encrypt)
        self.ui.btn_decrypt.clicked.connect(self.call_api_decrypt)
        self.ui.btn_sign.clicked.connect(self.call_api_sign)
        self.ui.btn_verify.clicked.connect(self.call_api_verify)

    def call_api_gen_keys(self):
        try:
            self.rsa_cipher.generate_keys()
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Information)
            msg.setText("Tạo khóa thành công")
            msg.exec_()
        except Exception as e:
            print("Lỗi khi tạo khóa: %s" % str(e))

    def call_api_encrypt(self):
        try:
            message = self.ui.txt_plain_text.toPlainText()
            public_key, _ = self.rsa_cipher.load_keys()
            encrypted_message = self.rsa_cipher.encrypt(message, public_key)
            encrypted_hex = encrypted_message.hex()
            self.ui.txt_cipher_text.setText(encrypted_hex)
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Information)
            msg.setText("Mã hóa thành công")
            msg.exec_()
        except Exception as e:
            print("Lỗi khi mã hóa: %s" % str(e))

    def call_api_decrypt(self):
        try:
            ciphertext_hex = self.ui.txt_cipher_text.toPlainText()
            ciphertext = bytes.fromhex(ciphertext_hex)
            _, private_key = self.rsa_cipher.load_keys()
            decrypted_message = self.rsa_cipher.decrypt(ciphertext, private_key)
            self.ui.txt_plain_text.setText(decrypted_message)
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Information)
            msg.setText("Giải mã thành công")
            msg.exec_()
        except Exception as e:
            print("Lỗi khi giải mã: %s" % str(e))

    def call_api_sign(self):
        try:
            message = self.ui.txt_info.toPlainText()
            _, private_key = self.rsa_cipher.load_keys()
            signature = self.rsa_cipher.sign(message, private_key)
            signature_hex = signature.hex()
            self.ui.txt_sign.setText(signature_hex)
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Information)
            msg.setText("Ký thành công")
            msg.exec_()
        except Exception as e:
            print("Lỗi khi ký: %s" % str(e))

    def call_api_verify(self):
        try:
            message = self.ui.txt_info.toPlainText()
            signature_hex = self.ui.txt_sign.toPlainText()
            signature = bytes.fromhex(signature_hex)
            public_key, _ = self.rsa_cipher.load_keys()
            is_verified = self.rsa_cipher.verify(message, signature, public_key)
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Information)
            if is_verified:
                msg.setText("Xác minh thành công")
            else:
                msg.setText("Xác minh thất bại")
            msg.exec_()
        except Exception as e:
            print("Lỗi khi xác minh: %s" % str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())