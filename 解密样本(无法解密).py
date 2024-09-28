from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from getpass import getpass

# 使用PBKDF2HMAC从密码生成密钥
def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# 使用AES-256对数据进行解密
def aes_256_decrypt(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    return unpadded_data

# 使用RSA解密AES密钥
def rsa_decrypt_aes_key(encrypted_aes_key, private_key):
    return private_key.decrypt(
        encrypted_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# 主函数
def main(fox_file_path):
    # 获取用户密码
    password = getpass("Enter password for decryption: ")
    
    # 读取.fox文件
    with open(fox_file_path, 'rb') as fox_file:
        # 读取盐值
        salt = fox_file.read(16)
        # 读取IV
        iv = fox_file.read(16)
        # 读取加密的AES密钥
        encrypted_aes_key = fox_file.read(256)  # 假设加密的
