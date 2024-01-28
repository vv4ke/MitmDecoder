from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import binascii


def demo1():

    # 密钥按照 16字节（128位、默认）、24字节（192位）或32字节（256位）进行填充，并且要求转化为 bytes类型
    digit = 16
    key = b'1d2d3d4d5d6d7d8d9d8d7d6d5d4d3d2d'
    key = b'123123' + b'\x00' * (digit - len(key))

    # 初始化AES加密器和解密器
    cipher = AES.new(key, AES.MODE_ECB)

    # 要加密的数据,并且要求转化为 bytes类型
    data = b'123123123'

    # 加密数据
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    print("加密后的数据:", ciphertext)

    # 解密数据
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    print("解密后的数据:", decrypted_data.decode())
    return


def demo2():
    # 密钥按照 16字节（128位、默认）、24字节（192位）或32字节（256位）进行填充，并且要求转化为 bytes类型
    # hex 格式转为 bytes
    key = binascii.unhexlify('1d2d3d4d5d6d7d8d9d8d7d6d5d4d3d2d')

    # 初始化AES加密器和解密器
    cipher = AES.new(key, AES.MODE_ECB)

    # 要加密的数据,并且要求转化为 bytes类型
    data = '32815db4b3d59e24b548dc036f6cc05e876d32cb6225c1a14eea0c2aa8a45734127778769caf3e3a4d33993fc60419b1b43ef14f018f93554bd331e74a14c57c1fae4fe99c92e8f45c925ffc3e1dcb85282baf29329b003c065f8f1d19b944b8023ef1a2bfded0b926959be9587e4e4d35d6aa7d36fb4f8483f1f3f95b3dfabef865435998e392c3ba94cfdb2bd92b42'
    print(data)
    ciphertext = binascii.unhexlify(data)

    # 解密数据
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    print("解密后的数据:", decrypted_data.decode())

    # 加密数据
    ciphertext = cipher.encrypt(pad(decrypted_data, AES.block_size))
    print("加密后的数据:", ciphertext.hex())

    return


if __name__ == '__main__':
    demo2()

