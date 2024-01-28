from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import binascii


def AES_decrypte(data=''):
    # hex 格式转为 bytes
    key = binascii.unhexlify('1d2d3d4d5d6d7d8d9d8d7d6d5d4d3d2d')

    # 初始化AES加密器和解密器
    cipher = AES.new(key, AES.MODE_ECB)

    # 要加密的数据,并且要求转化为 bytes类型
    # print(data)
    ciphertext = binascii.unhexlify(data)

    # 解密数据
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    # print("解密后的数据:", decrypted_data.decode())

    return decrypted_data


def AES_encrypt(plain_text=''):
    # hex 格式转为 bytes
    key = binascii.unhexlify('1d2d3d4d5d6d7d8d9d8d7d6d5d4d3d2d')

    # 初始化AES加密器和解密器
    cipher = AES.new(key, AES.MODE_ECB)

    # 要加密的数据,并且要求转化为 bytes类型
    # print(plain_text)
    plain_data = plain_text.encode()

    # 加密数据
    ciphertext = cipher.encrypt(pad(plain_data, AES.block_size)).hex()
    # print("加密后的数据:", ciphertext)

    return ciphertext


if __name__ == '__main__':
    cipher_text = 'e352298b41e0781923f98356b677e3e24973f0765ff4a77110de84a05ede5f94'
    print(cipher_text)

    plain_text = AES_decrypte(cipher_text)
    print(plain_text)

    cipher_text = AES_encrypt(plain_text)
    print(cipher_text)
