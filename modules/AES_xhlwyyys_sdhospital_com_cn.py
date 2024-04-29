from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import base64


def AES_decrypte(data=''):
    # utf-8 格式转为 bytes
    key = 'snHIYx2GtEmWnKMp6xd6ndpKNzF27vsb'.encode()

    # 初始化AES加密器和解密器
    cipher = AES.new(key, AES.MODE_ECB)

    # 要加密的数据,并且要求 base64 转化为 bytes类型
    # print(data)
    ciphertext = base64.b64decode(data)

    # 解密数据
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    # print("解密后的数据:", decrypted_data.decode())

    return decrypted_data


def AES_encrypt(plain_text=''):
    # hex 格式转为 bytes
    key = 'snHIYx2GtEmWnKMp6xd6ndpKNzF27vsb'.encode()

    # 初始化AES加密器和解密器
    cipher = AES.new(key, AES.MODE_ECB)

    # 要加密的数据,并且要求转化为 bytes类型
    # print(plain_text)
    plain_data = plain_text.encode()

    # 加密数据
    ciphertext = base64.b64encode(cipher.encrypt(pad(plain_data, AES.block_size))).decode()
    # print("加密后的数据:", ciphertext)

    return ciphertext


if __name__ == '__main__':
    cipher_text = 'CmSU13Zodx1f4VbNGPoS9w=='
    print(cipher_text)

    plain_text = AES_decrypte(cipher_text)
    print(plain_text)

    cipher_text = AES_encrypt(plain_text)
    print(cipher_text)
