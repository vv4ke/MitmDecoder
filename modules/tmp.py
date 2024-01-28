from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# 生成随机的16字节密钥
key = b'123123'

# 初始化AES加密器和解密器
cipher = AES.new(key, AES.MODE_ECB)

# 要加密的数据
data = b'123123123'

# 加密数据
ciphertext = cipher.encrypt(pad(data, AES.block_size))
print("加密后的数据:", ciphertext)

# 解密数据
decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
print("解密后的数据:", decrypted_data.decode())
