"""
Basic skeleton of a mitmproxy addon.

Run as follows: mitmproxy -s anatomy.py
"""
from mitmproxy import ctx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import re
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


class Front_and_Mitm:
    def __init__(self):
        self.keywords_request = 'params'
        self.keywords_response = 'params'

        self.regex_request = r'\w{32,}'
        self.regex_response = r'\w{32,}'

    def request(self, flow):
        try:
            # step1：判断请求报文是否需要解密
            request_body = flow.request.text
            if self.keywords_request not in request_body:
                return

            # step2：匹配报文中的密文
            if not re.search(self.regex_request, request_body):
                ctx.log.info(f"pass {flow.request.pretty_url} without match CipherText")
                return
            cipher_text = re.search(pattern=self.regex_request, string=request_body).group()

            # step3：解密密文 =》 明文
            plain_text = AES_decrypte(cipher_text)

            # step4：替换密文成明文
            flow.request.text = plain_text
            print(flow.request.text)

        except Exception as e:
            ctx.log.info(e)

    def response(self, flow):
        try:
            # step1：判断响应报文是否须加密
            if self.keywords_response not in flow.response.text:
                return

            # step2：匹配报文中的明文
            if not re.search(self.regex_response, flow.response.text):
                ctx.log.info(f"pass {flow.response.text} without match PlainText")
                return
            plain_text = re.search(self.regex_response, flow.response.text).group()

            # step3：加密明文 =》 密文
            cipher_text = AES_encrypt(plain_text)

            # step5：替换 明文=>密文, 更换signature
            flow.response.text.replace(plain_text, cipher_text)

        except Exception as e:
            ctx.log.info(e)


class Mitm_and_Backend:
    def __init__(self):
        self.keywords_request = 'params'
        self.keywords_response = 'params'

        self.regex_request = r'\w{32,}'
        self.regex_response = r'\w{32,}'

    def request(self, flow):
        try:
            # step1：判断请求报文是否需要加密
            print(flow.request.text)
            if self.keywords_request not in flow.request.text:
                return

            # step2：匹配报文中的 明文/签名
            if not re.search(self.regex_request, flow.request.text):
                ctx.log.info(f"pass {flow.request.pretty_url} without match PlainText")
                return
            plain_text = re.search(self.regex_request, flow.request.text).group()

            # step3：加密明文 =》密文
            cipher_text = AES_encrypt(plain_text)

            # step5：替换 明文成密文, 签名
            flow.request.text.replace(plain_text, cipher_text)

        except Exception as e:
            ctx.log.info(e)

    def response(self, flow):
        try:
            # step1：判断响应报文是否须解密
            if self.keywords_response not in flow.response.text:
                return

            # step2：匹配报文中的密文
            if not re.search(self.regex_response, flow.response.text):
                ctx.log.info(f"pass {flow.response.text} without match CipherText")
                return
            cipher_text = re.search(self.regex_response, flow.response.text).group()

            # step3：解密密文 =》 明文
            plain_text = AES_decrypte(cipher_text)

            # step5：替换密文成明文
            flow.response.text.replace(cipher_text, plain_text)

        except Exception as e:
            ctx.log.info(e)


# listen-port 8081 web-port 8082
addons = [
    Front_and_Mitm()
]

