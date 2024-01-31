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
        self.request_judge_keyword = 'params'
        self.request_regex = r'\w{32,}'
        self.mark_header = 'Vvak4'

        self.response_template = '{"params":"%s"}'

    def request(self, flow):
        try:
            # step1：判断请求报文是否需要解密
            request_body = flow.request.text
            if self.request_judge_keyword not in request_body:
                return

            # step2：匹配报文中的密文
            if not re.search(self.request_regex, request_body):
                ctx.log.info(f"pass {flow.request.pretty_url} without match CipherText")
                return
            cipher_text = re.search(pattern=self.request_regex, string=request_body).group()

            # step3：解密密文 =》 明文
            plain_text = AES_decrypte(cipher_text)

            # step4：重构请求数据包body 替换成明文请求数据包
            flow.request.text = plain_text
            print(flow.request.text)

            # step5：添加修改标识header
            flow.request.headers[self.mark_header] = ''

        except Exception as e:
            ctx.log.info(e)

    def response(self, flow):
        try:
            # step1：判断响应报文是否存在表示头，需要加密
            if self.mark_header not in list(flow.response.headers):
                return

            # step2：获取需加密的明文
            plain_text = flow.response.text

            # step3：加密明文 =》 密文
            cipher_text = AES_encrypt(plain_text)

            # step4：替换 明文=>密文, 更换signature
            flow.response.text = self.response_template % cipher_text

            # step5：删除标识头
            flow.response.headers.pop(self.mark_header)

        except Exception as e:
            ctx.log.info(e)


class Mitm_and_Backend:
    def __init__(self):
        self.mark_header = 'Vvak4'
        self.request_template = '{"params":"%s"}'

        self.regex_response = r'\w{32,}'
        self.response_judge_keyword = 'params'

    def request(self, flow):
        try:
            # step1：判断请求报文是否需要加密
            if self.mark_header not in list(flow.request.headers):
                return

            # step2：匹配报文中的 明文/签名
            plain_text = flow.request.text

            # step3：加密明文 =》密文
            cipher_text = AES_encrypt(plain_text)

            # step4：根据模板重构请求报文,替换成密文/签名
            flow.request.text = self.request_template % cipher_text

            # step5：删除标识头
            flow.request.headers.pop(self.mark_header)

        except Exception as e:
            ctx.log.info(e)

    def response(self, flow):
        try:
            # step1：判断响应报文是否须解密
            response_body = flow.response.text
            if self.response_judge_keyword not in response_body:
                return

            # step2：匹配报文中的密文
            if not re.search(self.regex_response, response_body):
                ctx.log.info(f"pass {response_body} without match CipherText")
                return
            cipher_text = re.search(self.regex_response, response_body).group()

            # step3：解密密文 =》 明文
            plain_text = AES_decrypte(cipher_text)

            # step4：重构响应数据包，替换密文成明文
            flow.response.text = plain_text

            # step5：添加修改标识header
            flow.response.headers[self.mark_header] = ''

        except Exception as e:
            ctx.log.info(e)


# listen-port 8083 web-port 8084
addons = [
    Mitm_and_Backend()
]

