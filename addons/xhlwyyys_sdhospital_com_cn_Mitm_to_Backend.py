"""
Basic skeleton of a mitmproxy addon.

Run as follows:
mitmweb.exe -s .\addons_jkgz_hn165_com_Mitm_and_Backend.py --listen-port 8083 --web-port 8084
"""
from mitmproxy import ctx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import re
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


class Mitm_and_Backend:
    def __init__(self):
        self.mark_header = 'vvak4'
        self.request_template = '{"encryption_data":"%s"}'

        self.regex_response = r'{\"encryption_response\":\"(.+)\"}'
        self.response_judge_keyword = 'encryption_response'

    def request(self, flow):
        try:
            # step1：判断请求报文是否需要加密
            if self.mark_header not in flow.request.headers.keys():
                ctx.log.error(f"未在流向后端的请求数据包 {flow.request.pretty_url}中，识别到特征标识头 {self.mark_header}，故pass")
                return

            # step2：匹配报文中的 明文/签名
            plain_text = flow.request.text
            ctx.log.info(f"需要加密的请求数据包内容：\n{plain_text}")

            # step3：加密明文 =》密文
            cipher_text = AES_encrypt(plain_text)
            ctx.log.info(f"请求数据包加密后的内容：\n{cipher_text}")

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
                ctx.log.error(f"未在流向中端的 {flow.request.pretty_url} 响应数据包中匹配到特征关键字 {self.response_judge_keyword},故选择pass")
                return

            # step2：匹配报文中的密文
            if not re.search(self.regex_response, response_body):
                ctx.log.error(f"在流向中端的 {flow.request.pretty_url} 请求数据包中匹配到特征关键字 {self.response_judge_keyword},但是未匹配出需要解密的密文,故选择pass")
                return
            cipher_text = re.search(self.regex_response, response_body).group(1)
            ctx.log.info(f"匹配到需要解密的响应数据包内容：\n{cipher_text}")

            # step3：解密密文 =》 明文
            plain_text = AES_decrypte(cipher_text)
            ctx.log.info(f"响应数据包解密得到的明文内容：\n{plain_text}")

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