"""
Basic skeleton of a mitmproxy addon.

Run as follows:
mitmweb.exe -s .\addons\ht_sit_cc_Front_and_Mitm.py --listen-port 8081 --web-port 8082 --mode upstream:http://127.0.0.1:8080 -k
"""
import re
import base64

from mitmproxy import ctx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def AES_decrypte(cipher_string=''):
    # 将 密钥&明文 转化为 bytes 格式 ; utf-8/hex/base64 --> bytes
    key = 'snHIYx2GtEmWnKMp6xd6ndpKNzF27vsb'.encode()
    cipher_bytes = bytes.fromhex(cipher_string)

    # 初始化AES加密器和解密器
    cipher = AES.new(key, AES.MODE_ECB)

    # 解密数据
    plain_string = unpad(cipher.decrypt(cipher_bytes), AES.block_size).decode()

    return plain_string


def AES_encrypt(plain_string=''):
    # 将 密钥&明文 转化为 bytes 格式 ; utf-8/hex/base64 --> bytes
    key = 'snHIYx2GtEmWnKMp6xd6ndpKNzF27vsb'.encode()
    plain_bytes = plain_string.encode()

    # 初始化AES加密器和解密器
    cipher = AES.new(key, AES.MODE_ECB)

    # 加密数据
    cipher_string = bytes.hex(base64.b64encode(cipher.encrypt(pad(plain_bytes, AES.block_size))))

    return cipher_string


def resp_decode(cipher_string=''):
    plain_string = bytes.fromhex(cipher_string).decode()
    return plain_string[:-16]


def resp_encode(plain_string=''):
    cipher_string = bytes.hex((plain_string + '').encode())
    return cipher_string


class Front_and_Mitm:
    def __init__(self):
        # 标识头
        self.mark_header = 'Vvak4'
        # 请求包设置
        self.request_judge_keyword = ''
        self.request_regex = r'(\w+)'
        # 响应包设置
        self.response_template = ''

    def request(self, flow):
        try:
            # step1：判断请求报文是否需要解密
            request_body = flow.request.text
            if self.request_judge_keyword not in request_body:
                ctx.log.error(
                    f"未在流向中端的 {flow.request.pretty_url} 请求数据包中匹配到特征关键字 {self.request_judge_keyword},故选择pass")
                return

            # step2：匹配报文中的密文
            if not re.search(self.request_regex, request_body):
                ctx.log.error(
                    f"在流向中端的 {flow.request.pretty_url} 请求数据包中匹配到特征关键字 {self.request_judge_keyword},但是未匹配出需要解密的密文,故选择pass")
                return
            cipher_text = re.search(pattern=self.request_regex, string=request_body).group(1)
            ctx.log.info(f"匹配到需要解密的请求数据包内容：\n{cipher_text}")

            # step3：解密密文 =》 明文
            plain_text = AES_decrypte(cipher_text)
            ctx.log.info(f"请求数据包解密得到的明文内容：\n{plain_text}")

            # step4：重构请求数据包body 替换成明文请求数据包
            flow.request.text = plain_text

            # step5：添加修改标识header
            flow.request.headers[self.mark_header] = ''

        except Exception as e:
            ctx.log.info(e)

    def response(self, flow):
        try:
            # step1：判断响应报文是否存在表示头，需要加密
            if self.mark_header not in flow.response.headers.keys():
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


# listen-port 8081 web-port 8082
addons = [
    Front_and_Mitm()
]
