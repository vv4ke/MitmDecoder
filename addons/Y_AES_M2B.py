"""
Basic skeleton of a mitmproxy addon.

Run as follows:
mitmdump.exe -s .\addons\PY_AES_M2B.py --listen-port 8082
"""
import re
import base64

from mitmproxy import ctx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from urllib.parse import unquote, quote


def AES_decrypte(cipher_string=''):
    """
    AES 解密函数
    :param cipher_string:
    :return:
    """
    # 将 密钥&明文 转化为 bytes 格式 ; utf-8/hex/base64 --> bytes
    key = 'keykeykeykeykeykeykeykeykeykeyke'.encode()
    iv = 'iviviviviviviviv'.encode()
    # cipher_bytes = bytes.fromhex(cipher_string)
    cipher_bytes = base64.b64decode(cipher_string)

    # 初始化AES加密器和解密器
    cipher = AES.new(mode=AES.MODE_CBC, key=key, iv=iv)

    # 解密数据
    plain_string = unpad(cipher.decrypt(cipher_bytes), AES.block_size).decode()

    return plain_string


def AES_encrypt(plain_string=''):
    # 将 密钥&明文 转化为 bytes 格式 ; utf-8/hex/base64 --> bytes
    key = 'keykeykeykeykeykeykeykeykeykeyke'.encode()
    iv = 'iviviviviviviviv'.encode()
    plain_bytes = plain_string.encode()

    # 初始化AES加密器和解密器
    cipher = AES.new(mode=AES.MODE_CBC, key=key, iv=iv)

    # 加密数据
    # cipher_string = bytes.hex(cipher.encrypt(pad(plain_bytes, AES.block_size)))
    cipher_string = base64.b64encode(cipher.encrypt(pad(plain_bytes, AES.block_size))).decode()

    return cipher_string


class Mitm_and_Backend:
    def __init__(self):
        # 标识头设置
        self.mark_header = 'Vvak4'
        # 请求包设置
        self.request_template = '{"Vvak4":"%s"}'
        self.host_name = ['Vvak4.com']
        # 响应包设置
        self.response_judge_keyword = 'Vvak4'
        self.regex_response = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'

    def request(self, flow):
        try:
            # step1：获取到要加密的明文
            if flow.request.host not in self.host_name:
                ctx.log.error(f"{flow.request.host} 不在host名单内。")
                return
            elif flow.request.headers[self.mark_header] == '0':
                plain_text = flow.request.text
                ctx.log.info(f"从 POST 请求体中获取到需要加密的请求数据包内容：\n{plain_text}")

            elif flow.request.headers[self.mark_header] == '1':
                plain_text = flow.request.query[self.response_judge_keyword]
                ctx.log.info(f"从 GET 请求体中获取到需要加密的请求数据包内容：\n{plain_text}")
            else:
                ctx.log.error(f"未在流向后端的请求数据包 {flow.request.pretty_url}中，匹配到明文，故pass")
                return

            # step3：加密明文 =》密文
            cipher_text = AES_encrypt(unquote(plain_text))
            ctx.log.info(f"请求数据包加密后的内容：\n{cipher_text}")

            # step4：根据模板重构请求报文,替换成密文/签名
            if flow.request.headers[self.mark_header] == '0':
                flow.request.text = self.request_template % cipher_text
            else:
                # print(flow.request.url.replace(quote(plain_text), cipher_text))
                flow.request.url = flow.request.url.replace(quote(plain_text), cipher_text)

            # step5：删除标识头
            flow.request.headers.pop(self.mark_header)

        except Exception as e:
            ctx.log.info(e)

    def response(self, flow):
        try:
            # step1：判断响应报文是否须解密
            response_body = flow.response.text
            double_quotation_marks = False

            # step2：匹配报文中的密文
            if flow.request.host not in self.host_name:
                ctx.log.error(f"{flow.request.host} 不在host名单内。")
                return
            elif response_body.startswith('"') and response_body.endswith('"'):
                double_quotation_marks = True
                cipher_text = response_body[1:-1]

            elif re.search(self.regex_response,response_body):
                cipher_text =response_body

            else:
                ctx.log.error(f"未在流向中端的 {flow.request.pretty_url} 请求数据包中匹配到密文字")
                return

            ctx.log.info(f"匹配到需要解密的响应数据包内容：\n{cipher_text}")

            # step3：解密密文 =》 明文
            plain_text = AES_decrypte(cipher_text)
            ctx.log.info(f"响应数据包解密得到的明文内容：\n{plain_text}")

            # step4：重构响应数据包，替换密文成明文
            flow.response.text = plain_text

            # step5：添加修改标识header
            if double_quotation_marks:
                flow.response.headers[self.mark_header] = '1'
            else:
                flow.response.headers[self.mark_header] = '0'

        except Exception as e:
            ctx.log.info(e)


# listen-port 8082
addons = [
    Mitm_and_Backend()
]
