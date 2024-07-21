"""
Basic skeleton of a mitmproxy addon.

Run as follows:
mitmdump.exe -s .\addons\PY_AES_F2M.py --listen-port 8081 --mode upstream:http://127.0.0.1:8080 -k
"""
import re
import base64

from mitmproxy import ctx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


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


class Front_and_Mitm:
    def __init__(self):
        # 标识头
        self.mark_header = 'vvak4'
        # 请求包设置
        self.host_name = ['vvak4.com']
        self.request_judge_keyword = 'vvak4'
        self.request_regex = r"{\"vvak4\":\"([a-zA-Z0-9+\/=]+)\""
        # 响应包设置
        self.response_template = '%s'

    def request(self, flow):
        try:
            # step1：判断请求报文是否需要解密
            request_body = flow.request.text
            request_template_type = '0'   # 默认post:0 get:1
            cipher_text = ''

            if flow.request.host not in self.host_name:
                ctx.log.error(
                    f"请求的 host: {flow.request.host} 不在名单内")
            elif self.request_judge_keyword in request_body:
                cipher_text = re.search(pattern=self.request_regex, string=request_body).group(1)
                ctx.log.info(f"在 POST 请求体中匹配到需要解密的请求数据包内容：\n{cipher_text}")
                request_template_type = '0'

            elif flow.request.query[self.request_judge_keyword]:
                cipher_text = flow.request.query[self.request_judge_keyword]
                ctx.log.info(f"在 GET 请求体匹配到需要解密的请求数据包内容：\n{cipher_text}")
                request_template_type = '1'

            else:
                return

            # step3：解密密文 =》 明文
            plain_text = AES_decrypte(cipher_text)
            ctx.log.info(f"请求数据包解密得到的明文内容：\n{plain_text}")

            # step4：重构请求数据包body 替换成明文请求数据包
            if request_template_type == '0':
                flow.request.text = plain_text
            else:
                # flow.request.query[self.request_judge_keyword] = quote(plain_text)
                flow.request.query[self.request_judge_keyword] = plain_text

            # step5：添加修改标识header
            flow.request.headers[self.mark_header] = request_template_type

        except Exception as e:
            ctx.log.info(e)

    def response(self, flow):
        try:
            # step1：判断响应报文是否存在表示头，需要加密
            if self.mark_header not in flow.response.headers.keys():
                ctx.log.error(f"未在流向前端的响应数据包中，识别到特征标识头 {self.mark_header}，故pass")
                return

            # step2：获取需加密的明文
            plain_text = flow.response.text
            ctx.log.info(f"需要加密的响应数据包内容：\n{plain_text}")

            # step3：加密明文 =》 密文
            cipher_text = AES_encrypt(plain_text)

            # step4：替换 明文=>密文, 更换signature
            if flow.response.headers[self.mark_header] == '1':
                flow.response.text = f'"{cipher_text}"'
            else:
                flow.response.text = cipher_text
            ctx.log.info(f"响应数据加密后的内容：\n{cipher_text}")

            # step5：删除标识头
            flow.response.headers.pop(self.mark_header)

        except Exception as e:
            ctx.log.info(e)


# listen-port 8081
addons = [
    Front_and_Mitm()
]

if __name__ == '__main__':
    cipher_text = 'x2yTzF/n7MqPIdc1Q5bd4g=='
    cipher_bytes = base64.b64decode(cipher_text)
    print(cipher_bytes)
    plain_text = AES_decrypte(cipher_text)
    print(plain_text)
    cipher_text_new = AES_encrypt(plain_text)
    print(cipher_text_new)
