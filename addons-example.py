"""
Basic skeleton of a mitmproxy addon.

Run as follows: mitmproxy -s anatomy.py
"""
import re

from mitmproxy import ctx
from modules.AES import decrypt, encrypt
from modules.MD5 import signature


class Front_and_Mitm:
    def __init__(self):
        self.keywords_request = ''
        self.keywords_response = ''

        self.regex_request = r''
        self.regex_response = r''

    def request(self, flow):
        try:
            # step1：判断请求报文是否需要解密
            if self.keywords_request not in flow.request.text:
                return

            # step2：匹配报文中的密文
            if not re.search(self.regex_request, flow.request.text):
                ctx.log.info(f"pass {flow.request.pretty_url} without match CipherText")
                return
            cipher_text = re.search(pattern=self.regex_request, string=flow.request.text).group()

            # step3：解密密文 =》 明文
            plain_text = decrypt(cipher_text)

            # step4：替换密文成明文
            flow.request.text.replace(cipher_text, plain_text)

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
            cipher_text = encrypt(plain_text)

            # step4：重新签名？
            # signature = self.signature()

            # step5：替换 明文=>密文, 更换signature
            flow.response.text.replace(plain_text, cipher_text)

        except Exception as e:
            ctx.log.info(e)


class Mitm_and_Backend:
    def __init__(self):
        self.keywords_request = ''
        self.keywords_response = ''

        self.regex_request = r''
        self.regex_response = r''
        self.regex_signature = r''

    def request(self, flow):
        try:
            # step1：判断请求报文是否需要加密
            if self.keywords_request not in flow.request.text:
                return

            # step2：匹配报文中的 明文/签名
            if not re.search(self.regex_request, flow.request.text):
                ctx.log.info(f"pass {flow.request.pretty_url} without match PlainText")
                return
            plain_text = re.search(self.regex_request, flow.request.text).group()
            old_signature = re.search(self.regex_signature, flow.request.text).group()

            # step3：加密明文 =》密文
            cipher_text = encrypt(plain_text)

            # step4：重新签名？
            new_signature = signature(param='')

            # step5：替换 明文成密文, 签名
            flow.request.text.replace(plain_text, cipher_text)
            flow.request.text.replace(old_signature, new_signature)

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
            plain_text = decrypt(cipher_text)

            # step5：替换密文成明文
            flow.response.text.replace(cipher_text, plain_text)

        except Exception as e:
            ctx.log.info(e)


addons = [
    Front_and_Mitm(),
    Mitm_and_Backend()
]

