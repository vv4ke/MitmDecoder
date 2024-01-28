import re

from mitmproxy import ctx

class Counter:
    def __init__(self):
        self.keywords_request = 'params'
        self.keywords_response = 'params'

        self.regex_request = r'\w{32,}'
        self.regex_response = r'\w{32,}'

    def request(self, flow):
        ctx.log.info('params' in flow.request.text)
        cipher_text = re.search(pattern=self.regex_request, string=flow.request.text).group()
        plain_text = '1'

        flow.request.text = plain_text
        print(flow.request.text)



addons = [
    Counter()
]
