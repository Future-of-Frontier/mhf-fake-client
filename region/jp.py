from .region import Region
import json
import requests
from bs4 import BeautifulSoup

class RegionJP(Region):
    def __init__(self):
        self.name = "jp"
        self.serverlist_url = "http://srv-mhf.capcom-networks.jp/serverlist.xml"
        self.signin_req_type = "DLTSKEYSIGN:100"
        self.msg_sys_login_request_version = 0xB

    def cog_jp_login(self, username, password):
        url_base = 'https://www.capcom-onlinegames.jp/auth/launcher/'

        # Startup session and get cookies from the start page.
        sess = requests.Session()
        sess.get(url_base + 'start.html?q=711')

        # Post our login request
        data = {
            'id':username,
            'pw':password,
            'svid': 1000,
            'lifetime': 60,
            'fromURL': 'http://cog-members.mhf-z.jp',
        }
        resp = sess.post(url_base + 'login', data=data)

        # Parse the result.
        s = BeautifulSoup(resp.content, features='html.parser')
        login_result = json.loads(s.select('input')[0].get('value'))
        if login_result['code'] != '000':
            raise Exception('Error on cog jp login')

        return login_result['skey']