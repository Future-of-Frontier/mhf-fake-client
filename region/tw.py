from .region import Region

class RegionTW(Region):
    def __init__(self):
        self.name = "tw"
        self.serverlist_url = "http://mhf-n.capcom.com.tw/server/serverlist.xml"
        self.signin_req_type = "DSGN:100"
        self.msg_sys_login_request_version = 0x9