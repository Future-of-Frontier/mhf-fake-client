from net import *

import socket
import requests
from bs4 import BeautifulSoup


class Region(object):
    """Base class to implement shared functionality across regions.
    """
    def __init__(self):
        self.name = ""
        self.serverlist_url = ""
        self.signin_req_type = ""
        self.msg_sys_login_request_version = 0

    def serverlist_get_first(self):
        return self._serverlist_get_first(self.serverlist_url)

    def signin(self, host, port, username, skey):
        return self._signin(host, port, self.signin_req_type, username, skey)

    def _serverlist_get_first(self, url):
        resp = requests.get(url)
        s = BeautifulSoup(resp.content, features='html.parser')
        for item in s.select('server_groups > group'):
            if item.get('ip') != "" and item.get('port') != 0:
                return (item.get('ip'), item.get('port'))

    def _signin(self, host, port, req_type, username, skey):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        # 8 NULL bytes to init the connection.
        sock.sendall(bytearray(8))

        ps = PacketStreamContext(SocketFileWrapper(sock))

        # Build the signin packet data.
        body = SignInRequest.build(dict(
                    req_type=req_type,
                    id=username,
                    skey=skey,
                    unk=''
                ))


        # Send the packet.
        ps.make_and_send_packet(body)

        # Get the response and parse it.
        pkt = ps.read_packet()
        
        return SignInResp.parse(pkt.data)

