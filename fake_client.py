import socket
import struct
import sys
import io
import json
from net import *

from hexdump import hexdump
import requests
from bs4 import BeautifulSoup
from construct import *

def cog_jp_login(username, password):
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

def cog_jp_serverlist_get_first():
    resp = requests.get('http://srv-mhf.capcom-networks.jp/serverlist.xml')
    s = BeautifulSoup(resp.content, features='html.parser')
    for item in s.select('server_groups > group'):
        if item.get('ip') != "" and item.get('port') != 0:
            return (item.get('ip'), item.get('port'))


SignInResp = EmbeddedSwitch(
    Struct(
        "resp_code" / Byte,
    ),
    this.resp_code,
    {
        1: Struct(
            #"unk_0" / If(False, PaddedString(16, "utf8")), # Unknown condition.
            "unk_hostname_count" / Byte,
            "entrance_server_count" / Byte,
            "character_count" / Byte,
            "unk_0" / Int32ul,
            "str_id" / PaddedString(16, "utf8"),
            # "unk_3B74" / If(False, PascalString(Byte, "utf8")), # Unknown condition.
            "unk_3AE8" / Int32ul,
            "unk_hostnames" / Array(this.unk_hostname_count, PascalString(Byte, "utf8")),
            "entrance_servers" / Array(this.entrance_server_count, PascalString(Byte, "utf8")),
            "characters" / Array(this.character_count,
                Struct(
                    "unk_0" / Int32ul,
                    "unk_1" / Int16ul,
                    "unk_2" / Int16ul,
                    "unk_3" / Int32ul,
                    "unk_4" / Byte,
                    "unk_5" / Byte,
                    "unk_6" / Byte,
                    "unk_7" / Byte,
                    "unk_8" / PaddedString(16, "utf8"),
                    "unk_9" / PaddedString(32, "utf8"),
                    "unk_10" / If(this.unk_7 > 0, Struct(
                        "unk_0" / Int16ul,
                        "unk_1" / Byte,
                        "unk_2" / Byte,
                        )
                    ),
                )
            ),
            "unk_count_0" / Byte,
            "unk_count_extended_0" / If(this.unk_count_0 == 255, Int16ul),
            "unk_objs_0" / Array(this.unk_count_0 if this.unk_count_0 < 255 else this.unk_count_extended_0,
                Struct(
                    "unk_0" / Int32ul,
                    "unk_1" / Int32ul,
                    "unk_2" / PascalString(Byte, "ansi")
                )
            ),
            "unk_count_1" / Byte,
            "unk_substruct" / If(this.unk_count_1 == 0,
                Struct(
                    "unk_25A0" / Byte,
                    # Alot more here.
                )
            ),

            "unk_count_extended_1" / If(this.unk_count_1 == 255, Int16ul),
            "unk_objs_1" / Array(this.unk_count_1 if this.unk_count_1 < 255 else this.unk_count_extended_1,
                Struct(
                    "unk_0" / Int32ul,
                    "unk_1" / Int32ul,
                    "unk_2" / PascalString(Byte, "ansi")
                )
            ),


            ),
        17: Struct(),
    }
)

def cog_jp_signin(host, port, username, skey):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # 8 NULL bytes to init the connection.
    sock.sendall(bytearray(8))

    ps = PacketStreamContext(SocketFileWrapper(sock))

    # Build the signin packet data.
    body = bytearray()
    body.extend(b'DLTSKEYSIGN:100')
    body.extend(b'\x00')
    body.extend(username.encode('ansi'))
    body.extend(b'\x00')
    body.extend(skey.encode('ansi'))
    body.extend(b'\x00')
    body.extend(b'\x00')

    # Send the packet.
    ps.make_and_send_packet(body)

    # Get the resp.
    pkt = ps.read_packet()

    #hexdump(pkt.data)
    print(SignInResp.parse(pkt.data))



if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == 'bruteforce':
        with open(sys.argv[2], 'rb') as f:
            ps = PacketStreamContext(f)
            pkt = ps.read_packet(bruteforce_encryption=True)
            print('Bruteforced output:')
            hexdump(pkt.data)
    elif len(sys.argv) >= 4 and sys.argv[1] == 'cog':
        username = sys.argv[2]
        password = sys.argv[3]

        (host, port) = cog_jp_serverlist_get_first()

        # Do the launcher login
        skey = cog_jp_login(username, password)

        # Do the client "signin"
        cog_jp_signin(host, int(port), username, skey)


    elif len(sys.argv) >= 3 and sys.argv[1] == 'construct_test':
        with open(sys.argv[2], 'rb') as f:
            data = f.read()
            print(SignInResp.parse(data))

    elif len(sys.argv) >= 2 and sys.argv[1] == 'channel_test': # Grab JP channel listing and decrypt:
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('106.185.74.61', 53310)) # Should be gotten from the SignInResp.

        # 8 NULL bytes to init the connection.
        sock.sendall(bytearray(8))

        # Encrypted packet with 'ALL+\x00' body.
        ps = PacketStreamContext(SocketFileWrapper(sock))
        ps.make_and_send_packet(b'ALL+\x00')

        # Read the response
        pkt = ps.read_packet()

        # More crypto on crypto, ugh.
        hexdump(pkt.data)
