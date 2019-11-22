import socket
import struct
import sys
import io
import json
from net import *

from hexdump import hexdump
import requests
from bs4 import BeautifulSoup

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


def cog_jp_signin(host, port, username, skey):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # 8 NULL bytes to init the connection.
    sock.sendall(bytearray(8))

    ps = PacketStreamContext(SocketFileWrapper(sock))

    # Build the signin packet data.
    body = SignInRequest.build(dict(
                req_type='DLTSKEYSIGN:100',
                id=username,
                skey=skey,
                unk=''
            ))


    # Send the packet.
    ps.make_and_send_packet(body)

    # Get the response and parse it.
    pkt = ps.read_packet()
    return SignInResp.parse(pkt.data)

def cog_jp_read_entrance_server_list(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # 8 NULL bytes to init the connection.
    sock.sendall(bytearray(8))

    # Encrypted packet with 'ALL+\x00' body.
    ps = PacketStreamContext(SocketFileWrapper(sock))
    ps.make_and_send_packet(b'ALL+\x00')

    # Read the response
    pkt = ps.read_packet()

    # Read the two binary8 parts.
    stream = io.BytesIO(pkt.data)
    (server_info_header, server_info_bytes) = read_binary8_part(stream)
    (user_info_header, user_info_bytes) = read_binary8_part(stream)
    stream.close()

    # Start parsing the server info.
    si_size = ServerInfo.sizeof()
    ci_size = ChannelInfo.sizeof()
    si_stream = io.BytesIO(server_info_bytes)
    # Loop over the server info structs.
    print(server_info_header)
    for i in range(server_info_header.entry_count):
        si = ServerInfo.parse(si_stream.read(si_size))

        # Loop over the channel info structs.
        print("server #{}".format(i))
        print(si)
        print(si.unk_str.decode('shift_jis'))
        for j in range(si.channel_count):
            print("channel #{}".format(j))
            ci = ChannelInfo.parse(si_stream.read(ci_size))
            print(ci)

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

        (sign_host, sign_port) = cog_jp_serverlist_get_first()

        # Do the launcher login
        skey = cog_jp_login(username, password)
        print("Got SKEY: {}".format(skey))

        # Do the client "signin"
        signin_resp = cog_jp_signin(sign_host, int(sign_port), username, skey)
        print("Got sign in response:")
        print(signin_resp)

        # Get the entrance server info.
        (entrance_host, entrance_port) = signin_resp.entrance_servers[0].split('\x00')[0].split(':') # Split IP and port.
        print("Getting servers from entrance server: {}:{}".format(entrance_host, entrance_port))

        # Print the server list.
        cog_jp_read_entrance_server_list(entrance_host, int(entrance_port))


    elif len(sys.argv) >= 2 and sys.argv[1] == 'channel_test': # Grab JP channel listing and decrypt:
        # This doesn't require any authentication....
        cog_jp_read_entrance_server_list('106.185.74.61', 53310) # Should be gotten from the SignInResp.
