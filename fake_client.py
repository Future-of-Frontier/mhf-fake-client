import socket
import struct
import sys
import io
import json
from net import *
from jp import *

from hexdump import hexdump


def do_login_test(host, port, login_token):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # DELETE ME
    host = '106.185.75.29'
    port = 54001

    sock.connect((host, port))

    # 8 NULL bytes to init the connection.
    sock.sendall(bytearray(8))

    ps = PacketStreamContext(SocketFileWrapper(sock))
    #ps._send_key_rot = 0
    ps._read_key_rot = 0

    body = MsgSysPing.build(dict(
        opcode=PacketID.MSG_SYS_PING,
        ack_handle=0x01FF0000,
    ))
    #body = b'\x00\x1C\x01\xFB\x04\x28\x00\x08\x35\x36\x31\x36\x32\x64\x30'

    print("made:")
    hexdump(body)


    # Send the packet.
    ps.make_and_send_packet(body, key_rot_delta=2)

    # Get the response and parse it.
    pkt = ps.read_packet()
    print("got:")
    hexdump(pkt.data)

    return

    """
    ############################################
    # Build the login packet data.
    body = MsgSysLoginRequest.build(dict(
        opcode=PacketID.MSG_SYS_LOGIN,
        ack_handle=0x01FF0001,
        unk_0=0x23B606F3,
        unk_1=0x04F2F327,
        unk_2=0x23B606F3,
        login_token=login_token,
    ))

    print("made:")
    hexdump(body)


    # Send the packet.
    ps.make_and_send_packet(body)
    sock.sendall(bytearray(b'\x00\x11\x00\x10'))

    # Get the response and parse it.
    pkt = ps.read_packet()
    print("got:")
    hexdump(pkt.data)

    # Get the response and parse it.
    pkt = ps.read_packet()
    print("got:")
    hexdump(pkt.data)
    """


def enum_quest_test(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # 8 NULL bytes to init the connection.
    sock.sendall(bytearray(8))

    ps = PacketStreamContext(SocketFileWrapper(sock))

    # Send the packet.
    ps.make_and_send_packet(bytearray(b'\x00\xA0\x01\xFE\x00\x05\x00\x08\x00\x04\x00\x53\x00\x00\x10'))
    ps._read_key_rot = 0

    # Get the response and parse it.
    pkt = ps.read_packet()
    print("got:")
    hexdump(pkt.data)

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
        if signin_resp.resp_code == 23:
            print("Region blocked at sign server.")
            sys.exit(1)

        print("Got sign in response:")
        print(signin_resp)


        # Get the entrance server info.
        (entrance_host, entrance_port) = signin_resp.entrance_servers[0].split('\x00')[0].split(':') # Split IP and port.
        print("Getting servers from entrance server: {}:{}".format(entrance_host, entrance_port))

        # Print the server list.
        (server_list, entrance_ps) = cog_jp_read_entrance_server_list(entrance_host, int(entrance_port))

        """
        for (server, channels) in server_list:
            print(ip_string_from_uint32(server.host_ip_4byte))
            print(server.name.decode('shift_jis'))
        """

        # Just choose the first server and first channel for simplicity.
        (server, channels) = server_list[0]
        channel = channels[0]

        game_host = ip_string_from_uint32(server.host_ip_4byte)
        game_port = channel.port
        print("Connecting to game server {} @ {}:{}".format(server.name.decode('shift_jis'), game_host, game_port))

        do_login_test(game_host, game_port, signin_resp.login_token)
        


    elif len(sys.argv) >= 2 and sys.argv[1] == 'channel_test': # Grab JP channel listing and decrypt:
        # This doesn't require any authentication....
        server_list = cog_jp_read_entrance_server_list('106.185.74.61', 53310) # Should be gotten from the SignInResp.
        for (server, channels) in server_list:
            print(server.name.decode('shift_jis'))

    elif len(sys.argv) >= 2 and sys.argv[1] == 'quest_test':
        enum_quest_test('106.185.75.29', 54001)