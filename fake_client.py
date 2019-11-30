import socket
import struct
import sys
import io
import os
import json
import time
from net import *
from jp import *

from hexdump import hexdump

last_bruteforce_index = 0

# Helper function to make sequential ACK handle values for packets.
cur_ack_handle = 0x01FF0000
def get_ack_handle():
    global cur_ack_handle
    tmp = cur_ack_handle
    cur_ack_handle += 1
    return tmp

# Helper function to read until a MSG_SYS_ACK packet with an expected handle value. 
def read_until_expected_ack(ps, expected):
    while True:
        pkt = ps.read_packet()
        parsed = MsgHeader.parse(pkt.data)

        if parsed.opcode == PacketID.MSG_SYS_ACK:
            parsed = MsgSysAck.parse(pkt.data)
            if parsed.ack_handle == expected:
                return parsed

# Sends a MSG_SYS_PING and reads the response off the stream.
def do_ping(ps):
    handle = get_ack_handle()
    body = MsgSysPing.build(dict(
        opcode=PacketID.MSG_SYS_PING,
        ack_handle=handle,
    ))

    # Send the packet.
    ps.make_and_send_packet(body)

    # Read and verify the ACK handle.
    return read_until_expected_ack(ps, handle)


# Sends a MSG_SYS_LOGIN and reads the response off the stream.
def do_login(ps, login_token, login_token_number):
    # Build the login packet data.
    handle = get_ack_handle()
    body = MsgSysLoginRequest.build(dict(
        opcode=PacketID.MSG_SYS_LOGIN,
        ack_handle=handle,
        unk_0=0x23B606F3,
        unk_1=login_token_number,
        unk_2=0x23B606F3,
        login_token=login_token,
    ))

    # Send the packet.
    ps.make_and_send_packet(body)
    
    # Read and verify the ACK handle.
    return read_until_expected_ack(ps, handle)

def do_get_file(ps, filename):
    handle = get_ack_handle()
    body = MsgSysGetFile.build(dict(
        opcode=PacketID.MSG_SYS_GET_FILE,
        ack_handle=handle,
        is_scenario_file=0,
        filename_len=len(filename)+1,
        filename=filename.encode('utf8'),
    ))

    # Send the packet.
    ps.make_and_send_packet(body)
    
    # Read and verify the ACK handle.
    return read_until_expected_ack(ps, handle)

def connect_to_game_server_and_download_file(host, port, login_token, login_token_number, filename):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    ps = PacketStreamContext(SocketFileWrapper(sock))

    # Do a ping first.
    do_ping(ps)

    # Do the login.
    do_login(ps, login_token, login_token_number)

    # HACK -- if the filename passed is "_ALL_", bruteforce all combos.
    if filename == '_ALL_':
        all_folder = 'download_all'
        try:
            os.makedirs(all_folder)
        except:
            pass

        global last_bruteforce_index
        for i in range(last_bruteforce_index, 99999+1):
            print('\n\n')
            print('i is {}'.format(i))
            start = time.time()
            for j in ['d', 'n']:
                
                print("\tTrying {:05d}{} 0-9".format(i, j))
                for k in range(9+1):
                    name = '{:05d}{}{}'.format(i, j, k)
                    # Download the file normally.
                    get_file_resp = do_get_file(ps, name)
                    
                    #print("response data len:{}".format(len(get_file_resp.response_data)))
                    if len(get_file_resp.response_data) > 0:
                        with open('{}\\{}.bin'.format(all_folder, name), 'wb') as f:
                            f.write(get_file_resp.response_data)
                        print('\tGot {}'.format(name))
                    else:
                        # Got a zero-data response, likely not anything beyond this.
                        print("\tGot zero-length response, likely not anything beyond this for char ({}). Skipping.".format(j))
                        break

            end = time.time()
            print("Took {} seconds".format(end-start))
            last_bruteforce_index += 1
    else:
        # Download the file normally.
        get_file_resp = do_get_file(ps, filename)
        output_filename = 'download_{}.bin'.format(filename)
        with open(output_filename, 'wb') as f:
            f.write(get_file_resp.response_data)

        print("Downloaded {} as {}".format(filename, output_filename))

    #ps.make_and_send_packet(bytearray(b'\x00\xA0\x01\xFF\x00\x02\x00\x08\x00\x04\x00\x52\x00\x00\x10')) # Enum quest
    #ps.make_and_send_packet(bytearray(b'\x00\x1C\x01\xFF\x00\x02\x00\x08\x35\x36\x31\x36\x32\x64\x30')) # GetFile


def cmd_download_file(username, password, filename):
    (sign_host, sign_port) = cog_jp_serverlist_get_first()

    # Do the launcher login
    skey = cog_jp_login(username, password)
    print("Got SKEY: {}".format(skey))

    # Do the client "signin"
    signin_resp = cog_jp_signin(sign_host, int(sign_port), username, skey)
    if signin_resp.resp_code == 23:
        print("Region blocked at sign server.")
        sys.exit(1)

    #print("Got sign in response:")
    #print(signin_resp)

    # Get the entrance server info.
    (entrance_host, entrance_port) = signin_resp.entrance_servers[0].split('\x00')[0].split(':') # Split IP and port.
    print("Getting servers from entrance server: {}:{}".format(entrance_host, entrance_port))

    # Print the server list.
    (server_list, entrance_ps) = cog_jp_read_entrance_server_list(entrance_host, int(entrance_port))

    # Just choose the first server and first channel for simplicity.
    (server, channels) = server_list[0]
    channel = channels[0]

    game_host = ip_string_from_uint32(server.host_ip_4byte)
    game_port = channel.port
    print("Connecting to game server {}:{}, \"{}\"".format(game_host, game_port, server.name.decode('shift_jis')))

    # Finally connect to the ingame server, login, and download the file.
    connect_to_game_server_and_download_file(game_host, game_port, signin_resp.login_token, signin_resp.login_token_number, filename)

if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == 'bruteforce':
        with open(sys.argv[2], 'rb') as f:
            ps = PacketStreamContext(f)
            pkt = ps.read_packet(bruteforce_encryption=True)
            print('Bruteforced output:')
            hexdump(pkt.data)
    elif len(sys.argv) >= 5 and sys.argv[1] == 'download_file':
        username = sys.argv[2]
        password = sys.argv[3]
        filename = sys.argv[4]
        if len(sys.argv) >= 5:
            last_bruteforce_index = int(sys.argv[5])

        # If we are downloading all of them, download until completion,
        # restarting from the last saved position if an exception occurs.
        if sys.argv[4] == '_ALL_':
            while True:
                try:
                    cmd_download_file(username, password, filename)
                except Exception as e:
                    print(e)
                    continue
                
                break
        else:
            # Otherwise download the single file, don't care about exceptions.
            cmd_download_file(username, password, filename)
    elif len(sys.argv) >= 2 and sys.argv[1] == 'channel_test': # Grab JP channel listing and decrypt:
        # This doesn't require any authentication....
        server_list = cog_jp_read_entrance_server_list('106.185.74.61', 53310) # Should be gotten from the SignInResp.
        for (server, channels) in server_list:
            print(ip_string_from_uint32(server.host_ip_4byte))
            print(server.name.decode('shift_jis'))
    else:
        print("Invalid option argument.")