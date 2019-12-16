import socket
import struct
import sys
import io
import os
import json
import time
import zlib
import argparse
from net import *
from region import *

from hexdump import hexdump

download_start_offset = 0

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
def do_login(ps, req_version, login_token, login_token_number, character_id):
    # Build the login packet data.
    handle = get_ack_handle()
    body = MsgSysLoginRequest.build(dict(
        opcode=PacketID.MSG_SYS_LOGIN,
        ack_handle=handle,
        char_id_0=character_id,
        login_token_number=login_token_number,
        hardcoded_req_version=req_version,
        char_id_1=character_id,
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

def do_get_file_scenario(ps, u0, u1, u2, u3):
    handle = get_ack_handle()
    body = MsgSysGetFile.build(dict(
        opcode=PacketID.MSG_SYS_GET_FILE,
        ack_handle=handle,
        is_scenario_file=1,
        filename_len=0,
        filename="",
        scenario_identifer=dict(
            unk_0=u0,
            unk_1=u1,
            unk_2=u2,
            unk_3=u3,
        )
    ))

    # Send the packet.
    ps.make_and_send_packet(body)
    
    # Read and verify the ACK handle.
    return read_until_expected_ack(ps, handle)


# Do a complete login process and return a PacketStreamContext for sending/receiving ingame packets.
# (launcher login -> sign server login -> entrance server -> game server)
def get_working_ingame_session(username, password, region_str):
    skey = None
    if region_str == 'jp':
        region = RegionJP()
        skey = region.cog_jp_login(username, password)
        print("Got SKEY: {}".format(skey))
    elif region_str == 'tw':
        region = RegionTW()

    # Do the client "signin"
    (sign_host, sign_port) = region.serverlist_get_first()
    signin_resp = region.signin(sign_host, int(sign_port), username, skey or password)
    if signin_resp.resp_code == 23:
        print("Region blocked at sign server.")
        sys.exit(1)

    #print("Got sign in response:")
    #print(signin_resp)

    # Get the entrance server info.
    (entrance_host, entrance_port) = signin_resp.entrance_servers[0].split('\x00')[0].split(':') # Split IP and port.
    print("Getting servers from entrance server: {}:{}".format(entrance_host, entrance_port))

    # Read the server list.
    (server_list, entrance_ps) = read_entrance_server_list(entrance_host, int(entrance_port))

    
    # Just choose the first server and first channel for simplicity.
    (server, channels) = server_list[0]
    channel = channels[0]
    
    
    """
    # Can't get into some servers?
    for (server, channels) in server_list:
        if region_str == 'jp':
            server_name = server.name.decode('shift_jis')
        elif region_str == 'tw':
            server_name = server.name.decode('big5')
        print(server_name)


        if '棘龍' in server_name or 'ビギニング' in server_name:
            print("Found server")
            server = server
            channel = channels[0]

            break
    """

    game_host = ip_string_from_uint32(server.host_ip_4byte)
    game_port = channel.port
    print("Connecting to game server {}:{}".format(game_host, game_port))

    # Finally connect to the ingame server, login, and download the file.
    character_id = signin_resp.characters[0].character_id
    print("Chosen character ID: {}".format(character_id))

    # Connect to the game server, ping, and login
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((game_host, game_port))

    ps = PacketStreamContext(SocketFileWrapper(sock))

    # Do a ping first, then login
    do_ping(ps)
    do_login(ps, region.msg_sys_login_request_version, signin_resp.login_token, signin_resp.login_token_number, character_id)
    print("Logged in?")

    return (sock, ps)


def cmd_download_file(username, password, region, filename):
    (sock, ps) = get_working_ingame_session(username, password, region)
    
    # HACK -- if the filename passed is "_ALL_", bruteforce all combos.
    if filename == '_ALL_':
        all_folder = 'download_all'
        try:
            os.makedirs(all_folder)
        except:
            pass

        global download_start_offset
        for i in range(download_start_offset, 99999+1):
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
            download_start_offset += 1
    else:
        # Download the file normally.
        get_file_resp = do_get_file(ps, filename)
        output_filename = 'download_{}.bin'.format(filename)
        with open(output_filename, 'wb') as f:
            f.write(get_file_resp.response_data)

        print("Downloaded {} as {}".format(filename, output_filename))

def cmd_download_scenarios(username, password, region):
    (sock, ps) = get_working_ingame_session(username, password, region)

    scenario_folder = 'download_scenario'
    try:
        os.makedirs(scenario_folder)
    except:
        pass

    global download_start_offset
    for category_id in range(download_start_offset, 8): # Ran the full 256 multiple times, nothing beyond 7.
        # No hard limit on the main ID, just go until it stops returning data for the next index.
        for main_id in range(0, 999999999):
            print("Checking {}_{}_0_1".format(category_id, main_id))
            
            # Check if the category_id and main_id are valid by getting it with the known-good u2=0, flags=1 values.
            get_file_resp = do_get_file_scenario(ps, category_id, main_id, 0, 1)
            if get_file_resp.response_data == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                break
            else:
                print("{}_{}_0_1 is valid, now iterating u2 values.".format(category_id, main_id))

            last_wrote_u2_response_data_crc32 = 0
            for u2 in range(0, 256):
                flags = 0xFF
                name = "{}_{}_{}_{}".format(category_id, main_id, u2, flags)
                print("\tTrying {}".format(name))

                # Try to get it and check if the response is an empty NULL*12:
                get_file_resp = do_get_file_scenario(ps, category_id, main_id, u2, flags)

                # Server starts repeating a generic response when the u2 value gets too high,
                # check the crc32 to the last and exit if its the same.
                this_crc32 = zlib.crc32(get_file_resp.response_data)

                if get_file_resp.response_data == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' or this_crc32 == last_wrote_u2_response_data_crc32:
                    break
                else:
                    print('\tGot {}'.format(name))
                    with open('{}\\{}.bin'.format(scenario_folder, name), 'wb') as f:
                        f.write(get_file_resp.response_data)
                    
                    last_wrote_u2_response_data_crc32 = this_crc32

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("command",
        choices=['bruteforce', 'download_file', 'download_scenarios'],
        help="Command to execute",
    )

    parser.add_argument('--username', help="Game username/id for login")
    parser.add_argument('--password', help="Game password for login")
    parser.add_argument('--region', choices=['jp', 'tw'])

    parser.add_argument('--filename', help="Filename to use for the `bruteforce` and `download_file` commands")
    parser.add_argument('--start_offset', help="Starting offset to use for the `download_file` and `download_scenarios` commands")

    args = parser.parse_args()
    #print(args.echo)

    def require_arg(args, arg):
        if getattr(args, arg) == None:
            print("--{} argument required for this command".format(arg))
            sys.exit(1)

    if args.start_offset != None:
        download_start_offset = int(args.start_offset)

    if args.command == 'bruteforce':
        require_arg(args, 'filename')
        with open(args.filename, 'rb') as f:
            ps = PacketStreamContext(f)
            pkt = ps.read_packet(bruteforce_encryption=True)
            print('Bruteforced output:')
            hexdump(pkt.data)

    elif args.command == 'download_file':
        require_arg(args, 'username')
        require_arg(args, 'password')
        require_arg(args, 'region')
        require_arg(args, 'filename')

        # If we are downloading all of them, download until completion,
        # restarting from the last saved position if an exception occurs.
        if args.filename == '_ALL_':
            while True:
                try:
                    cmd_download_file(args.username, args.password, args.region, args.filename)
                except Exception as e:
                    print(e)
                    continue
                
                break
        else:
            # Otherwise download the single file, don't care about exceptions.
            cmd_download_file(args.username, args.password, args.region, args.filename)

    elif args.command == 'download_scenarios':
        require_arg(args, 'username')
        require_arg(args, 'password')
        require_arg(args, 'region')
        cmd_download_scenarios(args.username, args.password, args.region)
    