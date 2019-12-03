import socket
import struct
import sys
import io
import os
import json
import time
import zlib
from net import *
from jp import *

from hexdump import hexdump

last_quest_bruteforce_index = 0
start_scenario_category_id = 0
start_scenario_main_id = 0
start_scenario_u2 = 0

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
def do_login(ps, login_token, login_token_number, character_id):
    # Build the login packet data.
    handle = get_ack_handle()
    body = MsgSysLoginRequest.build(dict(
        opcode=PacketID.MSG_SYS_LOGIN,
        ack_handle=handle,
        unk_0=character_id,
        unk_1=login_token_number,
        unk_2=character_id,
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


#ps.make_and_send_packet(bytearray(b'\x00\xA0\x01\xFF\x00\x02\x00\x08\x00\x04\x00\x52\x00\x00\x10')) # Enum quest
#ps.make_and_send_packet(bytearray(b'\x00\x1C\x01\xFF\x00\x02\x00\x08\x35\x36\x31\x36\x32\x64\x30')) # GetFile


# Do a complete login process and return a PacketStreamContext for sending/receiving ingame packets.
# (launcher login -> sign server login -> entrance server -> game server)
def get_working_ingame_session(username, password):
    # Do the launcher login
    skey = cog_jp_login(username, password)
    print("Got SKEY: {}".format(skey))

    # Do the client "signin"
    (sign_host, sign_port) = cog_jp_serverlist_get_first()
    signin_resp = cog_jp_signin(sign_host, int(sign_port), username, skey)
    if signin_resp.resp_code == 23:
        print("Region blocked at sign server.")
        sys.exit(1)

    #print("Got sign in response:")
    #print(signin_resp)

    # Get the entrance server info.
    (entrance_host, entrance_port) = signin_resp.entrance_servers[0].split('\x00')[0].split(':') # Split IP and port.
    print("Getting servers from entrance server: {}:{}".format(entrance_host, entrance_port))

    # Read the server list.
    (server_list, entrance_ps) = cog_jp_read_entrance_server_list(entrance_host, int(entrance_port))

    # Just choose the first server and first channel for simplicity.
    (server, channels) = server_list[0]
    channel = channels[0]

    game_host = ip_string_from_uint32(server.host_ip_4byte)
    game_port = channel.port
    print("Connecting to game server {}:{}, \"{}\"".format(game_host, game_port, server.name.decode('shift_jis')))

    # Finally connect to the ingame server, login, and download the file.
    character_id = signin_resp.characters[0].character_id
    print("Chosen character ID: {}".format(character_id))

    # Connect to the game server, ping, and login
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((game_host, game_port))

    ps = PacketStreamContext(SocketFileWrapper(sock))

    # Do a ping first, then login
    do_ping(ps)
    do_login(ps, signin_resp.login_token, signin_resp.login_token_number, character_id)

    return (sock, ps)


def cmd_download_file(username, password, filename):
    (sock, ps) = get_working_ingame_session(username, password)
    
    # HACK -- if the filename passed is "_ALL_", bruteforce all combos.
    if filename == '_ALL_':
        all_folder = 'download_all'
        try:
            os.makedirs(all_folder)
        except:
            pass

        global last_quest_bruteforce_index
        for i in range(last_quest_bruteforce_index, 99999+1):
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
            last_quest_bruteforce_index += 1
    else:
        # Download the file normally.
        get_file_resp = do_get_file(ps, filename)
        output_filename = 'download_{}.bin'.format(filename)
        with open(output_filename, 'wb') as f:
            f.write(get_file_resp.response_data)

        print("Downloaded {} as {}".format(filename, output_filename))

def cmd_download_scenarios(username, password):
    global start_scenario_category_id
    global start_scenario_main_id
    global start_scenario_u2

    (sock, ps) = get_working_ingame_session(username, password)

    scenario_folder = 'download_scenario'
    try:
        os.makedirs(scenario_folder)
    except:
        pass

    for category_id in range(start_scenario_category_id, 256): # Ran the full 256 multiple times, nothing beyond 7.
        # No hard limit on the main ID, just go until it stops returning data for the next index.
        for main_id in range(start_scenario_main_id, 999999999):
            print("Checking {}_{}_0_1".format(category_id, main_id))
            
            # Check if the category_id and main_id are valid by getting it with the known-good u2=0, flags=1 values.
            get_file_resp = do_get_file_scenario(ps, category_id, main_id, 0, 1)
            if get_file_resp.response_data == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                break
            else:
                print("{}_{}_0_1 is valid, now iterating u2 values.".format(category_id, main_id))

            last_wrote_u2_response_data_crc32 = 0
            for u2 in range(start_scenario_u2, 256):
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
        if len(sys.argv) >= 6:
            last_quest_bruteforce_index = int(sys.argv[5])

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

    
    elif len(sys.argv) >= 4 and sys.argv[1] == 'download_scenarios':
        username = sys.argv[2]
        password = sys.argv[3]
        if len(sys.argv) >= 7:
            start_scenario_category_id = int(sys.argv[4])
            start_scenario_main_id = int(sys.argv[5])
            start_scenario_u2 = int(sys.argv[6])

        cmd_download_scenarios(username, password)

    elif len(sys.argv) >= 2 and sys.argv[1] == 'channel_test': # Grab JP channel listing and decrypt:
        # This doesn't require any authentication....
        server_list = cog_jp_read_entrance_server_list('106.185.74.61', 53310) # Should be gotten from the SignInResp.
        for (server, channels) in server_list:
            print(ip_string_from_uint32(server.host_ip_4byte))
            print(server.name.decode('shift_jis'))
    else:
        print("Invalid option argument.")