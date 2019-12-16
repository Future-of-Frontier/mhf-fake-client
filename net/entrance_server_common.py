import socket
import io
from . import *


DECODE_BINARY8_KEY = bytes([0x01, 0x23, 0x34, 0x45, 0x56, 0xAB, 0xCD, 0xEF])
def decode_binary8(data, unk_key_byte):
    cur_key = ((54323 * unk_key_byte) + 1) & 0xFFFFFFFF

    output_data = bytearray()
    for i in range(len(data)):
        tmp = (data[i] ^ (cur_key >> 13)) & 0xFF
        output_data.append(tmp ^ DECODE_BINARY8_KEY[i&7])
        cur_key = ((54323 * cur_key) + 1) & 0xFFFFFFFF

    return output_data

def read_binary8_part(stream):
    # Read the header and decrypt the header first to get the size.
    enc_bytes = bytearray(stream.read(12))
    dec_header_bytes = decode_binary8(enc_bytes[1:], enc_bytes[0])
    header = Binary8Header.parse(dec_header_bytes)

    # Then read the body, append to the header, and decrypt the full thing.
    enc_bytes.extend(stream.read(header.body_size))
    dec_bytes = decode_binary8(enc_bytes[1:], enc_bytes[0])

    # Then return the parsed header and just the raw body data.
    return (header, dec_bytes[11:])

def read_entrance_server_list(host, port):
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
    #print(server_info_header)

    servers = []
    for i in range(server_info_header.entry_count):
        si = ServerInfo.parse(si_stream.read(si_size))

        # Loop over the channel info structs.
        #print("server #{}".format(i))
        #print(si)
        #print(si.name.decode('big5'))
        channels = []
        for j in range(si.channel_count):
            #print("channel #{}".format(j))
            ci = ChannelInfo.parse(si_stream.read(ci_size))
            channels.append(ci)
            #print(ci)

        servers.append((si, channels))

    return (servers, ps)