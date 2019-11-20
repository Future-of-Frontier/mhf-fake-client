import struct

from .crypto import *

class PacketHeader(object):
    SIZE = 14
    def __init__(self):
        # I'm unsure what this field is.
        # It is calculated via `(packet_encrypted_body_size >> 12) & 0xF3 | 3`.
        # I've only ever observed this being 3, but it can be different if 
        #   the packet size has the bits at 0xC000 set. 
        # Additionally, if ((pf0&0xF) < 2 && cmessage_man->field_32D): rot_key=0.
        self.pf0 = None

        self.key_rot_delta = None
        self.pkt_num = None
        self.pkt_data_size = None
        self.prev_packet_combined_check = None
        self.check0 = None
        self.check1 = None
        self.check2 = None

    def parse_from(self, data):
        (pf0, key_rot_delta, pkt_num, pkt_data_size, prev_packet_combined_check, check0, check1, check2) = struct.unpack('>BBHHHHHH', data)
        self.pf0 = pf0
        self.key_rot_delta = key_rot_delta
        self.pkt_num = pkt_num
        self.pkt_data_size = pkt_data_size
        self.prev_packet_combined_check = prev_packet_combined_check
        self.check0 = check0
        self.check1 = check1
        self.check2 = check2

    def build(self):
        return struct.pack(
            '>BBHHHHHH',
             self.pf0,
             self.key_rot_delta,
             self.pkt_num,
             self.pkt_data_size,
             self.prev_packet_combined_check,
             self.check0,
             self.check1,
             self.check2)

class Packet(object):
    def __init__(self, header, data):
        self.header = header
        self.data = data

class PacketStreamContext(object):
    """PacketStreamContext is a helper class for packet IO and crypto.
    """
    def __init__(self, data_stream):
        self._read_key_rot = 995117
        self._send_key_rot = 995117
        self._sent_packets = 0
        self._prev_send_packet_combined_check = 0
        self._ds = data_stream

    def _encrypt(self, data, rot_key, override_byte_key=None):
        return PacketCrypto.encrypt(data, rot_key, override_byte_key)


    def _decrypt(self, data, rot_key, override_byte_key=None):
        return PacketCrypto.decrypt(data, rot_key, override_byte_key)

    def read_packet(self, bruteforce_encryption=False):
        # Read the header.
        header = PacketHeader()
        header.parse_from(self._ds.read(PacketHeader.SIZE))

        # Update the rolling key index.
        if header.key_rot_delta != 0:
            self._read_key_rot = (header.key_rot_delta * (self._read_key_rot + 1)) & 0xFFFFFFFF

        # Read the encrypted packet body data.
        encrypted_data = self._ds.read(header.pkt_data_size)

        # Decrypt the data
        if not bruteforce_encryption:
            (output_data, combined_check, check0, check1, check2) = PacketCrypto.decrypt(encrypted_data, self._read_key_rot)
        else:
            # Loop over all the 256 possibilities until the checksums match.
            matchFound = False
            for i in range(256):
                (output_data, combined_check, check0, check1, check2) = PacketCrypto.decrypt(encrypted_data, 0, i)
                if check0 == header.check0 and check1 == header.check1 and check2 == header.check2:
                    matchFound = True
                    break
            if not matchFound:
                raise Exception("Could not bruteforce the packet!")

        return Packet(header, output_data)

    # Encrypts the data, makes the header, and returns the completed raw packet.
    def _make_raw_packet(self, data, pkt_num, prev_packet_combined_check, key_rot_delta=None):
         # Update the rolling key index.
        if key_rot_delta != None:
            self._send_key_rot = (key_rot_delta * (self._send_key_rot + 1)) & 0xFFFFFFFF

        # Encrypt the data.
        (enc_data, combined_check, check_0, check_1, check_2) = PacketCrypto.encrypt(data, self._send_key_rot)

        # Make the packet header.
        header = PacketHeader()
        header.pf0 = ((len(enc_data) >> 12) & 0xF3) | 3
        header.key_rot_delta = key_rot_delta or 0
        header.pkt_num = pkt_num
        header.pkt_data_size = len(enc_data)
        header.prev_packet_combined_check = prev_packet_combined_check
        header.check0 = check_0
        header.check1 = check_1
        header.check2 = check_2

        # Combine the packet header and data together.
        packet = bytearray()
        packet.extend(header.build())
        packet.extend(enc_data)

        return (packet, combined_check)

    def make_and_send_packet(self, data, key_rot_delta=2):
        (packet, combined_check) = self._make_raw_packet(data, self._sent_packets, self._prev_send_packet_combined_check, key_rot_delta)

        # Send the packet.
        self._ds.write(packet)

        # Increment the sent_packets used for packet ID's.
        self._sent_packets += 1
        self._prev_send_packet_combined_check = combined_check