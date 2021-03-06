from .constructs import Binary8Header

ENCRYPT_KEY = b'\x90\x51\x26\x25\x04\xBF\xCF\x4C\x92\x02\x52\x7A\x70\x1A\x41\x88\x8C\xC2\xCE\xB8\xF6\x57\x7E\xBA\x83\x63\x2C\x24\x9A\x67\x86\x0C\xBE\x72\xFD\xB6\x7B\x79\xB0\x22\x5A\x60\x5C\x4F\x49\xE2\x0E\xF5\x3A\x81\xAE\x11\x6B\xF0\xA1\x01\xE8\x65\x8D\x5B\xDC\xCC\x93\x18\xB3\xAB\x77\xF7\x8E\xEC\xEF\x05\x00\xCA\x4E\xA7\xBC\xB5\x10\xC6\x6C\xC0\xC4\xE5\x87\x3F\xC1\x82\x29\x96\x45\x73\x07\xCB\x43\xF9\xF3\x08\x89\xD0\x99\x6A\x3B\x37\x19\xD4\x40\xEA\xD7\x85\x16\x66\x1E\x9C\x39\xBB\xEE\x4A\x03\x8A\x36\x2D\x13\x1D\x56\x48\xC7\x0D\x59\xB2\x44\xA3\xFE\x8B\x32\x1B\x84\xA0\x2E\x62\x17\x42\xB9\x9B\x2B\x75\xD8\x1C\x3C\x4D\x76\x27\x6E\x28\xD3\x33\xC3\x21\xAF\x34\x23\xDD\x68\x9F\xF1\xAD\xE1\xB4\xE7\xA6\x74\x15\x4B\xFA\x3D\x5F\x7C\xDA\x2F\x0A\xE3\x7D\xC8\xB7\x12\x6F\x9E\xA9\x14\x53\x97\x8F\x64\xF4\xF8\xA2\xA4\x2A\xD2\x47\x9D\x71\xC5\xE9\x06\x98\x20\x54\x80\xAA\xF2\xAC\x50\xD6\x7F\xD9\xC9\xCD\x69\x46\x6D\x30\xB1\x58\x0B\x55\xD1\x5D\xD5\xBD\x31\xDE\xA5\xE4\x91\x0F\x61\x38\xDF\xA8\xE6\x3E\x1F\x35\xED\xDB\x94\xEB\x09\x5E\x95\xFB\xFC\xE0\x78\xFF'
DECRYPT_KEY = b'\x48\x37\x09\x76\x04\x47\xCC\x5C\x61\xF8\xB3\xE0\x1F\x7F\x2E\xEB\x4E\x33\xB8\x7A\xBC\xAB\x6E\x8C\x3F\x68\x0D\x87\x93\x7B\x70\xF2\xCE\x9D\x27\xA0\x1B\x03\x02\x97\x99\x58\xC5\x90\x1A\x79\x8A\xB2\xDD\xE6\x86\x9B\x9F\xF3\x78\x67\xED\x72\x30\x66\x94\xAE\xF1\x55\x6A\x0E\x8D\x5E\x82\x5A\xDB\xC7\x7D\x2C\x75\xAC\x07\x95\x4A\x2B\xD4\x01\x0A\xBD\xCF\xE1\x7C\x15\xDF\x80\x28\x3B\x2A\xE3\xF9\xAF\x29\xEC\x8B\x19\xC0\x39\x6F\x1D\xA2\xDA\x65\x34\x50\xDC\x98\xB9\x0C\xC9\x21\x5B\xAA\x91\x96\x42\xFE\x25\x0B\x24\xB0\xB5\x16\xD6\xD0\x31\x57\x18\x88\x6D\x1E\x54\x0F\x62\x77\x85\x10\x3A\x44\xBF\x00\xEA\x08\x3E\xF6\xFA\x59\xBE\xCD\x64\x1C\x8F\x71\xC8\xBA\xA3\x89\x36\xC3\x83\xC4\xE8\xA9\x4B\xEF\xBB\xD1\x41\xD3\xA5\x32\x9E\x26\xDE\x81\x40\xA7\x4D\x23\xB7\x13\x8E\x17\x73\x4C\xE5\x20\x05\x51\x56\x11\x9C\x52\xCA\x4F\x7E\xB6\xD8\x49\x5D\x3D\xD9\x12\x06\x63\xE2\xC6\x9A\x69\xE4\xD5\x6C\x92\xD7\xB1\xF5\x3C\xA1\xE7\xEE\xFD\xA6\x2D\xB4\xE9\x53\xF0\xA8\x38\xCB\x6B\xF7\x45\xF4\x74\x46\x35\xA4\xD2\x60\xC1\x2F\x14\x43\xC2\x5F\xAD\xFB\xFC\x22\x84\xFF'
SHARED_CRYPT_KEY = b'\xDD\xA8\x5F\x1E\x57\xAF\xC0\xCC\x43\x35\x8F\xBB\x6F\xE6\xA1\xD6\x60\xB9\x1A\xAE\x20\x49\x24\x81\x21\xFE\x86\x2B\x98\xB7\xB3\xD2\x91\x01\x3A\x4C\x65\x92\x1C\xF4\xBE\xDD\xD9\x08\xE6\x81\x98\x1B\x8D\x60\xF3\x6F\xA1\x47\x24\xF1\x53\x45\xC8\x7B\x88\x80\x4E\x36\xC3\x0D\xC9\xD6\x8B\x08\x19\x0B\xA5\xC1\x11\x4C\x60\xF8\x5D\xFC\x15\x68\x7E\x32\xC0\x50\xAB\x64\x1F\x8A\xD4\x08\x39\x7F\xC2\xFB\xBA\x6C\xF0\xE6\xB0\x31\x10\xC1\xBF\x75\x43\xBB\x18\x04\x0D\xD1\x97\xF7\x23\x21\x83\x8B\xCA\x25\x2B\xA3\x03\x13\xEA\xAE\xFE\xF0\xEB\xFD\x85\x57\x53\x65\x41\x2A\x40\x99\xC0\x94\x65\x7E\x7C\x93\x82\xB0\xB3\xE5\xC0\x21\x09\x84\xD5\xEF\x9F\xD1\x7E\xDC\x4D\xF5\x7E\xCD\x45\x3C\x7F\xF5\x59\x98\xC6\x55\xFC\x9F\xA3\xB7\x74\xEE\x31\x98\xE6\xB7\xBE\x26\xF4\x3C\x76\xF1\x23\x7E\x02\x4E\x3C\xD1\xC7\x28\x23\x73\xC4\xD9\x5E\x0D\xA1\x80\xA5\xAA\x26\x0A\xA3\x44\x82\x74\xE6\x3C\x44\x27\x51\x0D\x5F\xC7\x9C\xD6\x63\x67\xA5\x27\x97\x38\xFB\x2D\xD3\xD6\x60\x25\x83\x4D\x37\x5B\x40\x59\x11\x77\x51\x11\x14\x18\x07\x63\xB1\x34\x3D\xB8\x60\x13\xC2\xE8\x13\x82'

class PacketCrypto(object):
    def encrypt(data, rot_key, override_byte_key=None):
        return PacketCrypto._general_crypt(data, rot_key, 0, override_byte_key)

    def decrypt(data, rot_key, override_byte_key=None):
        return PacketCrypto._general_crypt(data, rot_key, 1, override_byte_key)

    def _general_crypt(data, rot_key, crypt_type, override_byte_key=None):
        """A generic crypto function for both encryption and decryption

        :param data: input data
        :param rot_key: crypto key index rotation
        :param crypt_type: determines whether to encrypt(0) or decrypt(1)
        :param override_byte_key: override value for the truncated rotation index byte
        :type data: bytes
        :type rot_key: int
        :type crypt_type: int
        :type override_byte_key: bool
        """
        unk_cryptkey_rot_arg = ((rot_key >> 1) % 999983) & 0xFF
        if override_byte_key is not None:
            unk_cryptkey_rot_arg = override_byte_key

        unk_derived_cryptkey_rot = (len(data) * (unk_cryptkey_rot_arg+1)) & 0xFFFFFFFF
        shared_buf_idx = 1
        accumulator_0 = 0
        accumulator_1 = 0
        accumulator_2 = 0

        output_data = bytearray()
        if crypt_type == 0: # Encrypt
            for i in range(len(data)):
                # Do the encryption for this iteration
                enc_key_idx = ((unk_derived_cryptkey_rot >> 10) ^ data[i]) & 0xFF
                unk_derived_cryptkey_rot = (0x4FD * (unk_derived_cryptkey_rot + 1)) & 0xFFFFFFFF
                enc_key_byte = ENCRYPT_KEY[enc_key_idx]

                # Update the checksum accumulators.
                accumulator_2 = (accumulator_2 + (shared_buf_idx * data[i])) & 0xFFFFFFFF
                accumulator_1 = (accumulator_1 + enc_key_idx) & 0xFFFFFFFF
                accumulator_0 = (accumulator_0 + (enc_key_byte << (i & 7)) & 0xFFFFFFFF) & 0xFFFFFFFF

                # Append the output.
                output_data.append(SHARED_CRYPT_KEY[shared_buf_idx] ^ enc_key_byte)

                # Update the shared_buf_idx for the next iteration.
                shared_buf_idx = data[i]
        elif crypt_type == 1: # Decrypt
            for i in range(len(data)):
                # Do the decryption for this iteration
                old_shared_buf_idx = shared_buf_idx
                t_idx = data[i] ^ SHARED_CRYPT_KEY[shared_buf_idx]
                dec_key_byte = DECRYPT_KEY[t_idx]
                shared_buf_idx = ((unk_derived_cryptkey_rot >> 10) ^ dec_key_byte) & 0xFF

                # Update the checksum accumulators.
                accumulator_0 = (accumulator_0 + ((t_idx << (i & 7)) & 0xFFFFFFFF))
                accumulator_1 = (accumulator_1 + dec_key_byte) & 0xFFFFFFFF
                accumulator_2 = (accumulator_2 + ((old_shared_buf_idx * shared_buf_idx)&0xFFFFFFFF)) & 0xFFFFFFFF

                # Append the output.
                output_data.append(shared_buf_idx)

                # Update the key pos for next iteration.
                unk_derived_cryptkey_rot = (0x4FD * (unk_derived_cryptkey_rot + 1)) & 0xFFFFFFFF
        else:
            raise Exception("Unknown crypt_type value.")

        combined_check = (accumulator_1 + (accumulator_0 >> 1) + (accumulator_2 >> 2)) & 0xFFFF
        check_0 = (accumulator_0 ^ ((accumulator_0&0xFFFF0000)>>16)) & 0xFFFF
        check_1 = (accumulator_1 ^ ((accumulator_1&0xFFFF0000)>>16)) & 0xFFFF
        check_2 = (accumulator_2 ^ ((accumulator_2&0xFFFF0000)>>16)) & 0xFFFF

        return (output_data, combined_check, check_0, check_1, check_2)


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