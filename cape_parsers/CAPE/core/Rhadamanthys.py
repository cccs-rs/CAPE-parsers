import struct
import base64
import re
import json


DESCRIPTION = "Rhadamanthys parser"
AUTHOR = "kevoreilly, YungBinary"

CUSTOM_ALPHABETS = [
    b"3Fijkbc|l4NOPQRSTUVWXY567DdewxEqrstuvyz-ABC1fghop2mnGHIJKLMZ089a", # 0.9.3
    b"4NOPQRSTUVWXY567DdeEqrstuvwxyz-ABC1fghop23Fijkbc|lmnGHIJKLMZ089a", # 0.9.2
    b"ABC1fghijklmnop234NOPQRSTUVWXY567DEFGHIJKLMZ089abcdeqrstuvwxyz-|", # 0.9.X
]

CHACHA_KEY = b"\x52\xAB\xDF\x06\xB6\xB1\x3A\xC0\xDA\x2D\x22\xDC\x6C\xD2\xBE\x6C\x20\x17\x69\xE0\x12\xB5\xE6\xEC\x0E\xAB\x4C\x14\x73\x4A\xED\x51"
CHACHA_NONCE = b"\x5F\x14\xD7\x9C\xFC\xFC\x43\x9E\xC3\x40\x6B\xBA"


def mask32(x):
    return x & 0xFFFFFFFF


def add32(x, y):
    return mask32(x + y)


def left_rotate(x, n):
    return mask32(x << n) | (x >> (32 - n))


def quarter_round(block, a, b, c, d):
    block[a] = add32(block[a], block[b])
    block[d] ^= block[a]
    block[d] = left_rotate(block[d], 16)
    block[c] = add32(block[c], block[d])
    block[b] ^= block[c]
    block[b] = left_rotate(block[b], 12)
    block[a] = add32(block[a], block[b])
    block[d] ^= block[a]
    block[d] = left_rotate(block[d], 8)
    block[c] = add32(block[c], block[d])
    block[b] ^= block[c]
    block[b] = left_rotate(block[b], 7)


def chacha20_permute(block):
    for doubleround in range(10):
        quarter_round(block, 0, 4, 8, 12)
        quarter_round(block, 1, 5, 9, 13)
        quarter_round(block, 2, 6, 10, 14)
        quarter_round(block, 3, 7, 11, 15)
        quarter_round(block, 0, 5, 10, 15)
        quarter_round(block, 1, 6, 11, 12)
        quarter_round(block, 2, 7, 8, 13)
        quarter_round(block, 3, 4, 9, 14)


def words_from_bytes(b):
    assert len(b) % 4 == 0
    return [int.from_bytes(b[4 * i : 4 * i + 4], "little") for i in range(len(b) // 4)]


def bytes_from_words(w):
    return b"".join(word.to_bytes(4, "little") for word in w)


def chacha20_block(key, nonce, blocknum):
    # This implementation doesn't support 16-byte keys.
    assert len(key) == 32
    assert len(nonce) == 12
    assert blocknum < 2**32
    constant_words = words_from_bytes(b"expand 32-byte k")
    key_words = words_from_bytes(key)
    nonce_words = words_from_bytes(nonce)
    # fmt: off
    original_block = [
        constant_words[0],  constant_words[1],  constant_words[2],  constant_words[3],
        key_words[0],       key_words[1],       key_words[2],       key_words[3],
        key_words[4],       key_words[5],       key_words[6],       key_words[7],
        mask32(blocknum),   nonce_words[0],     nonce_words[1],     nonce_words[2],
    ]
    # fmt: on
    permuted_block = list(original_block)
    chacha20_permute(permuted_block)
    for i in range(len(permuted_block)):
        permuted_block[i] = add32(permuted_block[i], original_block[i])
    return bytes_from_words(permuted_block)


def chacha20_stream(key, nonce, length, blocknum):
    output = bytearray()
    while length > 0:
        block = chacha20_block(key, nonce, blocknum)
        take = min(length, len(block))
        output.extend(block[:take])
        length -= take
        blocknum += 1
    return output


def decrypt_config(data):
    decrypted_config = b""
    data_len = len(data)
    v3 = 0
    while True:
        v8 = 4
        while v8:
            if data_len <= (v3 + 4):
                return decrypted_config
            a = data[v3]
            b = data[v3 + 4]
            c = a ^ b
            decrypted_config += bytes([c])
            v8 -= 1
            v3 += 1


def chacha20_xor(custom_b64_decoded, key, nonce):
    message_len = len(custom_b64_decoded)
    key_stream = chacha20_stream(key, nonce, message_len, 0x80)

    xor_key = bytearray()
    for i in range(message_len):
        xor_key.append(custom_b64_decoded[i] ^ key_stream[i])

    return xor_key


def extract_base64_strings(data, minchars, maxchars):
    apat = b"([A-Za-z0-9-|]{" + str(minchars).encode() + b"," + str(maxchars).encode() + b"})\x00"
    strings = [s.decode() for s in re.findall(apat, data)]
    upat = b"((?:[A-Za-z0-9-|]\x00){" + str(minchars).encode() + b"," + str(maxchars).encode() + b"})\x00\x00"
    strings.extend(ws.decode("utf-16le") for ws in re.findall(upat, data))
    return strings


def extract_c2_url(data):
    pattern = b"(http[\x20-\x7e]+)\x00"
    match = re.search(pattern, data)
    if match:
        return match.group(1).decode()


def custom_b64decode(data: bytes, custom_alphabet: bytes):
    """Decodes base64 data using a custom alphabet."""
    standard_alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    # Translate the data back to the standard alphabet before decoding
    table = bytes.maketrans(custom_alphabet, standard_alphabet)
    return base64.b64decode(data.translate(table), validate=True)


def lzo_noheader_decompress(data: bytes, decompressed_size: int):
    src = 0
    dst = bytearray()
    length = len(data)

    while src < length:
        ctrl = data[src]
        src += 1

        # Special short match
        # Copies exactly 3 bytes from dst starting match_len + 1 bytes back.
        if ctrl == 0x20:
            match_len = data[src]
            src += 1
            start = len(dst) - match_len - 1
            end = start + 3
            #print(f"Control code: {hex(ctrl)}, Offset backtrack length: {hex(match_len)}, Current offset: {hex(len(dst))}, New offset: {hex(start)}")
            dst.extend(dst[start:end])

        elif ctrl >= 0xE0 or ctrl == 0x40:
            # Compute base copy length from the upper bits of ctrl
            base_len = ((ctrl >> 5) - 1) + 3

            if ctrl >= 0xE0:
                # Long copy: extra length byte follows
                copy_len = base_len + data[src]
                # Offset is byte after
                start = data[src + 1]
                src += 2
            elif ctrl == 0x40:
                # Short copy: offset byte after control code
                copy_len = base_len
                start = data[src]
                src += 1

            # Calculate offset in output buffer
            offset = len(dst) - start - 1

            #print(f"Control code: {hex(ctrl)}, Offset backtrack length: {hex(start)}, Current offset: {hex(len(dst))}, New offset: {hex(len(dst) - start)}, Length to copy: {hex(copy_len)}")

            # Copy from previously decompressed data
            dst.extend(dst[offset:offset + copy_len])

        else:
            # Literal run
            literal_len = (ctrl & 0x1F) + 1
            #print(f"Control code: {hex(ctrl)}, Literal length: {hex(literal_len)}")
            dst.extend(data[src:src+literal_len])
            src += literal_len

        if len(dst) == decompressed_size:
            return bytes(dst)


def parse_compression_header(config: bytes):
    """Parse compressed size, decompressed size, and data offset from config"""

    # 0x2A when looking at the config in memory
    base_offset = 0x26

    # Compressed data offset field, for calculating the offset to the compressed buffer
    comp_offset_field = config[base_offset]
    # Number of bytes the field spans
    comp_offset_size_len = (comp_offset_field & 3) + 1
    for i in range(1, comp_offset_size_len):
        comp_offset_field |= config[base_offset + i] << (8 * i)

    comp_size_offset = comp_offset_field >> 2

    # Compressed size field, for finding the size of the compressed buffer
    comp_offset = base_offset + comp_offset_size_len
    comp_size_field = config[comp_offset]
    # Number of bytes the field spans
    comp_size_len = (comp_size_field & 3) + 1
    for i in range(1, comp_size_len):
        comp_size_field |= config[comp_offset + i] << (8 * i)

    # Decompressed size field
    decomp_field_offset = base_offset + comp_offset_size_len + comp_size_len
    decomp_size_field = config[decomp_field_offset]
    # Number of bytes the field spans
    decomp_field_len = (decomp_size_field & 3) + 1
    for i in range(1, decomp_field_len):
        decomp_size_field |= config[decomp_field_offset + i] << (8 * i)

    # Calculate return values
    decompressed_size = decomp_size_field >> 2
    compressed_data_offset = decomp_field_offset + decomp_field_len + comp_size_offset
    compressed_size_key = config[0x28] << 8
    compressed_size = (compressed_size_key | comp_size_field) >> 2
    compressed_data = config[compressed_data_offset : compressed_data_offset + compressed_size]

    return {
        "compressed_size": compressed_size,
        "decompressed_size": decompressed_size,
        "compressed_data": compressed_data
    }


def handle_encrypted_string(encrypted_string: str) -> list:
    """
    Args:
        encrypted_string: a str representing
    Returns:
        Command and Control server list, may be empty
    """

    for alphabet in CUSTOM_ALPHABETS:
        try:
            custom_b64_decoded = custom_b64decode(encrypted_string, alphabet)
            xor_key = chacha20_xor(custom_b64_decoded, CHACHA_KEY, CHACHA_NONCE)
            # Decrypted, may still be the compressed malware configuration
            config = decrypt_config(xor_key)

            # First byte should be 0xFF
            if config[0] != 0xFF:
                continue

            # Attempt to extract C2 url, only works in version prior to 0.9.2
            c2_url = extract_c2_url(config)
            if c2_url:
                return [c2_url]

            # Parse header
            parsed = parse_compression_header(config)
            if not parsed:
                continue

            # Decompress LZO-like compression
            decompressed = lzo_noheader_decompress(parsed['compressed_data'], parsed['decompressed_size'])
            pattern = re.compile(b'.' + bytes([decompressed[1]]))

            cncs = [f"https://{chunk.decode()}" for chunk in pattern.split(decompressed) if chunk]
            return cncs
        except Exception:
            continue

    return []


def extract_config(data):
    """
    Extract Rhadamanthys malware configuration.
    """
    config_dict = {}
    # Extract very old variant
    magic = struct.unpack("I", data[:4])[0]
    if magic == 0x59485221:
        config_dict["CNCs"] = [data[24:].split(b"\0", 1)[0].decode()]
        return config_dict

    # New variants, extract base64 strings
    extracted_strings = extract_base64_strings(data, 100, 256)
    if not extracted_strings:
        return config_dict

    # Handle each encrypted string
    for string in extracted_strings:
        cncs = handle_encrypted_string(string)
        if cncs:
            return {"CNCs": cncs}

    return config_dict


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        config_json = json.dumps(extract_config(f.read()), indent=4)
        print(config_json)

detection_rule = """
rule Rhadamanthys
{
    meta:
        author = "kevoreilly, YungBinary"
        description = "Rhadamanthys Payload"
        cape_type = "Rhadamanthys Payload"
    strings:
        $rc4 = {88 4C 01 08 41 81 F9 00 01 00 00 7C F3 89 75 08 33 FF 8B 4D 08 3B 4D 10 72 04 83 65 08 00}
        $code = {8B 4D FC 3B CF 8B C1 74 0D 83 78 04 02 74 1C 8B 40 1C 3B C7 75 F3 3B CF 8B C1 74 57 83 78 04 17 74 09 8B 40 1C 3B C7 75 F3 EB}
        $conf_1 = {46 BB FF 00 00 00 23 F3 0F B6 44 31 08 03 F8 23 FB 0F B6 5C 39 08 88 5C 31 08 88 44 39 08 02 C3 8B 5D 08 0F B6 C0 8A 44 08 08}
        $conf_2 = {0F B6 4F 2A 8D 77 2A 33 C0 6A 03 89 45 F8 89 45 FC 89 45 08 8B C1}
        $beef = {57 8D 44 33 FC 53 83 C6 FC 50 56 E8 [4] 83 C4 10 66 81 3F EF BE 0F 85}
        $anti = {50 68 [4] 68 [4] E8 [4] 83 C4 0C A3 [4] 85 C0 74}
        $dnr = {99 52 50 8D 45 ?? 99 52 50 8B C7 99 52 50 8B C3 99 52 50}
        $sys = {83 E4 F0 6A 33 E8 00 00 00 00 83 04 24 05 CB}
        $cape_string = "cape_options"
    condition:
        2 of them and not $cape_string
}

rule RhadamanthysLoader
{
    meta:
        author = "kevoreilly"
        description = "Rhadamanthys Loader"
        cape_type = "Rhadamanthys Loader"
    strings:
        $ref = {33 D2 B9 0B 00 00 00 F7 F1 B8 01 00 00 00 6B C8 00 8D 84 0D [4] 0F BE 0C 10 8B 95 [4] 03 95 [4] 0F B6 02 33 C1 8B 8D [4] 03 8D [4] 88 01}
        $ntdll = {B9 6E 00 00 00 66 89 8D [4] BA 74 00 00 00 66 89 95 [4] B8 64 00 00 00 66 89 85 [4] B9 6C 00 00 00 66 89 8D [4] BA 6C 00 00 00 66 89 95}
        $exit = {6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 8B 95 [4] 52 8B 85 [4] 50 6A 00 68 FF FF 1F 00}
    condition:
        2 of them
}

"""
