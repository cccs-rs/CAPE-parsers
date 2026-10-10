# MIT License
#
# Copyright (c) 2017 Jason Reaves
# Copyright (c) 2019 Graham Austin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import hashlib
import struct
import xml.etree.ElementTree as ET

import pefile
from Cryptodome.Cipher import AES

import yara

rule_source = """
rule TrickBot
{
    meta:
        author = "grahamaustin"
        description = "TrickBot Payload"
        cape_type = "TrickBot Payload"
    strings:
        $snippet1 = {B8 ?? ?? 00 00 85 C9 74 32 BE ?? ?? ?? ?? BA ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? 03 F2 8B 2B 83 C3 04 33 2F 83 C7 04 89 29 83 C1 04 3B DE 0F 43 DA}
    condition:
        uint16(0) == 0x5A4D and ($snippet1)
}
"""


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "TrickBot":
            for item in match.strings:
                if item.identifier == rule_name:
                    addresses[item.identifier] = item.instances[0].offset
                    return addresses


def xor_data(data, key, key_len):
    decrypted_blob = b""
    for i, x in enumerate(range(0, len(data), 4)):
        xor = struct.unpack("<L", data[x : x + 4])[0] ^ struct.unpack("<L", key[i % key_len])[0]
        decrypted_blob += struct.pack("<L", xor)
    return decrypted_blob


def derive_key(n_rounds, input_bf):
    intermediate = input_bf
    for _ in range(n_rounds):
        sha = hashlib.sha256()
        sha.update(intermediate)
        current = sha.digest()
        intermediate += current
    return current


# expects a str of binary data open().read()
def trick_decrypt(data):
    key = derive_key(128, data[:32])
    iv = derive_key(128, data[16:48])[:16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    mod = len(data[48:]) % 16
    if mod != 0:
        data += "0" * (16 - mod)
    return aes.decrypt(data[48:])[: -(16 - mod)]


def get_rsrc(pe):
    ret = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = str(resource_type.name)
            else:
                name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
            if name is None:
                name = str(resource_type.struct.name)
            if hasattr(resource_type, "directory"):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, "directory"):
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            ret.append((name, data, resource_lang.data.struct.Size, resource_type))
    return ret


def va_to_fileoffset(pe, va):
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        if rva >= section.VirtualAddress and rva < section.VirtualAddress + section.Misc_VirtualSize:
            return rva - section.VirtualAddress + section.PointerToRawData


# Thanks Robert Giczewski - https://malware.love/malware_analysis/reverse_engineering/2020/11/17/trickbots-latest-trick.html
def convert_to_real_ip(ip_str):
    octets = ip_str.split(".")
    o1 = int(octets[0])
    o2 = int(octets[2])
    o3 = int(octets[3])
    o4 = int(octets[1])
    x = ((~o1 & 0xFF) & 0xB8 | (o1 & 0x47)) ^ ((~o2 & 0xFF) & 0xB8 | (o2 & 0x47))
    o = (o3 & (~o2 & 0xFF)) | ((~o3 & 0xFF) & o2)
    result_octets = [
        str(x),
        str(((~o & 0xFF) & o4) | (o & (~o4 & 0xFF))),
        str(o),
        str(((~o2 & 0xFF) & o4) | ((~o4 & 0xFF) & o2)),
    ]
    return f"{'.'.join(result_octets)}:443"


def get_ip(ip_str, tag):
    if tag == "srva":
        return convert_to_real_ip(ip_str.split(":", 1)[0])
    return ip_str


def decode_onboard_config(data):
    try:
        pe = pefile.PE(data=data)
        rsrcs = get_rsrc(pe)
    except Exception:
        return
    if rsrcs != []:
        a = rsrcs[0][1]
        data = trick_decrypt(a[4:])
        length = struct.unpack_from("<I", data)[0]
        if length < 4000:
            return data[8 : length + 8]
        a = rsrcs[1][1]
        data = trick_decrypt(a[4:])
        length = struct.unpack_from("<I", data)[0]
        if length < 4000:
            return data[8 : length + 8]

    # Following code by grahamaustin
    snippet = yara_scan(data, "$snippet1")
    if not snippet:
        return
    offset = int(snippet["$snippet1"])
    key_len = struct.unpack("<L", data[offset + 10 : offset + 14])[0]
    key_offset = struct.unpack("<L", data[offset + 15 : offset + 19])[0]
    key_offset = va_to_fileoffset(pe, int(struct.unpack("<L", data[offset + 15 : offset + 19])[0]))
    data_offset = va_to_fileoffset(pe, int(struct.unpack("<L", data[offset + 20 : offset + 24])[0]))
    size_offset = va_to_fileoffset(pe, int(struct.unpack("<L", data[offset + 53 : offset + 57])[0]))
    size = size_offset - data_offset
    key = data[key_offset : key_offset + key_len]
    key = [key[i : i + 4] for i in range(0, len(key), 4)]
    key_len2 = len(key)
    a = data[data_offset : data_offset + size]
    a = xor_data(a, key, key_len2)

    data = trick_decrypt(a)
    length = struct.unpack_from("<I", data)[0]
    if length < 4000:
        return data[8 : length + 8]


def extract_config(data):
    xml = decode_onboard_config(data)
    try:
        root = ET.fromstring(xml)
    except Exception:
        return
    raw_config = {}
    for child in root:

        tag = child.attrib["key"] if hasattr(child, "key") else child.tag
        if tag == "autorun":
            val = list(map(lambda x: x.items(), child.getchildren()))
        elif tag == "servs":
            val = list(map(lambda x: get_ip(x.text, x.tag), child.getchildren()))
        else:
            val = child.text

        raw_config[tag] = val

    return raw_config

detection_rule = """
rule TrickBot
{
    meta:
        author = "sysopfb & kevoreilly"
        description = "TrickBot Payload"
        cape_type = "TrickBot Payload"
    strings:
        $str1 = "<moduleconfig>*</moduleconfig>" ascii wide
        $str2 = "group_tag" ascii wide
        $str3 = "client_id" ascii wide
        $code1 = {8A 11 88 54 35 F8 46 41 4F 89 4D F0 83 FE 04 0F 85 7E 00 00 00 8A 1D ?? ?? ?? ?? 33 F6 8D 49 00 33 C9 84 DB 74 1F 8A 54 35 F8 8A C3 8D 64 24 00}
        $code2 = {8B 4D FC 8A D1 02 D2 8A C5 C0 F8 04 02 D2 24 03 02 C2 88 45 08 8A 45 FE 8A D0 C0 FA 02 8A CD C0 E1 04 80 E2 0F 32 D1 8B 4D F8 C0 E0 06 02 45 FF 88 55 09 66 8B 55 08 66 89 11 88 41 02}
        $code3 = {0F B6 54 24 49 0F B6 44 24 48 48 83 C6 03 C0 E0 02 0F B6 CA C0 E2 04 C0 F9 04 33 DB 80 E1 03 02 C8 88 4C 24 40 0F B6 4C 24 4A 0F B6 C1 C0 E1 06 02 4C 24 4B C0 F8 02 88 4C 24 42 24 0F}
        $code4 = {53 8B 5C 24 18 55 8B 6C 24 10 56 8B 74 24 18 8D 9B 00 00 00 00 8B C1 33 D2 F7 F3 41 8A 04 2A 30 44 31 FF 3B CF 75 EE 5E 5D 5B 5F C3}
        $code5 = {50 0F 31 C7 44 24 04 01 00 00 00 8D 0C C5 00 00 00 00 F7 C1 F8 07 00 00 74 1B 48 C1 E2 20 48 8B C8 48 0B CA 0F B6 C9 C1 E1 03 F7 D9 C1 64 24 04 10 FF C1 75 F7 59 C3}
        $code6 = {53 8B 5C 24 0C 56 8B 74 24 14 B8 ?? ?? ?? ?? F7 E9 C1 FA 02 8B C2 C1 E8 1F 03 C2 6B C0 16 8B D1 2B D0 8A 04 1A 30 04 31 41 3B CF 75 DD 5E 5B 5F C3}
        $code7 = {B8 ?? ?? 00 00 85 C9 74 32 BE ?? ?? ?? ?? BA ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? 03 F2 8B 2B 83 C3 04 33 2F 83 C7 04 89 29 83 C1 04 3B DE 0F 43 DA}
    condition:
        all of ($str*) or any of ($code*)
}

rule Trickbot_PermaDll_UEFI_Module
{
    meta:
        author = "@VK_Intel | Advanced Intelligence"
        description = "Detects TrickBot Banking module permaDll"
        md5 = "491115422a6b94dc952982e6914adc39"
    strings:
        $module_cfg = "moduleconfig"
        $str_imp_01 = "Start"
        $str_imp_02 = "Control"
        $str_imp_03 = "FreeBuffer"
        $str_imp_04 = "Release"
        $module = "user_platform_check.dll"
        $intro_routine = { 83 ec 40 8b ?? ?? ?? 53 8b ?? ?? ?? 55 33 ed a3 ?? ?? ?? ?? 8b ?? ?? ?? 56 57 89 ?? ?? ?? a3 ?? ?? ?? ?? 39 ?? ?? ?? ?? ?? 75 ?? 8d ?? ?? ?? 89 ?? ?? ?? 50 6a 40 8d ?? ?? ?? ?? ?? 55 e8 ?? ?? ?? ?? 85 c0 78 ?? 8b ?? ?? ?? 85 ff 74 ?? 47 57 e8 ?? ?? ?? ?? 8b f0 59 85 f6 74 ?? 57 6a 00 56 e8 ?? ?? ?? ?? 83 c4 0c eb ??}
    condition:
        6 of them
}

"""
