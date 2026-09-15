# Thanks to @MuziSec - https://github.com/MuziSec/malware_scripts/blob/main/bumblebee/extract_config.py
# 2024 updates by @enzok
#
import logging
import traceback
from contextlib import suppress

import pefile

# import regex as re
# test
import re
from Cryptodome.Cipher import ARC4

import yara

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

rule_source = """
rule BumbleBee
{
    meta:
        author = "enzok"
        description = "BumbleBee 2024"
    strings:
        $rc4key = {48 [6] 48 [6] E8 [4] 4C 89 AD [4] 4C 89 AD [4] 4C 89 B5 [4] 4C 89 AD [4] 44 88 AD [4] 48 8D 15 [4] 44 38 2D [4] 75}
        $botidlgt = {4C 8B C1 B? 4F 00 00 00 48 8D 0D [4] E8 [4] 4C 8B C3 48 8D 0D [4] B? 4F 00 00 00 E8 [4] 4C 8B C3 48 8D 0D [4] B? FF 0F 00 00 E8}
        $botid = {90 48 [6] E8 [4] 4C 89 AD [4] 4C 89 AD [4] 4C 89 B5 [4] 4C 89 AD [4] 44 88 AD [4] 48 8D 15 [4] 44 38 2D [4] 75}
        $port = {4C 89 6D ?? 4C 89 6D ?? 4c 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8D 05 [4] 44 38 2D [4] 75}
        $dga1 = {4C 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8B 1D [4] 48 8D 0D [4] E8 [4] 8B F8}
        $dga2 = {48 8D 0D [4] E8 [4] 8B F0 4C 89 6D ?? 4C 89 6D ?? 4C 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8D 15 [4] 44 38 2D [4] 75}
    condition:
        $rc4key and all of ($botid*) and 2 of ($port, $port, $dga1, $dga2)
}
"""

yara_rules = yara.compile(source=rule_source)


def extract_key_data(data, pe, key_match):
    """
    Given key match, convert rva to file offset and return key data at that offset.
    """
    try:
        # Get relative rva. The LEA is using a relative address. This address is relative to the address of the next ins.
        relative_rva = pe.get_rva_from_offset(key_match.start() + int(len(key_match.group()) / 2))
        # Now that we have the relative rva, we need to get the file offset
        key_offset = pe.get_offset_from_rva(relative_rva + int.from_bytes(key_match.group("key"), byteorder="little"))
        # Read arbitrary number of byes from key offset and split on null bytes to extract key
        key = data[key_offset : key_offset + 0x40].split(b"\x00")[0]
    except Exception as e:
        log.debug("There was an exception extracting the key: %s", str(e))
        log.debug(traceback.format_exc())
        return False
    return key


def extract_config_data(data, pe, config_match):
    """
    Given config match, convert rva to file offset and return data at that offset.
    The LEA ins are using relative addressing. Referenced data is relative to the address of the NEXT ins.
    This is inefficient but I'm bad at Python, okay?
    """
    try:
        # Get campaign id ciphertext
        campaign_id_rva = pe.get_rva_from_offset(config_match.start() + int(len(config_match.group("campaign_id_ins"))))
        campaign_id_offset = pe.get_offset_from_rva(
            campaign_id_rva + int.from_bytes(config_match.group("campaign_id"), byteorder="little")
        )
        campaign_id_ct = data[campaign_id_offset : campaign_id_offset + 0x10]
    except Exception as e:
        log.debug("There was an exception extracting the campaign id: %s", str(e))
        log.debug(traceback.format_exc())
        return False, False, False

    try:
        # Get botnet id ciphertext
        botnet_id_rva = pe.get_rva_from_offset(
            config_match.start() + int(len(config_match.group("campaign_id_ins"))) + int(len(config_match.group("botnet_id_ins")))
        )
        botnet_id_offset = pe.get_offset_from_rva(
            botnet_id_rva + int.from_bytes(config_match.group("botnet_id"), byteorder="little")
        )
        botnet_id_ct = data[botnet_id_offset : botnet_id_offset + 0x10]
    except Exception as e:
        log.debug("There was an exception extracting the botnet id: %s", str(e))
        log.debug(traceback.format_exc())
        return False, False, False

    # Get C2 ciphertext
    try:
        c2s_rva = pe.get_rva_from_offset(
            config_match.start()
            + int(len(config_match.group("campaign_id_ins")))
            + int(len(config_match.group("botnet_id_ins")))
            + int(len(config_match.group("c2s_ins")))
        )
        c2s_offset = pe.get_offset_from_rva(c2s_rva + int.from_bytes(config_match.group("c2s"), byteorder="little"))
        c2s_ct = data[c2s_offset : c2s_offset + 0x400]
    except Exception as e:
        log.debug("There was an exception extracting the C2s: %s", str(e))
        log.debug(traceback.format_exc())
        return False, False, False

    return campaign_id_ct, botnet_id_ct, c2s_ct


def extract_2024(pe, filebuf):
    config = {}
    rc4key_init_offset = 0
    botid_init_offset = 0
    port_init_offset = 0
    dga1_init_offset = 0
    dga2_init_offset = 0
    botidlgt_init_offset = 0

    matches = yara_rules.match(data=filebuf)
    if not matches:
        return

    for match in matches:
        if match.rule != "BumbleBee":
            continue
        for item in match.strings:
            for instance in item.instances:
                if "$rc4key" in item.identifier:
                    rc4key_init_offset = int(instance.offset)
                elif "$botidlgt" in item.identifier:
                    botidlgt_init_offset = int(instance.offset)
                elif "$botid" in item.identifier:
                    botid_init_offset = int(instance.offset)
                elif "$port" in item.identifier:
                    port_init_offset = int(instance.offset)
                elif "$dga1" in item.identifier:
                    dga1_init_offset = int(instance.offset)
                elif "$dga2" in item.identifier:
                    dga2_init_offset = int(instance.offset)

    if not rc4key_init_offset:
        return

    key_offset = pe.get_dword_from_offset(rc4key_init_offset + 57)
    key_rva = pe.get_rva_from_offset(rc4key_init_offset + 61) + key_offset
    key = pe.get_string_at_rva(key_rva)

    botid = ""
    botid_offset = pe.get_dword_from_offset(botid_init_offset + 51)
    botid_rva = pe.get_rva_from_offset(botid_init_offset + 55) + botid_offset
    botid_len_offset = pe.get_dword_from_offset(botidlgt_init_offset + 31)
    botid_data = pe.get_data(botid_rva)[:botid_len_offset]
    with suppress(Exception):
        botid = ARC4.new(key).decrypt(botid_data).split(b"\x00")[0].decode()

    port = ""
    port_offset = pe.get_dword_from_offset(port_init_offset + 23)
    port_rva = pe.get_rva_from_offset(port_init_offset + 27) + port_offset
    port_len_offset = pe.get_dword_from_offset(botidlgt_init_offset + 4)
    port_data = pe.get_data(port_rva)[:port_len_offset]
    with suppress(Exception):
        port = ARC4.new(key).decrypt(port_data).split(b"\x00")[0].decode()

    dgaseed_offset = pe.get_dword_from_offset(dga1_init_offset + 15)
    dgaseed_rva = pe.get_rva_from_offset(dga1_init_offset + 19) + dgaseed_offset
    dgaseed_data = pe.get_qword_at_rva(dgaseed_rva)

    numdga_offset = pe.get_dword_from_offset(dga1_init_offset + 22)
    numdga_rva = pe.get_rva_from_offset(dga1_init_offset + 26) + numdga_offset
    numdga_data = pe.get_string_at_rva(numdga_rva)

    domainlen_offset = pe.get_dword_from_offset(dga2_init_offset + 3)
    domainlen_rva = pe.get_rva_from_offset(dga2_init_offset + 7) + domainlen_offset
    domainlen_data = pe.get_string_at_rva(domainlen_rva)

    tld_offset = pe.get_dword_from_offset(dga2_init_offset + 37)
    tld_rva = pe.get_rva_from_offset(dga2_init_offset + 41) + tld_offset
    tld_data = pe.get_string_at_rva(tld_rva).decode()

    config = {
        "dga_seed": str(int(dgaseed_data)),
        "cryptokey": key.decode(),
        "cryptokey_type": "RC4",
        "raw": {
            "TLD": tld_data,
            "Domain length": domainlen_data.decode(),
            "Number DGA domains": numdga_data.decode(),
        },
    }
    if port:
        config["raw"]["port"] = port
    if botid:
        config["botnet"] = botid

    return config


def extract_config(data):
    """
    Extract key and config and decrypt
    """
    cfg = {}
    pe = None
    try:
        with suppress(Exception):
            pe = pefile.PE(data=data, fast_load=True)

        if not pe:
            return cfg

        key_regex = re.compile(rb"(\x48\x8D.(?P<key>....)\x80\x3D....\x00)", re.DOTALL)
        regex = re.compile(
            rb"(?P<campaign_id_ins>\x48\x8D.(?P<campaign_id>....))(?P<botnet_id_ins>\x48\x8D.(?P<botnet_id>....))(?P<c2s_ins>\x48\x8D.(?P<c2s>....))",
            re.DOTALL,
        )
        # Extract Key
        key_match = list(key_regex.finditer(data))
        if len(key_match) > 1:
            for index, match in enumerate(key_match):
                key = extract_key_data(data, pe, match)
                if not key:
                    continue
                if index == 0:
                    cfg["botnet"] = key.decode()
                elif index == 1:
                    cfg["campaign"] = key.decode()
                elif index == 2:
                    cfg.setdefault("raw", {})["Data"] = key.decode("latin-1")
                elif index == 3:
                    cfg["CNCs"] = list(key.decode().split(","))
        elif len(key_match) == 1:
            key = extract_key_data(data, pe, key_match[0])
            if not key:
                return cfg
            cfg["cryptokey"] = key.decode()
            cfg["cryptokey_type"] = "RC4"
        # Extract config ciphertext
        config_match = regex.search(data)
        campaign_id, botnet_id, c2s = extract_config_data(data, pe, config_match)
        if campaign_id:
            cfg["campaign"] = ARC4.new(key).decrypt(campaign_id).split(b"\x00")[0].decode()
        if botnet_id:
            cfg["botnet"] = ARC4.new(key).decrypt(botnet_id).split(b"\x00")[0].decode()
        if c2s:
            cfg["CNCs"] = list(ARC4.new(key).decrypt(c2s).split(b"\x00")[0].decode().split(","))
    except Exception as e:
        log.exception("This is broken: %s", str(e))

    if not cfg:
        cfg = extract_2024(pe, data)

    return cfg


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))

detection_rule = """
rule BumbleBeeLoader
{
    meta:
        author = "enzo & kevoreilly"
        description = "BumbleBee Loader"
        cape_type = "BumbleBeeLoader Payload"
    strings:
        $str_set = {C7 ?? 53 65 74 50}
        $str_path = {C7 4? 04 61 74 68 00}
        $openfile = {4D 8B C? [0-70] 4C 8B C? [0-70] 41 8B D? [0-70] 4? 8B C? [0-70] FF D?}
        $createsection = {89 44 24 20 FF 93 [2] 00 00 80 BB [2] 00 00 00 8B F? 74}
        $hook = {48 85 C9 74 20 48 85 D2 74 1B 4C 8B C9 45 85 C0 74 13 48 2B D1 42 8A 04 0A 41 88 01 49 FF C1 41 83 E8 01 75 F0 48 8B C1 C3}
        $iternaljob = "IternalJob"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule BumbleBeeShellcode
{
    meta:
        author = "kevoreilly"
        description = "BumbleBee Loader 2023"
        cape_type = "BumbleBeeLoader Payload"
        packed = "51bb71bd446bd7fc03cc1234fcc3f489f10db44e312c9ce619b937fad6912656"
    strings:
        $setpath = "setPath"
        $alloc = {B8 01 00 00 00 48 6B C0 08 48 8D 0D [2] 00 00 48 03 C8 48 8B C1 48 89 [3] 00 00 00 8B 44 [2] 05 FF 0F 00 00 25 00 F0 FF FF 8B C0 48 89}
        $hook = {48 85 C9 74 20 48 85 D2 74 1B 4C 8B C9 45 85 C0 74 13 48 2B D1 42 8A 04 0A 41 88 01 49 FF C1 41 83 E8 01 75 F0 48 8B C1 C3}
        $algo = {41 8B C1 C1 E8 0B 0F AF C2 44 3B C0 73 6A 4C 8B [3] 44 8B C8 B8 00 08 00 00 2B C2 C1 E8 05 66 03 C2 8B 94 [2] 00 00 00}
        $cape_string = "cape_options"
    condition:
        2 of them and not $cape_string
}

rule BumbleBee
{
    meta:
        author = "enzo & kevoreilly"
        description = "BumbleBee Payload"
        cape_type = "BumbleBee Payload"
    strings:
        $antivm1 = {84 C0 74 09 33 C9 FF [4] 00 CC 33 C9 E8 [3] 00 4? 8B C8 E8}
        $antivm2 = {84 C0 0F 85 [2] 00 00 33 C9 E8 [4] 48 8B C8 E8 [4] 48 8D 85}
        $antivm3 = {33 C9 E8 [4] 48 8B C8 E8 [4] 83 CA FF 48 8B 0D [4] FF 15}
        $antivm4 = {33 C9 E8 [4] 48 8B C8 E8 [4] 90 48 8B 05 [4] 48 85 C0 74}
	    $str_ua = "bumblebee"
        $str_gate = "/gate"
    condition:
        uint16(0) == 0x5A4D and (any of ($antivm*) or all of ($str_*))
}

rule BumbleBee2024
{
    meta:
        author = "enzok"
        description = "BumbleBee 2024"
        cape_type = "BumbleBee Payload"
        packed = "a20d56ab2e53b3a599af9904f163bb2e1b2bb7f2c98432519e1fbe87c3867e66"
    strings:
        $rc4key = {48 [6] 48 [6] E8 [4] 4C 89 AD [4] 4C 89 AD [4] 4C 89 B5 [4] 4C 89 AD [4] 44 88 AD [4] 48 8D 15 [4] 44 38 2D [4] 75}
        $botidlgt = {4C 8B C1 B? 4F 00 00 00 48 8D 0D [4] E8 [4] 4C 8B C3 48 8D 0D [4] B? 4F 00 00 00 E8 [4] 4C 8B C3 48 8D 0D [4] B? FF 0F 00 00 E8}
        $botid = {90 48 [6] E8 [4] 4C 89 AD [4] 4C 89 AD [4] 4C 89 B5 [4] 4C 89 AD [4] 44 88 AD [4] 48 8D 15 [4] 44 38 2D [4] 75}
        $port = {4C 89 6D ?? 4C 89 6D ?? 4c 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8D 05 [4] 44 38 2D [4] 75}
        $dga1 = {4C 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8B 1D [4] 48 8D 0D [4] E8 [4] 8B F8}
        $dga2 = {48 8D 0D [4] E8 [4] 8B F0 4C 89 6D ?? 4C 89 6D ?? 4C 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8D 15 [4] 44 38 2D [4] 75}
    condition:
        $rc4key and all of ($botid*) and 2 of ($port, $port, $dga1, $dga2)
}
"""
