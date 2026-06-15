# Derived from https://github.com/RussianPanda95/Configuration_extractors/blob/main/aurora_config_extractor.py
# A huge thank you to RussianPanda95

import base64
import json
import logging
import re

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

patterns = [
    rb"[A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{4})*(?=[0-9]+)",
    rb"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)",
]


def extract_config(data):
    config_dict = {}
    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, data))

    matches = [match for match in matches if len(match) > 90]

    # Search for the configuration module in the binary
    config_match = re.search(rb"eyJCdWlsZElEI[^&]{0,400}", data)
    if config_match:
        matched_string = config_match.group(0).decode("utf-8")
        decoded_str = base64.b64decode(matched_string).decode()
        for item in decoded_str.split(","):
            key = item.split(":")[0].strip("{").strip('"')
            value = item.split(":")[1].strip('"')
            if key == "IP":
                config_dict["CNCs"] = [f"tcp://{value}"]
            elif key == "BuildID":
                config_dict["build"] = value
            else:
                if value:
                    config_dict.setdefault("raw", {})[key] = value

    grabber_found = False

    # Extracting the modules
    for match in matches:
        match_str = match.decode("utf-8")
        decoded_str = base64.b64decode(match_str)

        if b"DW" in decoded_str:
            data_dict = json.loads(decoded_str)
            for elem in data_dict:
                if elem["Method"] == "DW":
                    config_dict.setdefault("raw", {})["Loader module"] = elem

        if b"PS" in decoded_str:
            data_dict = json.loads(decoded_str)
            for elem in data_dict:
                if elem["Method"] == "PS":
                    config_dict.setdefault("raw", {})["PowerShell module"] = elem

        if b"Path" in decoded_str:
            grabber_found = True
            break
        else:
            grabber_match = re.search(b"W3siUGF0aCI6.{116}", data)
            if grabber_match:
                encoded_string = grabber_match.group(0)
                decoded_str = base64.b64decode(encoded_string)
                grabber_str = decoded_str[:95].decode("utf-8", errors="ignore")
                cleanup_str = grabber_str.split("[")[-1].split("]")[0]

                if not grabber_found:
                    grabber_found = True
                    config_dict.setdefault("raw", {})["Grabber"] = cleanup_str

    return config_dict

detection_rule = """
rule AuroraStealer {

    meta:
        author          = "Johannes Bader @viql"
        version         = "v1.0"
        tlp             = "TLP:WHITE"
        date            = "2022-12-14"
        description     = "detects Aurora Stealer samples"
        malpedia_family = "win.aurora_stealer"
        hash1_md5        = "51c153501e991f6ce4901e6d9578d0c8"
        hash1_sha1       = "3816f17052b28603855bde3e57db77a8455bdea4"
        hash1_sha256     = "c148c449e1f6c4c53a7278090453d935d1ab71c3e8b69511f98993b6057f612d"
        hash2_md5        = "65692e1d5b98225dbfb1b6b2b8935689"
        hash2_sha1       = "0b51765c175954c9e47c39309e020bcb0f90b783"
        hash2_sha256     = "5a42aa4fc8180c7489ce54d7a43f19d49136bd15ed7decf81f6e9e638bdaee2b"
        cape_type        = "AuroraStealer Payload"

    strings:
        $str_func_01 = "main.(*DATA_BLOB).ToByteArray"
        $str_func_02 = "main.Base64Encode"
        $str_func_03 = "main.Capture"
        $str_func_04 = "main.CaptureRect"
        $str_func_05 = "main.ConnectToServer"
        $str_func_06 = "main.CreateImage"
        $str_func_07 = "main.FileExsist"
        $str_func_08 = "main.GetDisplayBounds"
        $str_func_09 = "main.GetInfoUser"
        $str_func_10 = "main.GetOS"
        $str_func_11 = "main.Grab"
        $str_func_12 = "main.MachineID"
        $str_func_13 = "main.NewBlob"
        $str_func_14 = "main.NumActiveDisplays"
        $str_func_15 = "main.PathTrans"
        $str_func_16 = "main.SendToServer_NEW"
        $str_func_17 = "main.SetUsermame"
        $str_func_18 = "main.Zip"
        $str_func_19 = "main.base64Decode"
        $str_func_20 = "main.countupMonitorCallback"
        $str_func_21 = "main.enumDisplayMonitors"
        $str_func_22 = "main.getCPU"
        $str_func_23 = "main.getDesktopWindow"
        $str_func_24 = "main.getGPU"
        $str_func_25 = "main.getMasterKey"
        $str_func_26 = "main.getMonitorBoundsCallback"
        $str_func_27 = "main.getMonitorRealSize"
        $str_func_28 = "main.sysTotalMemory"
        $str_func_29 = "main.xDecrypt"
        $str_type_01 = "type..eq.main.Browser_G"
        $str_type_02 = "type..eq.main.STRUSER"
        $str_type_03 = "type..eq.main.Telegram_G"
        $str_type_04 = "type..eq.main.Crypto_G"
        $str_type_05 = "type..eq.main.ScreenShot_G"
        $str_type_06 = "type..eq.main.FileGrabber_G"
        $str_type_07 = "type..eq.main.FTP_G"
        $str_type_08 = "type..eq.main.Steam_G"
        $str_type_09 = "type..eq.main.DATA_BLOB"
        $str_type_10 = "type..eq.main.Grabber"
        $varia_01 = "\\\\User Data\\\\Local State"
        $varia_02 = "\\\\\\\\Opera Stable\\\\\\\\Local State"
        $varia_03 = "Reconnect 1"
        $varia_04 = "@ftmone"
        $varia_05 = "^user^"
        $varia_06 = "wmic path win32_VideoController get name"
        $varia_07 = "\\\\AppData\\\\Roaming\\\\Telegram Desktop\\\\tdata"
        $varia_08 = "C:\\\\Windows.old\\\\Users\\\\"
        $varia_09 = "ScreenShot"
        $varia_10 = "Crypto"
    condition:
        uint16(0) == 0x5A4D and
        (
            32 of ($str_*) or
            9 of ($varia_*)
        )
}
"""
