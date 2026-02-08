from contextlib import suppress

try:
    from cape_parsers.utils.strings import extract_strings
except ImportError as e:
    print(f"Problem to import extract_strings: {e}")


def extract_config(data: bytes):
    config = {}
    config_dict = {}
    is_c2_found = False
    with suppress(Exception):
        if data[:2] == b"MZ":
            lines = extract_strings(data=data, on_demand=True, minchars=3)
            if not lines:
                return
        else:
            lines = data.decode().split("\n")
        base = next(i for i, line in enumerate(lines) if "Mozilla/5.0" in line)
        if not base:
            return
        for x in range(1, 32):
            # Data Exfiltration via Telegram
            if "api.telegram.org" in lines[base + x]:
                config_dict["Protocol"] = "Telegram"
                config["CNCs"] = lines[base + x]
                config_dict["Password"] = lines[base + x + 1]
                is_c2_found = True
                break
            # Data Exfiltration via Discord
            elif "discord" in lines[base + x]:
                config_dict["Protocol"] = "Discord"
                config["CNCs"] = [lines[base + x]]
                is_c2_found = True
                break
            # Data Exfiltration via FTP
            elif "ftp:" in lines[base + x]:
                config_dict["Protocol"] = "FTP"
                hostname = lines[base + x]
                username = lines[base + x + 1]
                password = lines[base + x + 2]
                config["CNCs"] = [f"ftp://{username}:{password}@{hostname}"]
                is_c2_found = True
                break
            # Data Exfiltration via SMTP
            elif "@" in lines[base + x]:
                config_dict["Protocol"] = "SMTP"
                if lines[base + x - 2].isdigit() and len(lines[base + x - 2]) <= 5:  # check if length <= highest Port 65535
                    # minchars 3 so Ports < 100 do not appear in strings / TBD: michars < 3
                    config_dict["Port"] = lines[base + x - 2]
                elif lines[base + x - 2] in {"true", "false"} and lines[base + x - 3].isdigit() and len(lines[base + x - 3]) <= 5:
                    config_dict["Port"] = lines[base + x - 3]
                config_dict["CNCs"] = [lines[base + +x - 1]]
                config_dict["Username"] = lines[base + x]
                config_dict["Password"] = lines[base + x + 1]
                if "@" in lines[base + x + 2]:
                    config_dict["EmailTo"] = lines[base + x + 2]
                is_c2_found = True
                break
        # Get Persistence Payload Filename
        for x in range(2, 22):
            # Only extract Persistence Filename when a C2 is detected.
            if ".exe" in lines[base + x] and is_c2_found:
                config_dict["Persistence_Filename"] = lines[base + x]
                break
        # Get External IP Check Services
        externalipcheckservices = []
        for x in range(-4, 19):
            if "ipify.org" in lines[base + x] or "ip-api.com" in lines[base + x]:
                externalipcheckservices.append(lines[base + x])
        if externalipcheckservices:
            config_dict["ExternalIPCheckServices"] = externalipcheckservices

        # Data Exfiltration via HTTP(S)
        temp_match = ["http://", "https://"]  # TBD: replace with a better url validator (Regex)
        if "Protocol" not in config_dict.keys():
            for index, string in enumerate(lines[base:]):
                if string == "Win32_BaseBoard":
                    for x in range(1, 8):
                        if any(s in lines[base + index + x] for s in temp_match):
                            config_dict["Protocol"] = "HTTP(S)"
                            config["CNCs"] = lines[base + index + x]
                            break
    if config or config_dict:
        config.setdefault("raw", config_dict)

        # If the data exfiltration is done through SMTP, then patch the extracted CNCs to include SMTP credentials
        if config_dict.get("Protocol") == "SMTP":
            config['CNCs'] = [f"smtp://{config_dict.get('Username')}:{config_dict.get('Password')}@{domain}:{config_dict.get('Port','587')}" for domain in config_dict.get('CNCs', [])]

        return config

if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))

detection_rule = """
rule agent_tesla
{
    meta:
        description = "Detecting HTML strings used by Agent Tesla malware"
        author = "Stormshield"
        version = "1.0"

    strings:
        $html_username    = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_pc_name     = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_os_name     = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
        $html_os_platform = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_clipboard   = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

    condition:
        3 of them
}

rule AgentTesla
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla Payload"
        cape_type = "AgentTesla Payload"
    strings:
        $string1 = "smtp" wide
        $string2 = "appdata" wide
        $string3 = "76487-337-8429955-22614" wide
        $string4 = "yyyy-MM-dd HH:mm:ss" wide
        //$string5 = "%site_username%" wide
        $string6 = "webpanel" wide
        $string7 = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:" wide
        $string8 = "<br>IP Address&nbsp;&nbsp;:" wide

        $agt1 = "IELibrary.dll" ascii
        $agt2 = "C:\\\\Users\\\\Admin\\\\Desktop\\\\IELibrary\\\\IELibrary\\\\obj\\\\Debug\\\\IELibrary.pdb" ascii
        $agt3 = "GetSavedPasswords" ascii
        $agt4 = "GetSavedCookies" ascii
    condition:
        uint16(0) == 0x5A4D and (all of ($string*) or 3 of ($agt*))
}

rule AgentTeslaV2 {
    meta:
        author = "ditekshen"
        description = "AgenetTesla Type 2 Keylogger payload"
        cape_type = "AgentTesla Payload"
    strings:
        $s1 = "get_kbHook" ascii
        $s2 = "GetPrivateProfileString" ascii
        $s3 = "get_OSFullName" ascii
        $s4 = "get_PasswordHash" ascii
        $s5 = "remove_Key" ascii
        $s6 = "FtpWebRequest" ascii
        $s7 = "logins" fullword wide
        $s8 = "keylog" fullword wide
        $s9 = "1.85 (Hash, version 2, native byte-order)" wide

        $cl1 = "Postbox" fullword ascii
        $cl2 = "BlackHawk" fullword ascii
        $cl3 = "WaterFox" fullword ascii
        $cl4 = "CyberFox" fullword ascii
        $cl5 = "IceDragon" fullword ascii
        $cl6 = "Thunderbird" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*)) or (6 of ($s*) and 2 of ($cl*))
}

rule AgentTeslaV3 {
    meta:
        author = "ditekshen"
        description = "AgentTeslaV3 infostealer payload"
        cape_type = "AgentTesla payload"
    strings:
        // --- High Fidelity Indicators (Malware Specific) ---
        $s_specific1 = "get_kbok" fullword ascii
        $s_specific2 = "get_CHoo" fullword ascii
        $s_specific3 = "KillTorProcess" fullword ascii
        $s_specific4 = "GetMozilla" ascii
        $s_specific5 = "torbrowser" wide
        $s_specific6 = "bot%telegramapi%" wide
        $s_specific7 = "%chatid%" wide
        
        // Known AgentTesla Typo (High Confidence)
        $s_typo      = "set_Lenght" fullword ascii

        // --- Config / Stack Strings (Unique data structures) ---
        $m1 = "yyyy-MM-dd hh-mm-ssCookieapplication/zipSCSC_.jpegScreenshotimage/jpeg/log.tmpKLKL_.html<html></html>Logtext/html[]Time" ascii
        $m2 = "%image/jpg:Zone.Identifier\\\\tmpG.tmp%urlkey%-f \\\\Data\\\\Tor\\\\torrcp=%PostURL%127.0.0.1POST+%2B" ascii
        $m3 = ">{CTRL}</font>Windows RDPcredentialpolicyblobrdgchrome{{{0}}}CopyToComputeHashsha512CopySystemDrive\\\\WScript.ShellRegReadg401" ascii
        $m4 = "%startupfolder%\\\\%insfolder%\\\\%insname%/\\\\%insfolder%\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run%insregname%SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\StartupApproved\\\\RunTruehttp" ascii
        $m5 = "\\\\WindowsLoad%ftphost%/%ftpuser%%ftppassword%STORLengthWriteCloseGetBytesOpera" ascii

        // --- Generic Functions (Require other indicators to match) ---
        // These are legitimate on their own, but suspicious in context
        $s_generic1 = "set_UseShellExecute" fullword ascii
        $s_generic2 = "set_IsBodyHtml" fullword ascii
        $s_generic3 = "set_AllowAutoRedirect" fullword ascii
        $s_generic4 = "set_RedirectStandardOutput" fullword ascii

    condition:
        (
            // 1. Strongest: Match any of the unique config blobs
            2 of ($m*)
        ) or (
            uint16(0) == 0x5a4d and
            (
                // 2. Strong: Match specific malware function names
                5 of ($s_specific*) or
                
                // 3. Combined: The Typo + Generic email/process functions
                ($s_typo and 4 of ($s_generic*))
            )
        )
}

rule AgentTeslaV4
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla Payload"
        cape_type = "AgentTesla Payload"
        packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
    strings:
        $decode1 = {(07|FE 0C 01 00) (07|FE 0C 01 00) 8E 69 (17|20 01 00 00 00) 63 8F ?? 00 00 01 25 47 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A D2 61 D2 52}
        $decode2 = {(07|FE 0C 01 00) (08|FE 0C 02 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (11 07|FE 0C 07 00) 91 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A 61 D2 61 D2 52}
        $decode3 = {(07|FE 0C 01 00) (11 07|FE 0C 07 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (08|FE 0C 02 00) 91 61 D2 52}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule AgentTeslaV4JIT
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla JIT-compiled native code"
        cape_type = "AgentTesla Payload"
        packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
    strings:
        $decode1 = {8B 01 8B 40 3C FF 50 10 8B C8 E8 [4] 89 45 CC B8 1A 00 00 00}
        $decode2 = {83 F8 18 75 2? 8B [2-5] D1 F8}
        $decode3 = {8D 4C 0? 08 0F B6 01 [0-3] 0F B6 5? 04 33 C2 88 01 B8 19 00 00 00}
    condition:
        2 of them
}

rule AgentTeslaV5 {
    meta:
      author = "ClaudioWayne"
      description = "AgentTeslaV5 infostealer payload"
      cape_type = "AgentTesla payload"
      sample = "893f4dc8f8a1dcee05a0840988cf90bc93c1cda5b414f35a6adb5e9f40678ce9"
    strings:
        $template1 = "<br>User Name: " fullword wide
        $template2 = "<br>Username: " fullword wide
        $template3 = "<br>RAM: " fullword wide
        $template4 = "<br>Password: " fullword wide
        $template5 = "<br>OSFullName: " fullword wide
        $template6 = "<br><hr>Copied Text: <br>" fullword wide
        $template7 = "<br>CPU: " fullword wide
        $template8 = "<br>Computer Name: " fullword wide
        $template9 = "<br>Application: " fullword wide

        $chromium_browser1 = "Comodo\\\\Dragon\\\\User Data" fullword wide
        $chromium_browser2 = "Fenrir Inc\\\\Sleipnir5\\\\setting\\\\modules\\\\ChromiumViewer" fullword wide
        $chromium_browser3 = "Google\\\\Chrome\\\\User Data" fullword wide
        $chromium_browser4 = "Elements Browser\\\\User Data" fullword wide
        $chromium_browser5 = "Yandex\\\\YandexBrowser\\\\User Data" fullword wide
        $chromium_browser6 = "MapleStudio\\\\ChromePlus\\\\User Data" fullword wide

        $mozilla_browser1 = "\\\\Mozilla\\\\SeaMonkey\\\\" fullword wide
        $mozilla_browser2 = "\\\\K-Meleon\\\\" fullword wide
        $mozilla_browser3 = "\\\\NETGATE Technologies\\\\BlackHawk\\\\" fullword wide
        $mozilla_browser4 = "\\\\Thunderbird\\\\" fullword wide
        $mozilla_browser5 = "\\\\8pecxstudios\\\\Cyberfox\\\\" fullword wide
        $mozilla_browser6 = "360Chrome\\\\Chrome\\\\User Data" fullword wide
        $mozilla_browser7 = "\\\\Mozilla\\\\Firefox\\\\" fullword wide

        $database1 = "Berkelet DB" fullword wide
        $database2 = " 1.85 (Hash, version 2, native byte-order)" fullword wide
        $database3 = "00061561" fullword wide
        $database4 = "key4.db" fullword wide
        $database5 = "key3.db" fullword wide
        $database6 = "global-salt" fullword wide
        $database7 = "password-check" fullword wide

        $software1 = "\\\\FileZilla\\\\recentservers.xml" fullword wide
        $software2 = "\\\\VirtualStore\\\\Program Files (x86)\\\\FTP Commander\\\\Ftplist.txt" fullword wide
        $software3 = "\\\\The Bat!" fullword wide
        $software4 = "\\\\Apple Computer\\\\Preferences\\\\keychain.plist" fullword wide
        $software5 = "\\\\MySQL\\\\Workbench\\\\workbench_user_data.dat" fullword wide
        $software6 = "\\\\Trillian\\\\users\\\\global\\\\accounts.dat" fullword wide
        $software7 = "SOFTWARE\\\\Martin Prikryl\\\\WinSCP 2\\\\Sessions" fullword wide
        $software8 = "FTP Navigator\\\\Ftplist.txt" fullword wide
        $software9 = "NordVPN" fullword wide
        $software10 = "JDownloader 2.0\\\\cfg" fullword wide
    condition:
        uint16(0) == 0x5a4d and 4 of ($template*) and 3 of ($chromium_browser*) and 3 of ($mozilla_browser*) and 3 of ($database*) and 5 of ($software*)
}

"""
