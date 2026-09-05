import importlib.util
import sys
import os

from rat_king_parser.rkp import RATConfigParser

HAVE_ASYNCRAT_COMMON = False
module_file_path = "/opt/CAPEv2/data/asyncrat_common.py"
if os.path.exists(module_file_path):
    try:
        module_name = os.path.basename(module_file_path).replace(".py", "")
        spec = importlib.util.spec_from_file_location(module_name, module_file_path)
        asyncrat_common = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = asyncrat_common
        spec.loader.exec_module(asyncrat_common)
        HAVE_ASYNCRAT_COMMON = True
    except Exception as e:
        print("Error loading asyncrat_common.py", e)


def extract_config(data: bytes):
    config = RATConfigParser(data=data, remap_config=True).report.get("config", {})
    if config and HAVE_ASYNCRAT_COMMON:
        config = asyncrat_common.convert_config(config)

    return config


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    print(extract_config(data))

detection_rule = """
rule XenoRAT {
    meta:
        author = "jeFF0Falltrades"
        cape_type = "XenoRAT payload"
    strings:
        $str_xeno_rat_1 = "xeno rat" wide ascii nocase
        $str_xeno_rat_2 = "xeno_rat" wide ascii nocase
        $str_xeno_update_mgr = "XenoUpdateManager" wide ascii
        $str_nothingset = "nothingset" wide ascii 
        $byte_enc_dec_pre = { 1f 10 8d [4] (0a | 0b) }
        $patt_config = { 72 [3] 70 80 [3] 04 }
    condition:
        4 of them and #patt_config >= 5
 }

"""
