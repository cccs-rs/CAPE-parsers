import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel
from parsers.CAPE.XWorm import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="XWorm", other=raw_config)

    return parsed_result


class XWorm(Extractor):
    author = "kevoreilly"
    family = "XWorm"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
