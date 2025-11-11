# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.community.Amatera import extract_config


def test_amatera():
    with open("tests/data/malware/26db2f20d3d84657af15509ba39f62690a06175c2d5671795e239bdbe3acbaef", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "CNCs": [
                "https://91.98.229.246"
            ],
            "cryptokey": "7640fed98a53856641763683163f4127b9fc00f9a788773c00ee1f2634cec82f",
            "cryptokey_type": "AES"
        }
