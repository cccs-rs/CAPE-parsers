# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.community.Amatera import extract_config


def test_amatera():
    with open("tests/data/malware/26db2f20d3d84657af15509ba39f62690a06175c2d5671795e239bdbe3acbaef", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "xor_key": "852149723",
            "cryptokey": "7640fed98a53856641763683163f4127b9fc00f9a788773c00ee1f2634cec82f",
            "cryptokey_type": "AES",
            "payload_guid_1": "f1575b64-8492-4e8b-b102-4d26e8c70371",
            "payload_guid_2": "08de0189-4e5e-477f-8700-1cd264a45266",
            "fake_c2": "aether100pronotification.table.core.windows.net",
            "CNCs": [
                "https://91.98.229.246"
            ],
        }
    with open("tests/data/malware/674300bf497042020ffa74b4da8e8bc4c0abd95b90c17f55ae0c907ff8fccd53", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "xor_key": "852149723",
            "cryptokey": "7640fed98a53856641763683163f4127b9fc00f9a788773c00ee1f2634cec82f",
            "cryptokey_type": "AES",
            "payload_guid_1": "f1575b64-8492-4e8b-b102-4d26e8c70371",
            "payload_guid_2": "08de2157-a1ab-4275-8705-4eaf40a53c78",
            "fake_c2": "cdn.extremepornvideos.com",
            "CNCs": [
                "https://46.62.199.102"
            ]
        }
