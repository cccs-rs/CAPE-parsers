import os

import requests

for root, dirs, files in os.walk('../../'):
    for filename in files:
        if filename.endswith('.py'):
            extractor_name = filename[:-3]
            resp = requests.get(f'https://raw.githubusercontent.com/kevoreilly/CAPEv2/refs/heads/master/data/yara/CAPE/{extractor_name}.yar')
            if resp.ok:
                rule_content = resp.text.replace("\\", '\\\\')
                with open(os.path.join(root, filename), 'a') as yar_file:
                    yar_file.write(f'\ndetection_rule = """\n{rule_content}\n"""\n')
