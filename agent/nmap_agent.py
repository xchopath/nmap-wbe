#!/usr/bin/env python3
#
# Sample command to use:
# API_NMAP_WBE=http://localhost:5000 LOGGING_LEVEL=DEBUG python nmap_agent.py

import nmap
import os
import pandas as pd
import io
import json
import logging
import sys
import traceback
import requests

LOGGING_LEVEL = os.getenv('LOGGING_LEVEL', 'DEBUG')
NMAP_ARGUMENTS = '-p - -Pn -T4 -sV --open'
API_NMAP_WBE = os.getenv('API_NMAP_WBE', 'http://localhost:5000')

try:
    logger = logging.getLogger()
    logger.setLevel(LOGGING_LEVEL)
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: {%(filename)s:%(lineno)d} - %(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
except Exception:
    print('ERROR! logger was not working', traceback.format_exc())
    exit()

def NmapPortScan(host):
    try:
        nm = nmap.PortScanner()
        nm.scan(host, arguments=NMAP_ARGUMENTS)
        df = pd.read_csv(io.StringIO(nm.csv()), delimiter=";")
        json_str = df.to_json(orient='records')
        result = json.loads(json_str)
        resp = []
        for d in result:
            try:
                del d['host']
            except:
                pass
            resp.append(dict(filter(lambda x:x[1], d.items())))
        logger.info('NmapPortScan for {} done'.format(host))
        return resp
    except Exception:
        logger.error(traceback.format_exc())
        return None

try:
    get = requests.get('{API_NMAP_WBE}/api/portscan/agent/task'.format(API_NMAP_WBE=API_NMAP_WBE))
    TARGET = get.json()['host']
    logger.info('Scanning {}...'.format(TARGET))
    scan_result = NmapPortScan(TARGET)
    r = requests.post('{API_NMAP_WBE}/api/portscan/agent/submit/{TARGET}'.format(API_NMAP_WBE=API_NMAP_WBE, TARGET=TARGET), json=scan_result)
    logger.info('Success: {}'.format(r.text))
except Exception:
    logger.error('FAILED! {}'.format(TARGET))
