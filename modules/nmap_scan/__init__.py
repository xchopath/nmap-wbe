import nmap
import os
import pandas as pd
import io
import json
from modules.environvars import *
from modules.logging import *

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