#!/usr/bin/env python3
# ----- Python 3.10.10 -----

from modules.logging import *
from modules.nmap_scan import NmapPortScan
from modules.environvars import *
from flask import Flask, request, jsonify
from pymongo import MongoClient
import redis
import threading
import time
import datetime

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

redis_connect = redis.Redis.from_url(REDIS_URI)
mongo_client = MongoClient(MONGODB_URI)
mongodb = mongo_client[MONGODB_NAME]
mongo_collection = mongodb[MONGODB_COLLECTION]

def getcache(host):
    try:
        current_time = int(time.time())
        epoch_time = redis_connect.hget('scanstamp', host)
        return int(epoch_time)
    except Exception:
        logger.error(traceback.format_exc())
        return False

def setcache(host):
    try:
        current_time = int(time.time())
        redis_connect.hset('scanstamp', host, current_time)
        return True
    except Exception:
        logger.error(traceback.format_exc())
        return False

def Scan_Worker(host):
    try:
        try:
            result = NmapPortScan(host)
            data = {'_id': host, 'data': result}
            mongo_collection.update_one({"_id": host}, {"$set": data}, upsert=True)
            logger.info('Scan {} successfully'.format(host))
            pass
        except Exception:
            logger.error(traceback.format_exc())
            pass
        setcache(host)
        redis_connect.srem("running", host)
    except Exception:
        logger.error(traceback.format_exc())

@app.route('/api/portscan/scan/<host>', methods=['GET'])
def scan(host):
    try:
        try:
            current_time = int(time.time())
            last_update = getcache(host)
            ago = current_time - last_update
            if current_time - last_update < MIN_RESCAN_TIME:
                return jsonify({'host': host, 'status': 'finished', 'last_update': str(datetime.timedelta(seconds=ago)), 'message': 'Request to GET /api/portscan/result/{}'.format(host)}), 200
            else:
                pass
        except Exception:
            pass
        host = host
        smembers = [ str(row, 'utf-8') for row in redis_connect.smembers("running") ]
        if host in smembers:
            return jsonify({'host': host, 'status': 'still scanning'}), 200
        redis_connect.sadd("running", host)
        scan_thread = threading.Thread(target=Scan_Worker, name="nmap_scan", args=(host,))
        scan_thread.start()
        return jsonify({'host': host, 'status': 'started'}), 200
    except Exception:
        logger.error(traceback.format_exc())
        return jsonify({'error': 500, 'message': 'please contact the administrator'}), 500

@app.route('/api/portscan/result/all', methods=['GET'])
def allresult():
    try:
        result = mongo_collection.find()
        result = list(result)
        if result is None:
            return jsonify({'status': None, 'data': 'is empty'}), 200
        return jsonify(result), 200
    except Exception:
        logger.error(traceback.format_exc())
        return jsonify({'error': 500, 'message': 'please contact the administrator'}), 500

@app.route('/api/portscan/result/<host>', methods=['GET'])
def singleresult(host):
    try:
        result = mongo_collection.find_one({"_id": host})
        if result is None:
            return jsonify({'host': host, 'data': None}), 200
        return jsonify({'host': host, 'data': result['data']}), 200
    except Exception:
        logger.error(traceback.format_exc())
        return jsonify({'error': 500, 'message': 'please contact the administrator'}), 500

if __name__ == '__main__':
    app.run(host=LISTEN_ADDR, port=LISTEN_PORT, debug=APP_DEBUG)
