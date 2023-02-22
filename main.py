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
import ipaddress
import random

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

redis_connect = redis.Redis.from_url(REDIS_URI)
mongo_client = MongoClient(MONGODB_URI)
mongodb = mongo_client[MONGODB_NAME]

def validate_ip(host):
    try:
        ip_object = ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

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
            mongodb['openport'].update_one({"_id": host}, {"$set": data}, upsert=True)
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
            return jsonify({'host': host, 'status': 'scanning'}), 200
        redis_connect.sadd("running", host)
        scan_thread = threading.Thread(target=Scan_Worker, name="nmap_scan", args=(host,))
        scan_thread.start()
        return jsonify({'host': host, 'status': 'started'}), 200
    except Exception:
        logger.error(traceback.format_exc())
        return jsonify({'status': 500, 'message': 'please contact the administrator'}), 500

@app.route('/api/portscan/result/<host>', methods=['GET'])
def singleresult(host):
    try:
        result = mongodb['openport'].find_one({"_id": host})
        if result is None:
            return jsonify({'host': host, 'data': None}), 200
        return jsonify({'host': host, 'data': result['data']}), 200
    except Exception:
        logger.error(traceback.format_exc())
        return jsonify({'status': 500, 'message': 'please contact the administrator'}), 500

@app.route('/api/portscan/list', methods=['GET'])
def allresult():
    try:
        result = mongodb['openport'].find({}, {'_id': True, 'data': False})
        result = list(result)
        if result is None:
            return jsonify({'status': None, 'data': 'is empty'}), 200
        data = [ row['_id'] for row in result ]
        return jsonify(data), 200
    except Exception:
        logger.error(traceback.format_exc())
        return jsonify({'status': 500, 'message': 'please contact the administrator'}), 500

@app.route('/api/portscan/agent/assign/<host>', methods=['GET'])
def agentassigntask(host):
    try:
        if not validate_ip(host) == True:
            return jsonify({'status': 400, 'message': '{} invalid ip address'.format(host)}), 400
        redis_connect.sadd("agent:tasklist", host)
        return jsonify({'status': 200, 'message': '{} has been assigned'.format(host)}), 200
    except Exception:
        logger.error(traceback.format_exc())
        return jsonify({'status': 500, 'message': 'please contact the administrator'}), 500

@app.route('/api/portscan/agent/task', methods=['GET'])
def agenttask():
    try:
        tasklist = [ str(row, 'utf-8') for row in redis_connect.smembers("agent:tasklist") ]
        taskhost = random.choice(tasklist)
        redis_connect.srem("agent:tasklist", taskhost)
        return jsonify({'host': taskhost}), 200
    except Exception:
        logger.error(traceback.format_exc())
        return jsonify({'status': 400, 'message': 'could not read any single task'}), 400 

@app.route('/api/portscan/agent/submit/<host>', methods=['POST'])
def agentsubmitreport(host):
    request_data = request.get_json()
    print(request_data)
    result = request_data
    data = {'_id': host, 'data': result}
    mongodb['openport'].update_one({"_id": host}, {"$set": data}, upsert=True)
    logger.info('Update {} successfully'.format(host))
    return jsonify({'host': host, 'message': 'update successfully'}), 200

if __name__ == '__main__':
    app.run(host=LISTEN_ADDR, port=LISTEN_PORT, debug=APP_DEBUG)
