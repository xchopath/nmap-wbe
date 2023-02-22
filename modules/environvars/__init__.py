import os

LISTEN_ADDR = os.getenv('LISTEN_ADDR', '0.0.0.0')
LISTEN_PORT = int(os.getenv('LISTEN_PORT', 5000))
APP_DEBUG = eval(os.getenv('APP_DEBUG', True))
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
MONGODB_NAME = os.getenv('MONGODB_NAME', 'ipscan')
REDIS_URI = os.getenv('REDIS_URI', 'redis://localhost:6379/0')
MIN_RESCAN_TIME = int(os.getenv('MIN_RESCAN_TIME', 600))
NMAP_ARGUMENTS = os.getenv('NMAP_ARGUMENTS', '-p - -Pn -T4 -sV --open')
