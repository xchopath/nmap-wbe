# Nmap-ws (Cloud Based Port-Scanner)

## Installation

Clone repository
```
git clone https://github.com/xchopath/nmap-ws
cd nmap-ws/
```

**Note:** check your `.env` first before install.

Install with docker compose
```
sudo docker-compose up -d
```

## API Documentation

This environment will run at port `5000` with these endpoints below.

### Endpoint

1. Assign scan task
```
GET /api/portscan/scan/<host>
```

2. Show all results
```
GET /api/portscan/result/all
```

3. Show the result
```
GET /api/portscan/result/<host>
```
