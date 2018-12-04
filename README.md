# ThunderDNS
This tool can forward TCP traffic over DNS protocol. Non-compile clients + socks5 support.

## Run

### Setting up NS records on our domain:

![](https://habrastorage.org/webt/_q/p4/er/_qp4erwn54g5nqqxmlnnquv1itk.png)

Please wait for clearing DNS-cache.

### Simple server run:
`python3 ./server.py --domain oversec.ru`

### Simple server run (Dockerfile):
`docker run <imageid> -e DOMAIN='<domain>'`

### Simple client run (Bash):
`bash ./bash_client.sh -d oversec.ru -n <clientname>`

### Simple client run (PowerShell):
`PS:> ./ps_client.ps1 -domain oversec.ru -clientname <clientname>`

### Show registered clients list:
`python3 ./proxy.py --dns 138.197.178.150 --dns_port 9091 --clients`

### Run proxy:
`python3 ./proxy.py --dns 138.197.178.150 --dns_port 9091 --socks5 --localport 9090 --client 1`

### Video demonstration
[![msf](http://img.youtube.com/vi/N6Nm9mWFI6w/0.jpg)](https://www.youtube.com/watch?v=N6Nm9mWFI6w)

[![socks5](http://img.youtube.com/vi/xSM-Dl1uo1k/0.jpg)](https://www.youtube.com/watch?v=xSM-Dl1uo1k)
