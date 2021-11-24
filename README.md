# Class Network 1 - second homework

### Test ipv4
ping -c4 8.8.8.8

### Test ipv6
ping6 localhost

### Test arp
sudo arping ip_of_your_router


## Python virtual env

Install dependency:

`sudo apt-get install -y tshark`

create venv

`python3 -m venv venv`

Activate venv:

`bin/activate`

Deactivate venv:

`deactivate`

Install lib:

`pip install pyshark`