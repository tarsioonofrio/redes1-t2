# Class Network 1 - second homework


## Install dependency:

`sudo apt-get install -y tshark`
## Python virtual env

create venv

`python3 -m venv venv`

Activate venv:

`bin/activate`

Deactivate venv:

`deactivate`

Install lib:

`pip install pyshark`

## Build with Cmake (optional)

    pip install cmake --upgrade
    cmake CMakeLists.txt -B cmake-build-debug
    make -C cmake-build-debug

## Run binary

The sniffer receive one argument: number of iterations or packets
to be received. To run for 100 packets:

`cmake-build-debug/redes1_t2 10`

## Run with tshark

Running with tshark both will capture packet simultaneously, 
that is important to validate the system. 
The binary must be in `cmake-build-debug`folder

`sudo bash run.sh`

## Validate

`python main.py`

Test ipv4

`ping -c4 8.8.8.8`

Test ipv6

`ping6 localhost`

Test arp

`sudo arping ip_of_your_router`

