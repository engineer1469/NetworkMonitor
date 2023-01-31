import concurrent.futures
from pythonping import ping
import ipaddress
import socket
import struct

def get_ip_prefix():
    host_name = socket.gethostname()
    ip_address = socket.gethostbyname(host_name)
    packed_ip = struct.unpack("!I", socket.inet_aton(ip_address))[0]
    ip_prefix = socket.inet_ntoa(struct.pack("!I", packed_ip & 0xFFFFFF00))
    ip_prefix = ip_prefix[:-1]
    return ip_prefix

def is_connected(ip_address):
    response = ping(ip_address, verbose=False, count=2, timeout=1)
    if response.packets_lost == 0:
        online.append(ip_address)
    else:
        offline.append(ip_address)

def scan_network():
    # create a queue to hold the IP addresses
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # submit the tasks to the executor
        futures = [executor.submit(is_connected, ip_address) for ip_address in ip_addresses]

        # wait for the tasks to complete
        concurrent.futures.wait(futures)
    
def compare():
    if online != online_old:
        print("\n"*50)
        print("something changed")
        went_online = list(set(online)-set(online_old))
        went_offline = list(set(online_old)-set(online))
        print("CAME ONLINE: ", went_online)
        print("WENT OFFLINE: ", went_offline)
        print("Active: ",len(online))
    else:
        print("\n"*50)
        print("nothing changed")
        print("Active: ",len(online))

def main():
    ip_prefix = get_ip_prefix()
    answer = input("Use detected IP prefix?({}) Y/N:".format(ip_prefix))
    if answer != 'Y' and answer != 'y':
        ip_prefix = input("Which prefix should be used?: ")
    global ip_addresses
    ip_addresses = [ip_prefix + str(i) for i in range(1, 256)]
    global online
    global offline
    online = []
    offline = []
    print("SCANNING...")

    while True:
        if len(online) == 0:
            scan_network()
        else:
            global online_old
            global offline_old
            online_old = online
            offline_old = offline
            online = []
            offline = []
            scan_network()
            online = sorted(online, key = ipaddress.IPv4Address)
            offline = sorted(offline, key = ipaddress.IPv4Address)
            compare()

if __name__ == "__main__":
    main()