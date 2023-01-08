import concurrent.futures
import sys
from pythonping import ping
import ipaddress

def is_connected(ip_address):
    response = ping(ip_address, verbose=False, count=2, timeout=1)
    if response.packets_lost == 0:
        online.append(ip_address)
    else:
        offline.append(ip_address)

ip_addresses = []
for i in range(255):
    ip_addresses.append("192.168.1.{}".format(str(i)))


def scan_network():
    # create a queue to hold the IP addresses
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # submit the tasks to the executor
        futures = [executor.submit(is_connected, ip_address) for ip_address in ip_addresses]

        # wait for the tasks to complete
        concurrent.futures.wait(futures)
    

def compare():
    if online != online_old:
        print("something changed")
        went_online = list(set(online)-set(online_old))
        went_offline = list(set(online_old)-set(online))
        print(went_online, "\n", went_offline)
    else:
        print("nothing changed")

def main():
    global online
    global offline
    online = []
    offline = []

    while True:
        if sys.getsizeof(online) == 64:
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