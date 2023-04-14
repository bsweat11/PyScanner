import time
import subprocess
import netifaces as net
from scapy.all import *
import socket
import sys
from queue import Queue
import threading



def scan_ports(received):
    #print('opened def scan_ports')
    print_lock = threading.Lock()
    target_scan = received

    global port_list
    port_list = []

    print()

    print(f'\nScanning ports on {target_scan}:\n')
    def portscan(port):
        print(port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            con = s.connect((target_scan,port))
            #print(con) ### returns None
            with print_lock:
                #print(f'[{port}]')
                port
            protocolname = 'tcp'
            service = socket.getservbyport(port, protocolname)
            state = 'open'
            port_list.append({'port': port, 'state': state.upper(), 'service': service.upper()})

            con.close()

        except:
            pass



    def threader():

        while True:
            worker = q.get()

            portscan(worker)
            q.task_done()

    q = Queue()


    for x in range(150):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
        clock_start = time.time()


    for worker in range(1,100):
        q.put(worker)


    q.join()
    print("PORT" + " " * 3 + "STATE" + " " * 3 + "SERVICE")
    print("----   -----   -------")

    for client in port_list:
        print("{}     {:5}   {:10}".format(client['port'], client['state'], client['service']))

def get_nic():
    gateways = net.gateways()
    interfaces = net.interfaces()
    #print(gateways)
    #print(interfaces)
    addrs = (net.ifaddresses(str(interfaces[0])))
    #print(addrs)

    the_gateway = gateways['default'][net.AF_INET][1] ### gets int that has a GW attached
    #print(the_gateway)
    print_gw = net.ifaddresses(the_gateway) #### Lists interfaces with gateway address
    #print(print_gw)
    my_ip = net.ifaddresses(the_gateway)[net.AF_INET][0]['addr'] #### Gets ip address from found interface
    #print(my_ip)
    subnet = net.ifaddresses(the_gateway)[net.AF_INET][0]['netmask']
    SUBNET_DICT = {
        '/1' : '128.0.0.0',
        '/2' : '192.0.0.0',
        '/3' : '224.0.0.0',
        '/4' : '240.0.0.0',
        '/5' : '248.0.0.0',
        '/6' : '252.0.0.0',
        '/7' : '254.0.0.0',
        '/8' : '255.0.0.0',
        '/9' : '255.128.0.0',
        '/10' : '255.192.0.0',
        '/11' : '255.224.0.0',
        '/12' : '255.240.0.0',
        '/13' : '255.248.0.0',
        '/14' : '255.252.0.0',
        '/15' : '255.254.0.0',
        '/16' : '255.255.0.0',
        '/17' : '255.255.128.0',
        '/18' : '255.255.192.0',
        '/19' : '255.255.224.0',
        '/20' : '255.255.240.0',
        '/21' : '255.255.248.0',
        '/22' : '255.255.252.0',
        '/23' : '255.255.254.0',
        '/24' : '255.255.255.0',
        '/25' : '255.255.255.128',
        '/26' : '255.255.255.192',
        '/27' : '255.255.255.224',
        '/28' : '255.255.255.240',
        '/29' : '255.255.255.248',
        '/30' : '255.255.255.252',
        '/31' : '255.255.255.254',
        '/32' : '255.255.255.255',
    }
    #print(subnet)
    for key, v in SUBNET_DICT.items():
        #print(key, v)
        if v == subnet:
            mask = 'CIDR Notation = ' + key
            slash_mask = key
    print()
    NETWORK = my_ip + slash_mask
    net_len = len(NETWORK)
    #print(net_len)
    space_length = (26 - 6) - net_len
    space_string = str(' ' * space_length)
    print('  __________________________')
    print(' |                          |')
    print(' |  [*] Network detected!!  |')
    print(' |                          |')
    print(f' |      {NETWORK}{space_string}|')
    print(' |__________________________|')
    print()
    print()
    yess = 'y'
    noo = 'n'

    for x in range(50):
        program = input('net_scanner$> ').lower()
        if 'port scan' in program:
            cmd_ps = program[10:]
            NETWORK = cmd_ps
            print('printing network')
            print(NETWORK)
            scan_ports(NETWORK)
            break
        elif 'net scan' in program:
            cmd_ns = program[9:]
            NETWORK = cmd_ns
            #print(NETWORK)
            scan_net(NETWORK)
            break
        elif 'help' in program:
            print('\nTo run this program, you must input the command (port scan, net scan) and then the IP or network that you wish to scan.\nFor example, if I wanted to port scan my router, I could input:\n  [net_scanner$>port scan 192.168.1.1')
            print('You could also port scan a range of IP addresses by using a CIDR notation (subnet mask, in CIDR format: 192.168.1.1/24)\n   Please note that port scanning an entire network can take some time to complete.\n   Also note, it may or may not be illegal to port/net scan addresses and/or networks that are not yours.\nUsing the network scanner tool is the same format, for example:\n  [net_scanner$>net scan 192.168.1.1/22\n\n')
            pass
        else:
            print("\nPlease type 'help' if you need assistance")



def scan_net(NETWORK):
    target_net = NETWORK
    print(f'\nScanning network {target_net}:\n')
    arp = ARP(pdst=target_net)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    start_time = time.time()

    #### start scanning... thread
    done = False
    #t = threading.Thread(target=animate(done))

    #t.start()

    for sent, received in result:
        #scan_ports(received.psrc)
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = '* * *'
            pass
        clients.append({'ip': received.psrc, 'mac': received.hwsrc, 'hostname': hostname})
    print()

   # done = True
    ### End scanning... thread

    print("IP" + " " * 18 + "MAC" + " " * 19 + "Hostname")
    print("---------------     -----------------     -------------------------")

    for client in clients:

        print("{:16}    {:18}    {:25}".format(client['ip'], client['mac'], client['hostname'])) #:36}    {
       # time.sleep(.5)
    end_time = time.time()
    print()
    total_time = end_time - start_time
    print('Time taken: ', round(total_time, 2),'s')
    print()
    print()


def main():
    get_nic()
    main()


def main_1():
    print('Author - Brandon Sweat')
    print('Copyright 2023 ')
    print('Program is not to be sold or re-distributed')
    print('Disclaimer: What you choose to do with this tool is of your own accord.\nIt may be illegal to port/net scan addresses and/or networks that are not yours.\n  !! USE AT YOUR OWN RISK !!')

    print(r'''

            _   __     __     _____
           / | / /__  / /_   / ___/_________ _____  ____  ___  _____
          /  |/ / _ \/ __/   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
         / /|  /  __/ /_    ___/ / /__/ /_/ / / / / / / /  __/ /
        /_/ |_/\___/\__/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/


        ''')
    print('[commands]')
    print('----------------------------------------------------------------------')
    print('[port scan] Initiate a port scan for the IP address input\n      e.g. port scan 192.168.1.1')
    print('[net scan] Initiate a network scan, or singular IP scan based on input\n      e.g. net scan 192.168.1.1 OR 192.168.1.1/24')
    print('[help] Type help for more information')




    get_nic()
    main()


main_1()
