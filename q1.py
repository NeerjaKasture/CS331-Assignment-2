from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.topo import Topo
from mininet.util import dumpNodeConnections
from mininet.cli import CLI
from mininet.node import CPULimitedHost, Controller
from mininet.link import TCLink
import pandas as pd
import time
import argparse

class MyTopo(Topo):
    def build(self,loss=0):
        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')

        # Add links between hosts and switches
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s3)
        self.addLink(h5, s3)
        self.addLink(h6, s4)  
        self.addLink(h7, s4)

        # Add links between switches
        self.addLink(s1, s2)
        self.addLink(s2, s3,loss=loss)
        self.addLink(s3, s4)

import subprocess

def analyze_pcap(pcap_file):

    def run_tshark(command):
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()

    # Extract total bytes for throughput
    total_bytes_cmd = f"tshark -r {pcap_file} -T fields -e frame.len"
    total_bytes_list = run_tshark(total_bytes_cmd).split("\n")
    total_bytes = sum(int(x) for x in total_bytes_list if x.isdigit())

    # Extract TCP payload bytes for goodput (excluding retransmissions)
    payload_bytes_cmd = f"tshark -r {pcap_file} -Y 'tcp.len > 0 and not tcp.analysis.retransmission' -T fields -e tcp.len"
    payload_bytes_list = run_tshark(payload_bytes_cmd).split("\n")
    total_payload_bytes = sum(int(x) for x in payload_bytes_list if x.isdigit())

    # Get total duration from first to last packet
    duration_cmd = f"tshark -r {pcap_file} -T fields -e frame.time_relative | sort -nr | head -1"
    total_duration = float(run_tshark(duration_cmd)) 


    throughput = (total_bytes / total_duration) / 1024  # KBps
    goodput = (total_payload_bytes / total_duration) / 1024 

    # Extract packet loss rate
    lost_segment_cmd = f"tshark -r {pcap_file} -Y 'tcp.analysis.lost_segment' | wc -l"
    total_packets_cmd = f"tshark -r {pcap_file} -Y 'tcp' | wc -l"
    total_packets = int(run_tshark(total_packets_cmd))  
    lost_segments = int(run_tshark(lost_segment_cmd))
    
    packet_loss_rate = (lost_segments / total_packets) * 100  if total_packets>0 else 0 # Convert to percentage

    # Extract max TCP window size
    window_cmd = f"tshark -r {pcap_file} -Y \"tcp.window_size_value\" -T fields -e tcp.window_size_value"
    window_size_list = run_tshark(window_cmd).split("\n")
    max_window_size = max((int(x) for x in window_size_list if x.isdigit()), default=0)


    print(f"Throughput (KBps): {throughput:.2f}")
    print(f"Goodput (KBps): {goodput:.2f}")
    print(f"Packet Loss Rate: {packet_loss_rate:.2f}%")
    print(f"Max TCP Window Size: {max_window_size} bytes")
    

def a(congestion_schemes,net):
 
    h7 = net.get('h7')  # Server
    h1 = net.get('h1')  # Client

    for cc in congestion_schemes:
        pcap_file = f"/tmp/a_{cc}.pcap"
        h7.cmd(f"tcpdump -i h7-eth0 -w {pcap_file} &")
        time.sleep(2)  # Wait for tcpdump to start

        # Start iPerf3 server
        h7.cmd('iperf3 -s -p 5201 -D &')
        time.sleep(2)  # Wait for server to start

        print(f"Running iperf3 test from h1 to h7 with TCP {cc}")

        # Run iPerf3 as a client
        result = h1.cmd(f'iperf3 -c {h7.IP()} -p 5201 -b 10M -P 10 -t 150 -C {cc}')
        

        # Stop iPerf3 server
        h7.cmd('pkill -f iperf3')

        h7.cmd("pkill -f tcpdump")
        print(f"Packet capture saved to {pcap_file}")
        
        print(f"Metrics for TCP {cc} :") 
        analyze_pcap(pcap_file)

        time.sleep(5)  # Wait before the next test


    net.stop()

def b(congestion_schemes,net):
    
    h7 = net.get('h7')  
    h1 = net.get('h1')  
    h3 = net.get('h3') 
    h4 = net.get('h4') 
    s4 = net.get('s4')


    for cc in congestion_schemes:
        print(f"Running tests with {cc} congestion control scheme...")
        
        
        h1.cmd(f"tcpdump -i h1-eth0 -w /tmp/b_{cc}_h1.pcap &")
        h3.cmd(f"tcpdump -i h3-eth0 -w /tmp/b_{cc}_h3.pcap &")
        h4.cmd(f"tcpdump -i h4-eth0 -w /tmp/b_{cc}_h4.pcap &")

        time.sleep(2)  # Wait for tcpdump to start

        h7.cmd(f'iperf3 -s -p 5201 -D &')
        time.sleep(2)  # Wait for server to start

        # Start H1 at T=0s (runs for 150s)
        print("Starting H1 at T=0s...")
        h1.cmd(f'iperf3 -c {h7.IP()} -p 5201 -b 10M -P 10 -t 150 -C {cc} &')

        # Start H3 at T=15s (runs for 120s)
        time.sleep(15)
        print("Starting H3 at T=15s...")
        h3.cmd(f'iperf3 -c {h7.IP()} -p 5201 -b 10M -P 10 -t 120 -C {cc} &')

        # Start H4 at T=30s (runs for 90s)
        time.sleep(15)
        print("Starting H4 at T=30s...")
        h4.cmd(f'iperf3 -c {h7.IP()} -p 5201 -b 10M -P 10 -t 90 -C {cc} &')

        # Wait for all tests to finish
        time.sleep(120)  

        h7.cmd('pkill -f iperf3')
        h1.cmd("pkill -f tcpdump")
        h3.cmd("pkill -f tcpdump")
        h4.cmd("pkill -f tcpdump")


        print(f"Metrics for TCP {cc} :") 
        print("For H1:")
        analyze_pcap(f'/tmp/b_{cc}_h1.pcap') 
        print("For H3:") 
        analyze_pcap(f'/tmp/b_{cc}_h3.pcap') 
        print("For H4:")
        analyze_pcap(f'/tmp/b_{cc}_h4.pcap')   
        print() 
        time.sleep(5)  # Wait before the next test

    net.stop()

def c(congestion_schemes,net):
    s1 = net.get('s1')
    s2 = net.get('s2')
    s3 = net.get('s3')
    s4 = net.get('s4')
    
    s1_s2_intf1, s1_s2_intf2 = s1.connectionsTo(s2)[0]
    s1_s2_intf1.config(bw=100)
    s1_s2_intf2.config(bw=100)
    
    s2_s3_intf1, s2_s3_intf2 = s2.connectionsTo(s3)[0]
    s2_s3_intf1.config(bw=50)
    s2_s3_intf2.config(bw=50)
    
    s3_s4_intf1, s3_s4_intf2 = s3.connectionsTo(s4)[0]
    s3_s4_intf1.config(bw=100)
    s3_s4_intf2.config(bw=100)
 
   

    h3 = net.get('h3')
    h7 = net.get('h7')
    h1 = net.get('h1')
    h2 = net.get('h2')
    h4 = net.get('h4')

    
    def run_test(case_name, clients):
       
        pcap_file = f"/tmp/c_{cc}_{case_name}.pcap"

        # Start tcpdump
        h7.cmd(f"tcpdump -i h7-eth0 -w {pcap_file} & echo $! > /tmp/tcpdump.pid")
        time.sleep(2)  # Ensure tcpdump starts

        # Start iPerf3 clients
        pids = []
        for client in clients:
            pid_file = f"/tmp/{client.name}_iperf.pid"
            client.cmd(f'iperf3 -c {h7.IP()} -p 5201 -b 10M -P 10 -t 150 -C {cc} & echo $! > {pid_file}')
            pids.append(pid_file)

        time.sleep(150)  # Wait for test to complete

        # Kill iPerf3 clients
        for pid_file in pids:
            client.cmd(f"kill $(cat {pid_file})")

        # Stop tcpdump
        h7.cmd("kill $(cat /tmp/tcpdump.pid)")
        print(f"Packet capture saved to {pcap_file}")


        print(f"Metrics for TCP {cc} ({case_name}):")
        analyze_pcap(pcap_file)
        print()

    for cc in congestion_schemes:
        # Start iPerf3 server
        h7.cmd('iperf3 -s -p 5201 -D &')
        time.sleep(2)  # Ensure server starts

        # Case 1: H3 → H7
        print("1. Link S2-S4 is active with client on H3 and server on H7.")
        run_test("case1", [h3])
        
        print("2.Link S1-S4 is active with: ")
        print("a. Running client on H1 and H2 and server on H7")
        run_test("case2a", [h1, h2])

        # Case 2b: H1, H3 → H7
        print("b. Running client on H1 and H3 and server on H7")
        run_test("case2b", [h1, h3])

        # Case 2c: H1, H3, H4 → H7
        print("c. Running client on H1, H3 and H4 and server on H7")
        run_test("case2c", [h1, h3, h4])

        # Stop iPerf3 server
        h7.cmd("pkill -f iperf3")

    net.stop()



def d(congestion_schemes, net):
    topo = MyTopo()
    net = Mininet(topo=MyTopo(loss=1), controller=Controller, link=TCLink, host=CPULimitedHost)
    net.start()

    print("S2-S3 loss is 1%")
    c(congestion_schemes, net)
    net.stop()
    
    net = Mininet(topo=MyTopo(loss=5), controller=Controller, link=TCLink, host=CPULimitedHost)
    net.start()

    print("S2-S3 loss is 5%")
    c(congestion_schemes, net)
    net.stop()



def mini():
    topo = MyTopo()
    net = Mininet(topo=topo, controller=Controller, link=TCLink, host=CPULimitedHost)
    net.start()
    CLI(net)
    net.stop()
	
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--part", type=str, choices=['a', 'b','c','d'], required=True)
    args = parser.parse_args()
    congestion_schemes = ['bic','highspeed','yeah']
    
    topo = MyTopo()
    net = Mininet(topo=topo, controller=Controller, link=TCLink, host=CPULimitedHost)
    net.start()


    if args.part == 'a':
        a(congestion_schemes,net)
    elif args.part == 'b':
        b(congestion_schemes,net)
    elif args.part=='c':
    	c(congestion_schemes,net)
    elif args.part == 'd':
    	net.stop()
    	d(congestion_schemes,net)
