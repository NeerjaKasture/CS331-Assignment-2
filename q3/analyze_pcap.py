import subprocess
def analyze_pcap(pcap_file):
    def run_tshark(command):
        """Run a tshark command and return the output."""
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

    # Calculate throughput and goodput in Bps
    throughput = (total_bytes / total_duration)
    goodput = (total_payload_bytes / total_duration)

    # Extract packet loss rate
    lost_segment_cmd = f"tshark -r {pcap_file} -Y 'tcp.analysis.lost_segment' | wc -l"
    total_packets_cmd = f"tshark -r {pcap_file} -Y 'tcp' | wc -l"
    total_packets = int(run_tshark(total_packets_cmd)) 
    lost_segments = int(run_tshark(lost_segment_cmd))
    packet_loss_rate = (lost_segments / total_packets) * 100  

    # Extract max packet size
    packet_size_cmd = f'tshark -r capture.pcap -Y "frame.len" -T fields -e frame.len'
    packet_size_list = run_tshark(packet_size_cmd).split("\n")
    max_packet_size = max((int(x) for x in packet_size_list if x.isdigit()), default=0)


    # Print metrics
    print(f"Throughput (Bps): {throughput:.2f}")
    print(f"Goodput (Bps): {goodput:.2f}")
    print(f"Packet Loss Rate: {packet_loss_rate:.2f}%")
    print(f"Max Packet Size: {max_packet_size} bytes")
    
analyze_pcap('capture_10.pcap')
