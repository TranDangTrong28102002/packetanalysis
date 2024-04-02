from flask import Flask, render_template, request
from scapy.all import rdpcap
from datetime import datetime
from scapy.layers.inet import IP

def filter_packets(pcap_file, filter_rule):
    # Đọc gói tin từ file pcap
    packets = rdpcap(pcap_file)
    # Lọc các gói tin dựa trên luật
    filtered_packets = []
    for No, packet in enumerate(packets):
        if packet.haslayer(filter_rule):
            # Lấy thông tin của gói tin
            human_readable_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
            source = packet[IP].src  # Chuyển đổi source thành địa chỉ IP
            destination = packet[IP].dst  # Chuyển đổi destination thành địa chỉ IP
            protocol = packet[IP].payload.__class__.__name__
            length = len(packet)
            info = packet.summary()
            # Thêm thông tin vào danh sách các gói tin đã lọc
            filtered_packets.append({
                'No.': No,
                "Time": human_readable_time,
                'Source': source,
                'Destination': destination,
                'Protocol': protocol,
                'Length': length,
                'Info': info
            })

    return filtered_packets