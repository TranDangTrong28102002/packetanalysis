from scapy.all import rdpcap


def display_packet(pcap_file, packet_number):
    # Đọc gói tin từ file pcap
    packets = rdpcap(pcap_file)

    # Kiểm tra xem số thứ tự gói tin có hợp lệ không
    if packet_number < 0 or packet_number >= len(packets):
        return "Số thứ tự gói tin không hợp lệ."

    # Lấy gói tin ứng với số thứ tự
    packet = packets[packet_number]

    # Trả về thông tin của gói tin dưới dạng HTML
    return f"<pre>{packet.show(dump=True)}</pre>"

