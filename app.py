from flask import Flask, render_template, jsonify, request
from werkzeug.utils import secure_filename
from scapy.all import sniff, IP, rdpcap, wrpcap
from packet_handler import display_packet
from filter_packets import filter_packets
from datetime import datetime
import threading
import os
import sys

app = Flask(__name__)
is_sniffing = False
packet_data = []  
packet_lock = threading.Lock()  # Lock để tránh xung đột dữ liệu
captured_packets = []
def packet_handler(packet):
    ip_packet = packet.getlayer(IP)
    captured_packets.append(packet)
    if ip_packet:
        ip_src = ip_packet.src
        ip_dst = ip_packet.dst
        protocol_name = ip_packet.payload.__class__.__name__  # Lấy tên lớp giao thức
        packet_length = len(packet)
        packet_info = packet.summary()

        # Chuyển đổi epoch time sang định dạng 'YYYY-MM-DD HH:MM:SS'
        human_readable_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')

        with packet_lock:  # Sử dụng lock để đảm bảo an toàn khi thao tác với biến toàn cục
            packet_data.append({
                "No.": len(packet_data),
                "Time": human_readable_time,
                "Source": ip_src,
                "Destination": ip_dst,
                "Protocol": protocol_name,  # Sử dụng tên giao thức
                "Length": packet_length,
                "Info": packet_info
            })

def start_sniffing():
    global is_sniffing
    is_sniffing = True
    sniff(prn=packet_handler, stop_filter=lambda _: not is_sniffing)

def stop_sniffing():
    global is_sniffing
    is_sniffing = False

# Khởi tạo và bắt đầu luồng để bắt các gói tin
sniff_thread = threading.Thread(target=start_sniffing)

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/filter", methods=["POST"])
def filter():
    packet_data = None
    if request.method == "POST":
        pcap_file = "captured_packets.pcap"  # Thay đổi đường dẫn tới file pcap cần xử lý
        filter_rule = request.form["filter_rule"]
        filtered_packets = filter_packets(pcap_file, filter_rule)
        packet_data = filtered_packets
    return render_template("index.html", packet_data=packet_data)

@app.route("/open", methods=["GET", "POST"])
def open():
    if request.method == "POST":
        pcap_file = "captured_packets.pcap"  # Thay đổi đường dẫn tới file pcap cần xử lý
        packet_number = int(request.form["packet_number"])
        packet_info = display_packet(pcap_file, packet_number)
        return render_template("index.html", packet_info=packet_info)
    return render_template("index.html", packet_info=None)

@app.route('/upload', methods=['POST'])
def upload_file():
    global packet_data
    packet_data = []  # Đảm bảo rằng danh sách packet_data được làm mới trước khi xử lý tệp mới
    if 'file' not in request.files:
        return "No file part"
    file = request.files['file']
    if file.filename == '':
        return "No selected file"
    if file:
        filename = secure_filename(file.filename)
        file.save(filename)
        if filename.endswith('.pcap'):
            packets = rdpcap(filename)
            for packet in packets:
                packet_handler(packet)
        else:
            return "Unsupported file format"
        return render_template('index.html', packet_data=packet_data)

@app.route('/get_latest_packets')
def get_latest_packets():
    # Trả về dữ liệu gần đây nhất dưới dạng JSON
    with packet_lock:  # Sử dụng lock để đảm bảo an toàn khi đọc dữ liệu từ biến toàn cục
        return jsonify(packet_data)

@app.route('/start')
def start():
    global sniff_thread
    if not sniff_thread.is_alive():
        sniff_thread = threading.Thread(target=start_sniffing)
        sniff_thread.start()
        return "Sniffing started."
    else:
        return "Sniffing is already started."

@app.route('/stop')
def stop():
    global sniff_thread
    stop_sniffing()
    return "Sniffing stopped."

@app.route('/save', methods=['POST'])
def save_packets():
    file_name = 'captured_packets.pcap'
    wrpcap(file_name, captured_packets)
    return f"Packets saved successfully as {file_name}!"

@app.route('/restart_flask')
def restart_flask():
    # Xóa sạch dữ liệu
    global packet_data
    with packet_lock:
        packet_data = []
    # Khởi động lại Flask
    os.execl(sys.executable, sys.executable, *sys.argv)
    return "Restarting Flask..."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
