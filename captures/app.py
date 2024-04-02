from flask import Flask, render_template, jsonify, request
from flask import Flask, render_template, send_from_directory, request, make_response
from scapy.all import *
from werkzeug.utils import secure_filename
from scapy.all import sniff, IP, rdpcap
from datetime import datetime
import threading
import os
import sys

app = Flask(__name__)
is_sniffing = False
packet_data = []  
packet_lock = threading.Lock() 
packet_queue = [] # Lock để tránh xung đột dữ liệu
SAVE_FOLDER = 'captures'

def packet_handler(packet):
    ip_packet = packet.getlayer(IP)
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
                "No.": len(packet_data) + 1,
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
    return render_template('index.html', packets=packet_queue)

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

@app.route('/download')
def download():
    filename = request.args.get('filename', 'captured.pcap')
    filepath = os.path.join(SAVE_FOLDER, filename)
    wrpcap(filepath, packet_queue)
    response = make_response(send_from_directory(SAVE_FOLDER, filename, as_attachment=True))
    return response

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
    if not os.path.exists(SAVE_FOLDER):
        os.makedirs(SAVE_FOLDER)
    app.run(host='0.0.0.0', port=8086, debug=True)
