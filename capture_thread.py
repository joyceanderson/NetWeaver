# In capture_thread.py (or at the top of packet_logger.py)
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff, IP, TCP

from scapy.all import Ether, ARP, IP, TCP, UDP, hexdump


class CaptureThread(QThread):
    packet_captured = pyqtSignal(dict)  # Signal to emit packet details

    def __init__(self, iface, filter_protocol=None):
        super().__init__()
        self.iface = iface
        self.filter_protocol = filter_protocol
        self.running = True
    def run(self):
        # Start sniffing on the specified interface
        sniff(iface=self.iface, prn=self.process_packet, stop_filter=lambda _: not self.running)

    # def process_packet(self, packet):
    #     # Filter packets by protocol if specified
    #     if self.filter_protocol and self.filter_protocol not in packet.summary():
    #         return
    #
    #     # Prepare packet information to emit
    #     packet_info = {
    #         "Protocol": packet.summary(),
    #         "Source IP": packet[IP].src if IP in packet else "N/A",
    #         "Destination IP": packet[IP].dst if IP in packet else "N/A",
    #         "Source Port": packet[TCP].sport if TCP in packet else "N/A",
    #         "Destination Port": packet[TCP].dport if TCP in packet else "N/A"
    #     }
    #     self.packet_captured.emit(packet_info)  # Emit packet details

    def process_packet(self, packet):
        """Process each captured packet and emit detailed information."""
        try:
            packet_info = {
                "Timestamp": f"{packet.time:.6f}",  # Packet timestamp
                "Source IP": packet[IP].src if IP in packet else "N/A",
                "Destination IP": packet[IP].dst if IP in packet else "N/A",
                "Protocol": packet.summary().split()[0],  # Extract protocol from summary
                "Length": len(packet),  # Packet length in bytes
                "Info": packet.summary()  # Packet summary as info
            }

            self.packet_captured.emit(packet_info)  # Emit packet details
        except Exception as e:
            print(f"Error processing packet: {e}")

    def stop(self):
        self.running = False
