import sys
import json  # Import json for loading configuration files
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QTabWidget,
    QLabel, QPushButton, QMessageBox, QHBoxLayout
)
from PyQt5.QtCore import QDateTime, Qt
from PyQt5.QtGui import QFont
from tabs.arp_tab import ARPTab  # Import ARPTab from the tabs directory
from tabs.tcp_tab import TCPTab  # Import TCPTab from the tabs directory
from tabs.udp_tab import UDPTab  # Import UDPTab from the tabs directory
from tabs.dns_tab import DNSTab  # Import DNSTab from the tabs directory
from packet_logger import PacketLogger  # Import PacketLogger


class NetworkPacketGenerator(QMainWindow):
    def __init__(self):
        super().__init__()

        # Initialize Packet Logger
        self.packet_logger = PacketLogger()

        # Enable drag-and-drop
        self.setAcceptDrops(True)

        # Create the main layout
        main_layout = QVBoxLayout()
        # self.setWindowTitle("Interactive Network Protocol Simulator")
        self.setGeometry(100, 100, 1300, 850)

        # Header and Description
        header_label = QLabel("NetWeaver")
        header_font = QFont()
        header_font.setBold(True)
        header_font.setPointSize(50)
        header_label.setFont(header_font)

        description_label = QLabel("An Interactive Network Protocol Learning Environment")
        description_font = QFont()
        description_font.setPointSize(14)
        description_label.setFont(description_font)
        description_label.setAlignment(Qt.AlignCenter)
        description_label.setStyleSheet("""
            QLabel {
                color: #666666;
                padding: 5px 20px;
                margin: 5px 0px;
            }
        """)
        description_label.setWordWrap(False)  # Keep text in one line
        description_label.setMinimumWidth(900)  # Ensure enough width for the text
        
        # Add subheading with more detailed description
        subheading_label = QLabel("Explore TCP/IP and ARP protocols through hands-on packet crafting and analysis • Learn network fundamentals by constructing and sending real packets")
        subheading_font = QFont()
        subheading_font.setPointSize(10)
        subheading_label.setFont(subheading_font)
        subheading_label.setAlignment(Qt.AlignCenter)
        subheading_label.setStyleSheet("""
            QLabel {
                color: #666666;
                padding: 5px 20px;
                margin: 5px 0px;
            }
        """)
        subheading_label.setWordWrap(False)  # Keep text in one line
        subheading_label.setMinimumWidth(900)  # Ensure enough width for the text

        # Create Tab Widget
        self.tabs = QTabWidget()

        # Create and add ARP tab (Layer 2 - Data Link Layer)
        self.arp_tab = ARPTab(
            log_sent_callback=self.log_sent_packet
        )
        self.tabs.addTab(self.arp_tab, "ARP")

        # Create and add TCP tab (Layer 4 - Transport Layer)
        self.tcp_tab = TCPTab(
            log_sent_callback=self.log_sent_packet
        )
        self.tabs.addTab(self.tcp_tab, "TCP")

        # Create and add UDP tab (Layer 4 - Transport Layer)
        self.udp_tab = UDPTab(
            log_sent_callback=self.log_sent_packet
        )
        self.tabs.addTab(self.udp_tab, "UDP")

        # Create and add DNS tab (Layer 7 - Application Layer)
        self.dns_tab = DNSTab(
            log_sent_callback=self.log_sent_packet
        )
        self.tabs.addTab(self.dns_tab, "DNS")

        # Connect the tab change signal
        self.tabs.currentChanged.connect(self.clear_other_tabs)

        # Connect the logger's row_selected signal to the ARP tab's populate_fields method
        self.packet_logger.row_selected.connect(self.arp_tab.populate_fields)  # For ARP packets
        self.packet_logger.packet_clicked.connect(self.handle_packet_click)  # For TCP packets

        # Add components to main layout
        main_layout.addWidget(header_label, alignment=Qt.AlignCenter)
        main_layout.addWidget(description_label, alignment=Qt.AlignCenter)
        main_layout.addWidget(subheading_label, alignment=Qt.AlignCenter)
        main_layout.addSpacing(10)  # Add some space before the tabs

        # Create a new layout for tabs and packet logger
        tab_logger_layout = QHBoxLayout()
        tab_logger_layout.addWidget(self.tabs, stretch=2)
        tab_logger_layout.addWidget(self.packet_logger, stretch=1)
        main_layout.addLayout(tab_logger_layout)

        # Set the main layout
        main_widget = QWidget()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # Set focus to destination IP in ARP tab after all tabs are created
        from PyQt5.QtCore import QTimer
        QTimer.singleShot(100, self.arp_tab.dst_ip.setFocus)

    def clear_other_tabs(self, index):
        """Clear fields of all tabs except the currently active one."""
        if index == 0:  # ARP tab is active
            self.tcp_tab.clear_fields()
            self.udp_tab.clear_fields()
            self.dns_tab.clear_fields()
        elif index == 1:  # TCP tab is active
            self.arp_tab.clear_fields()
            self.udp_tab.clear_fields()
            self.dns_tab.clear_fields()
        elif index == 2:  # UDP tab is active
            self.arp_tab.clear_fields()
            self.tcp_tab.clear_fields()
            self.dns_tab.clear_fields()
        else:  # DNS tab is active
            self.arp_tab.clear_fields()
            self.tcp_tab.clear_fields()
            self.udp_tab.clear_fields()

    def dragEnterEvent(self, event):
        """Accept drag event if a JSON file is being dragged."""
        if event.mimeData().hasUrls() and event.mimeData().urls()[0].toString().endswith('.json'):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        """Load configuration from the dropped JSON file."""
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            try:
                with open(file_path, 'r') as f:
                    config = json.load(f)
                self.load_config(config)
                QMessageBox.information(self, "Config Loaded", f"Configuration loaded from {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load configuration: {e}")

    def load_config(self, config):
        """Populate the ARP tab fields with the loaded configuration."""
        try:
            self.arp_tab.src_ip.setText(config.get("src_ip", ""))
            self.arp_tab.src_mac.setText(config.get("src_mac", ""))
            self.arp_tab.dst_ip.setText(config.get("dst_ip", ""))
            self.arp_tab.dst_mac.setText(config.get("dst_mac", "ff:ff:ff:ff:ff:ff"))
            self.arp_tab.arp_op.setCurrentIndex(config.get("arp_op", 0))
        except AttributeError:
            QMessageBox.warning(self, "Error", "ARP Tab not loaded correctly.")

    def log_packet(self, packet_type, packet_info):
        """Log a packet to the packet logger."""
        self.packet_logger.log_packet(packet_type, packet_info)

    def log_sent_packet(self, timestamp, protocol, src_ip, src_mac, src_port, dst_ip, dst_port, info):
        """Log a sent packet to the packet logger."""
        packet_info = {
            'timestamp': timestamp,
            'protocol': protocol,
            'src_ip': src_ip,
            'src_mac': src_mac,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'info': info
        }
        # Pass directly to log_packet
        self.packet_logger.log_packet(protocol, packet_info)

    def handle_packet_click(self, packet_info):
        """Handle packet clicks for both ARP and TCP packets."""
        try:
            current_tab = self.tabs.currentWidget()
            if isinstance(current_tab, TCPTab) and "TCP" in packet_info:
                current_tab.handle_sent_packet_click(packet_info)
        except Exception as e:
            print(f"Error handling packet click: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkPacketGenerator()
    window.show()
    sys.exit(app.exec_())
