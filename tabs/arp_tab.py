import socket
import sys
import psutil
import netifaces
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QLineEdit, QComboBox, QLabel, QPushButton,
    QMessageBox, QHBoxLayout, QFileDialog, QApplication, QToolTip, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QDateTime, QTimer
import re
import json
from scapy.all import ARP, Ether, srp1, send


class ARPTab(QWidget):
    def __init__(self, log_sent_callback=None):
        super().__init__()
        self.setAttribute(Qt.WA_AlwaysShowToolTips, True)  # Enable tooltips explicitly for this widget
        self.log_sent_callback = log_sent_callback  # Only keep log_sent_callback

        # Initialize auto-populated fields
        self.local_ip = self.get_local_ip()
        self.local_mac = self.get_mac_address()

        # Initialize layout
        layout = QVBoxLayout()

        # Add initial spacing to push title down
        layout.addSpacing(60)

        # Title and description (keep at top)
        title_label = QLabel("ARP Packet Generator")
        title_label.setFont(QFont('Arial', 18, QFont.Bold))
        layout.addWidget(title_label, alignment=Qt.AlignCenter)

        layout.addSpacing(15)

        subheader_label = QLabel("Configure and send ARP packets")
        subheader_label.setFont(QFont('Arial', 11))
        layout.addWidget(subheader_label, alignment=Qt.AlignCenter)

        # Add stretch to push fields up
        layout.addStretch(2)

        # Content container for fields and buttons
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(50, 0, 50, 0)

        # Network adapter dropdown
        adapter_layout = QHBoxLayout()
        adapter_label = QLabel("Select Network Adapter:")
        self.adapter_dropdown = QComboBox()
        self.adapter_dropdown.addItems(self.get_network_adapters())
        adapter_layout.addWidget(adapter_label)
        adapter_layout.addWidget(self.adapter_dropdown)
        content_layout.addLayout(adapter_layout)

        content_layout.addSpacing(20)

        # Grid layout for ARP fields
        grid_layout = QGridLayout()

        # Input fields with automatic IP and MAC detection
        self.src_ip = QLineEdit(self.local_ip)
        self.src_ip.setPlaceholderText("192.168.1.1")
        self.src_ip.setToolTip("Enter the source IP address (e.g., your local IP address).")
        self.src_ip.textChanged.connect(lambda: self.validate_input(self.src_ip, "IP"))

        self.src_mac = QLineEdit(self.local_mac)
        self.src_mac.setPlaceholderText("00:11:22:33:44:55")
        self.src_mac.setToolTip("Enter the source MAC address (e.g., your device's MAC address).")
        self.src_mac.textChanged.connect(lambda: self.validate_input(self.src_mac, "MAC"))

        self.dst_ip = QLineEdit()
        self.dst_ip.setPlaceholderText("192.168.1.2")
        self.dst_ip.setToolTip("Enter the destination IP address of the target device.")
        self.dst_ip.textChanged.connect(lambda: self.validate_input(self.dst_ip, "IP"))

        self.dst_mac = QLineEdit("ff:ff:ff:ff:ff:ff")
        self.dst_mac.setPlaceholderText("ff:ff:ff:ff:ff:ff")
        self.dst_mac.setReadOnly(True)
        self.dst_mac.setToolTip("The MAC address of the destination. Defaults to broadcast for ARP requests.")
        self.dst_mac.textChanged.connect(lambda: self.validate_input(self.dst_mac, "MAC"))

        self.arp_op = QComboBox()
        self.arp_op.addItems(["Request (1)", "Reply (2)"])
        self.arp_op.currentIndexChanged.connect(self.update_dst_mac_field)

        self.packet_count = QLineEdit()
        self.packet_count.setPlaceholderText("Number of Packets (e.g., 10)")
        self.packet_count.setToolTip("Specify the number of packets to send.")

        # Set up the grid layout
        grid_layout.addWidget(QLabel("Source IP"), 0, 0)
        grid_layout.addWidget(self.src_ip, 0, 1)
        grid_layout.addWidget(QLabel("Source MAC"), 0, 2)
        grid_layout.addWidget(self.src_mac, 0, 3)
        grid_layout.addWidget(QLabel("Destination IP"), 1, 0)
        grid_layout.addWidget(self.dst_ip, 1, 1)
        grid_layout.addWidget(QLabel("Destination MAC"), 1, 2)
        grid_layout.addWidget(self.dst_mac, 1, 3)
        grid_layout.addWidget(QLabel("ARP Operation"), 2, 0)
        grid_layout.addWidget(self.arp_op, 2, 1)
        grid_layout.addWidget(QLabel("Number of Packets"), 2, 2)
        grid_layout.addWidget(self.packet_count, 2, 3)

        content_layout.addLayout(grid_layout)
        content_layout.addSpacing(20)

        # Button layout
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 0, 0, 0)

        # Add buttons
        self.send_button = QPushButton("  Send Packet")
        self.clear_button = QPushButton("  Clear")
        self.save_button = QPushButton("  Save Config")
        self.load_button = QPushButton("  Load Config")

        # Style buttons
        self.send_button.setStyleSheet("background-color: black; color: white; font-weight: bold;")
        self.clear_button.setStyleSheet("background-color: gray; color: white;")
        self.save_button.setStyleSheet("background-color: green; color: white;")
        self.load_button.setStyleSheet("background-color: orange; color: white;")

        # Set fixed widths
        for button in [self.send_button, self.clear_button, self.save_button, self.load_button]:
            button.setFixedWidth(150)

        # Add buttons to layout
        button_layout.addWidget(self.send_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.load_button)
        button_layout.setAlignment(Qt.AlignCenter)

        content_layout.addLayout(button_layout)

        # Add the content widget to main layout
        layout.addWidget(content_widget, alignment=Qt.AlignCenter)

        # Add stretch at bottom to keep content centered
        layout.addStretch(3)

        self.setLayout(layout)

        # Set up event handlers and initial state
        if "en0" in self.get_network_adapters():
            self.adapter_dropdown.setCurrentText("en0")

        # Connect button click handlers
        self.send_button.clicked.connect(self.send_packet)
        self.clear_button.clicked.connect(self.confirm_clear)
        self.save_button.clicked.connect(self.save_configuration)
        self.load_button.clicked.connect(self.load_configuration)

        self.adapter_dropdown.currentIndexChanged.connect(self.update_ip_mac_fields)
        self.arp_op.currentIndexChanged.connect(self.update_dst_mac_field)
        self.update_dst_mac_field(0)
        self.dst_ip.setFocus()

    def get_network_adapters(self):
        """Get list of available network adapters."""
        adapters = []
        for interface in psutil.net_if_addrs().keys():
            adapters.append(interface)
        return adapters

    def get_local_ip(self):
        """Get the local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Dummy connection to determine local IP
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "Unavailable"

    def get_mac_address(self):
        """Get the MAC address of the active network interface."""
        try:
            ip_address = self.get_local_ip()
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == ip_address:
                        mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
                        return mac
            return "Unavailable"
        except Exception:
            return "Unavailable"

    def update_ip_mac_fields(self):
        """Auto-update IP and MAC fields based on selected adapter."""
        selected_adapter = self.adapter_dropdown.currentText()
        addrs = psutil.net_if_addrs().get(selected_adapter, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                self.src_ip.setText(addr.address)
            elif addr.family == psutil.AF_LINK:
                self.src_mac.setText(addr.address)

    def update_dst_mac_field(self, index):
        if index == 0:
            self.dst_mac.setText("ff:ff:ff:ff:ff:ff")
            self.dst_mac.setReadOnly(True)
        else:
            self.dst_mac.clear()
            self.dst_mac.setReadOnly(False)

    def send_packet(self):
        """Send ARP packet(s), disable button during operation, and handle UI updates."""
        # Disable button at start
        self.send_button.setEnabled(False)
        self.send_button.setStyleSheet("background-color: gray; color: white; font-weight: bold;")
        QApplication.processEvents()  # Force UI update

        src_ip = self.src_ip.text()
        src_mac = self.src_mac.text()
        dst_ip = self.dst_ip.text()
        dst_mac = self.dst_mac.text()
        op = self.arp_op.currentIndex() + 1  # Get selected operation (1 for Request, 2 for Reply)

        # Number of packets to send
        num_packets = int(self.packet_count.text()) if self.packet_count.text().isdigit() else 1

        # Validate fields
        if not src_ip or not src_mac or not dst_ip or (op == 2 and not dst_mac):
            self.show_error("Please fill in all required fields.")
            self.reset_button()
            return

        if not self.validate_ip(src_ip) or not self.validate_ip(dst_ip):
            self.show_error("Invalid IP address format.")
            self.reset_button()
            return

        if not self.validate_mac(src_mac) or (op == 2 and not self.validate_mac(dst_mac)):
            self.show_error("Invalid MAC address format.")
            self.reset_button()
            return

        try:
            if op == 1:  # ARP Request
                arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=op, psrc=src_ip, hwsrc=src_mac, pdst=dst_ip)
                for i in range(num_packets):
                    QApplication.processEvents()  # Process UI events between packets
                    result = srp1(arp_packet, timeout=2, verbose=False)
                    
                    # Log the request packet
                    if self.log_sent_callback:
                        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
                        info = f"ARP Request: Who has {dst_ip}? Tell {src_ip} (packet {i + 1}/{num_packets})"
                        self.log_sent_callback(
                            timestamp,
                            "ARP",
                            src_ip,
                            src_mac,
                            None,
                            dst_ip,
                            None,
                            info
                        )
                    
                    # If we got a reply, log it too
                    if result:
                        if self.log_sent_callback:
                            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
                            info = f"ARP Reply: {dst_ip} is at {result.hwsrc} (packet {i + 1}/{num_packets})"
                            self.log_sent_callback(
                                timestamp,
                                "ARP",
                                dst_ip,
                                result.hwsrc,
                                None,
                                src_ip,
                                None,
                                info
                            )
                QMessageBox.information(self, "Success", f"{num_packets} ARP Request packet(s) sent successfully.")
            else:  # ARP Reply
                for i in range(num_packets):
                    QApplication.processEvents()  # Process UI events between packets
                    arp_packet = ARP(op=op, psrc=src_ip, hwsrc=src_mac, pdst=dst_ip, hwdst=dst_mac)
                    send(arp_packet, verbose=False)
                    
                    # Log the reply packet
                    if self.log_sent_callback:
                        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
                        info = f"ARP Reply: {src_ip} is at {src_mac} (packet {i + 1}/{num_packets})"
                        self.log_sent_callback(
                            timestamp,
                            "ARP",
                            src_ip,
                            src_mac,
                            None,
                            dst_ip,
                            None,
                            info
                        )
                QMessageBox.information(self, "Success", f"{num_packets} ARP Reply packet(s) sent successfully.")
        except Exception as e:
            self.show_error(f"Failed to send ARP packets: {str(e)}")
        finally:
            # Add a small delay before re-enabling the button
            QTimer.singleShot(500, self.reset_button)

    def reset_button(self):
        """Reset send button to its default state."""
        self.send_button.setEnabled(True)
        self.send_button.setStyleSheet("background-color: black; color: white; font-weight: bold;")

    def confirm_clear(self):
        reply = QMessageBox.question(self, 'Clear Fields', 'Are you sure you want to clear all fields?',
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.clear_fields()

    def clear_fields(self):
        """Clear input fields."""
        self.src_ip.clear()
        self.src_mac.clear()
        self.dst_ip.clear()
        self.dst_mac.setText("ff:ff:ff:ff:ff:ff")
        self.arp_op.setCurrentIndex(0)

        # Reset the styles after clearing
        self.src_ip.setStyleSheet("")
        self.src_mac.setStyleSheet("")
        self.dst_ip.setStyleSheet("")
        self.dst_mac.setStyleSheet("")

        # Set focus to source IP field
        self.src_ip.setFocus()

    def save_configuration(self):
        """Save the current configuration to a JSON file if all required fields are filled."""
        # Validate that required fields are not empty
        if not self.src_ip.text() or not self.src_mac.text() or not self.dst_ip.text():
            QMessageBox.warning(self, "Save Config",  "Please fill in all required fields before saving.")
            return

        # Proceed with saving the configuration
        config = {
            "network_adapter": self.adapter_dropdown.currentText(),  # Save selected network adapter
            "src_ip": self.src_ip.text(),
            "src_mac": self.src_mac.text(),
            "dst_ip": self.dst_ip.text(),
            "dst_mac": self.dst_mac.text(),
            "arp_op": self.arp_op.currentIndex()
        }

        file_name, _ = QFileDialog.getSaveFileName(self, "Save Configuration", "", "JSON Files (*.json)")
        if file_name:
            with open(file_name, 'w') as f:
                json.dump(config, f)
            QMessageBox.information(self, "Save Config", "Configuration saved successfully.")

    def load_configuration(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Load Configuration", "", "JSON Files (*.json)")
        if file_name:
            with open(file_name, 'r') as f:
                config = json.load(f)

            # Set each field from the loaded configuration
            adapter = config.get("network_adapter", "")
            if adapter in self.get_network_adapters():
                self.adapter_dropdown.setCurrentText(adapter)
            self.src_ip.setText(config.get("src_ip", ""))
            self.src_mac.setText(config.get("src_mac", ""))
            self.dst_ip.setText(config.get("dst_ip", ""))
            self.dst_mac.setText(config.get("dst_mac", "ff:ff:ff:ff:ff:ff"))
            self.arp_op.setCurrentIndex(config.get("arp_op", 0))

            QMessageBox.information(self, "Load Config", "Configuration loaded successfully.")

    def show_help(self):
        QMessageBox.information(self, "Help", "This tool allows you to generate and send ARP packets.\n"
                                              "Fill in the required fields:\n"
                                              "- Destination IP and MAC: Target addresses\n"
                                              "Select 'Request' or 'Reply' to set ARP operation, and press 'Send Packet'.")

    def validate_input(self, field, input_type):
        """Validate IP and MAC input fields and update UI."""
        text = field.text()
        if not text:  # If empty, remove any border styling
            field.setStyleSheet("")
            return

        # Only validate and show colors for non-empty fields
        valid = self.validate_ip(text) if input_type == "IP" else self.validate_mac(text)
        field.setStyleSheet(f"border: 1px solid {'green' if valid else 'red'};")
        if not valid:
            QToolTip.showText(field.mapToGlobal(field.rect().center()), f"Invalid {input_type} format.")

    def validate_ip(self, ip):
        pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(pattern, ip):
            return all(0 <= int(num) <= 255 for num in ip.split('.'))
        return False

    def validate_mac(self, mac):
        pattern = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
        return re.match(pattern, mac) is not None

    def show_error(self, message):
        error_msg = QMessageBox()
        error_msg.setIcon(QMessageBox.Critical)
        error_msg.setWindowTitle("Validation Error")
        error_msg.setText(message)
        error_msg.exec_()

    def populate_fields(self, packet_data):
        """Populate fields in the ARP tab from a selected packet log entry."""
        self.src_ip.setText(packet_data.get("src_ip", ""))
        self.src_mac.setText(packet_data.get("src_mac", ""))
        self.dst_ip.setText(packet_data.get("dst_ip", ""))  # Ensure Destination IP is populated
        self.dst_mac.setText(packet_data.get("dst_mac", "ff:ff:ff:ff:ff:ff"))  # Optional: Populate Destination MAC
        self.dst_ip.setFocus()  # Focus on destination IP for convenience

    def showEvent(self, event):
        """Called when tab is shown. Update auto-populated fields."""
        super().showEvent(event)
        
        # Update fields with fresh values
        self.local_ip = self.get_local_ip()
        self.local_mac = self.get_mac_address()
        
        # Update UI
        self.src_ip.setText(self.local_ip)
        self.src_mac.setText(self.local_mac)


def default_log_sent_callback(timestamp, protocol, src_ip, src_mac, src_port, dst_ip, dst_port, info):
    print(f"{timestamp} {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {info}")


# Main block to start the application
if __name__ == "__main__":
    # Set high DPI attributes before creating the QApplication
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    # Create the application
    app = QApplication(sys.argv)
    QToolTip.setFont(QFont("Arial", 10))

    # Create the ARPTab instance, passing in the callback function
    window = ARPTab(log_sent_callback=default_log_sent_callback)
    window.setWindowTitle("ARP Packet Generator")
    window.show()

    sys.exit(app.exec_())
