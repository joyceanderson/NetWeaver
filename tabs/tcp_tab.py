import socket
import re
import json
import random
import psutil
import netifaces

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QLineEdit, QLabel, QPushButton,
    QComboBox, QTextEdit, QApplication, QHBoxLayout, QMessageBox, QFileDialog, QSpinBox, QGroupBox, QCheckBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QDateTime, QTimer
from scapy.all import IP, TCP, send, sniff, conf, Raw
import sys

def capture_response(src_ip, dst_ip, dst_port):
    """Capture TCP responses for a specific source and destination."""
    try:
        # Start capturing before sending
        def packet_filter(pkt):
            has_tcp = TCP in pkt and IP in pkt
            if not has_tcp:
                return False
                
            # Match packets in either direction of the connection
            correct_ips = (
                (pkt[IP].src == dst_ip and pkt[IP].dst == src_ip) or
                (pkt[IP].src == src_ip and pkt[IP].dst == dst_ip)
            )
            
            # Match the port in either source or destination
            correct_ports = (
                pkt[TCP].sport == int(dst_port) or
                pkt[TCP].dport == int(dst_port)
            )
            
            return correct_ips and correct_ports

        # Start capturing with a more permissive filter
        packets = sniff(
            filter=f"tcp and (host {src_ip} or host {dst_ip})",
            count=20,  # Capture more packets
            timeout=3,  # Shorter timeout for quicker response
            iface=conf.iface,  # Explicitly specify interface
            prn=lambda x: x,  # Process packets as they arrive
            lfilter=packet_filter,
            store=1  # Store packets for later processing
        )
        
        return packets
    except Exception as e:
        print(f"Error in capture_response: {str(e)}")
        return None


class TCPTab(QWidget):
    def __init__(self, log_sent_callback=None):
        super().__init__()
        self.log_sent_callback = log_sent_callback

        # Initialize auto-populated fields
        self.local_ip = self.get_local_ip()
        self.current_src_port = str(random.randint(49152, 65535))

        # Initialize layout
        layout = QVBoxLayout()

        # Add initial spacing to push title down
        layout.addSpacing(60)

        # Title and description (keep at top)
        title_label = QLabel("TCP Packet Generator")
        title_label.setFont(QFont('Arial', 18, QFont.Bold))
        layout.addWidget(title_label, alignment=Qt.AlignCenter)

        layout.addSpacing(10)

        subheader_label = QLabel("Configure and send TCP packets")
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

        # Grid layout for TCP fields
        grid_layout = QGridLayout()

        # Create input fields
        self.src_ip = QLineEdit(self.local_ip)
        
        # Add IP spoofing checkbox
        self.spoof_ip_checkbox = QCheckBox("Enable IP Spoofing")
        self.spoof_ip_checkbox.stateChanged.connect(self.on_spoof_ip_changed)
        
        self.src_port = QLineEdit(self.current_src_port)
        self.dst_ip = QLineEdit()
        self.port_layout = QHBoxLayout()
        self.dst_port_dropdown = QComboBox()
        self.dst_port_dropdown.addItems(["80 (HTTP)", "443 (HTTPS)", "22 (SSH)", "21 (FTP)", "25 (SMTP)", "Custom"])
        self.dst_port_dropdown.currentTextChanged.connect(self.on_port_selection_changed)
        self.port_layout.addWidget(self.dst_port_dropdown)
        self.dst_port = QLineEdit()
        self.dst_port.setPlaceholderText("Enter port number")
        self.dst_port.hide()  # Initially hidden
        self.port_layout.addWidget(self.dst_port)
        grid_layout.addWidget(QLabel("Source IP:"), 0, 0)
        grid_layout.addWidget(self.src_ip, 0, 1)
        grid_layout.addWidget(self.spoof_ip_checkbox, 0, 2)
        grid_layout.addWidget(QLabel("Source Port:"), 0, 3)
        grid_layout.addWidget(self.src_port, 0, 4)
        grid_layout.addWidget(QLabel("Destination IP:"), 1, 0)
        grid_layout.addWidget(self.dst_ip, 1, 1)
        grid_layout.addWidget(QLabel("Destination Port:"), 1, 2)
        grid_layout.addLayout(self.port_layout, 1, 3)

        self.seq_num = QSpinBox()
        self.seq_num.setRange(0, 2147483647)
        self.seq_num.setValue(0)
        self.ack_num = QSpinBox()
        self.ack_num.setRange(0, 2147483647)
        self.ack_num.setValue(0)
        self.window_size = QSpinBox()
        self.window_size.setRange(0, 65535)
        self.window_size.setValue(8192)

        # TCP flags
        self.flags_group = QGroupBox("TCP Flags")
        flags_layout = QHBoxLayout()
        self.flag_checkboxes = {}
        
        for flag in ["URG", "ACK", "PSH", "SYN", "FIN"]:
            checkbox = QCheckBox(flag)
            self.flag_checkboxes[flag] = checkbox
            flags_layout.addWidget(checkbox)
        
        self.flags_group.setLayout(flags_layout)

        grid_layout.addWidget(QLabel("Sequence Number:"), 2, 0)
        grid_layout.addWidget(self.seq_num, 2, 1)
        grid_layout.addWidget(QLabel("Acknowledgment Number:"), 2, 2)
        grid_layout.addWidget(self.ack_num, 2, 3)

        grid_layout.addWidget(QLabel("Window Size:"), 3, 0)
        grid_layout.addWidget(self.window_size, 3, 1)

        content_layout.addLayout(grid_layout)
        content_layout.addSpacing(10)
        content_layout.addWidget(self.flags_group)
        content_layout.addSpacing(20)

        # Payload (optional)
        self.payload = QTextEdit()
        self.payload.setPlaceholderText("Optional payload data (e.g., HTTP GET request)")
        self.payload.setFixedHeight(50)
        content_layout.addWidget(QLabel("Payload:"))
        content_layout.addWidget(self.payload)

        # Button layout
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 0, 0, 0)

        # Create and style buttons
        self.send_button = QPushButton("  Send Packet")
        self.clear_button = QPushButton("  Clear")
        self.save_button = QPushButton("  Save Config")
        self.load_button = QPushButton("  Load Config")

        self.send_button.setStyleSheet("background-color: black; color: white; font-weight: bold;")
        self.clear_button.setStyleSheet("background-color: gray; color: white;")
        self.save_button.setStyleSheet("background-color: green; color: white;")
        self.load_button.setStyleSheet("background-color: orange; color: white;")

        # Set fixed widths for buttons
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

        self.adapter_dropdown.currentIndexChanged.connect(self.update_ip_fields)
        self.flag_checkboxes["SYN"].setChecked(True)
        self.dst_ip.setFocus()

        # Connect buttons to their respective methods
        self.send_button.clicked.connect(self.send_packet)
        self.clear_button.clicked.connect(self.clear_fields)
        self.save_button.clicked.connect(self.save_configuration)
        self.load_button.clicked.connect(self.load_configuration)

    def get_local_ip(self):
        """Get the local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "Unavailable"

    def get_network_adapters(self):
        """Get list of available network adapters."""
        adapters = []
        for interface in psutil.net_if_addrs().keys():
            adapters.append(interface)
        return adapters
        
    def update_ip_fields(self):
        """Update IP fields based on the selected network adapter."""
        selected_adapter = self.adapter_dropdown.currentText()
        addrs = psutil.net_if_addrs().get(selected_adapter, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                if not self.spoof_ip_checkbox.isChecked():
                    self.src_ip.setText(addr.address)
                break

    def send_packet(self):
        """Construct, send the TCP packet, and capture responses."""
        try:
            # Disable button and update UI immediately
            self.send_button.setEnabled(False)
            self.send_button.setStyleSheet("background-color: gray; color: white; font-weight: bold;")
            QApplication.processEvents()  # Force UI update

            src_ip = self.src_ip.text()
            src_port = self.src_port.text()
            dst_ip = self.dst_ip.text()

            # Validate inputs
            if not self.validate_ip(src_ip):
                self.show_error("Invalid Source IP address format.")
                return
                
            # Additional warning for IP spoofing if enabled
            if self.spoof_ip_checkbox.isChecked():
                reply = QMessageBox.question(self,
                    "Confirm Packet Send",
                    f"You are about to send a packet with a spoofed IP address: {src_ip}\n"
                    "Are you sure you want to proceed?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No)
                
                if reply == QMessageBox.No:
                    return

            try:
                dst_port = self.get_selected_dst_port()
            except ValueError:
                self.show_error("Invalid destination port.")
                return

            try:
                src_port = int(src_port)
                if not (0 <= src_port <= 65535):
                    raise ValueError
            except ValueError:
                self.show_error("Source port must be a number between 0 and 65535.")
                return

            # Get selected flags
            flags = ""
            flag_map = {
                "SYN": "S",
                "ACK": "A",
                "FIN": "F",
                "PSH": "P",
                "URG": "U"
            }
            
            for flag, checkbox in self.flag_checkboxes.items():
                if checkbox.isChecked():
                    flags += flag_map[flag]

            # Create and send the packet
            packet = IP(src=src_ip, dst=dst_ip)/TCP(
                sport=int(src_port),
                dport=int(dst_port),
                flags=flags,
                seq=self.seq_num.value(),
                ack=self.ack_num.value(),
                window=self.window_size.value()
            )

            # Send the packet
            send(packet, verbose=False)

            # Log the sent packet (only once)
            if self.log_sent_callback:
                timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz")
                self.log_sent_callback(
                    timestamp,
                    "TCP",
                    src_ip,
                    "N/A",  # src_mac not used for TCP
                    src_port,
                    dst_ip,
                    dst_port,
                    f"TCP {flags} packet sent to {dst_ip}:{dst_port}"
                )

            # Attempt to capture responses
            QApplication.processEvents()
            responses = capture_response(src_ip, dst_ip, dst_port)
            
            if responses:
                for response in responses:
                    if TCP in response and IP in response:
                        # Get TCP flags
                        tcp_flags = response[TCP].flags
                        flag_desc = []
                        
                        # Decode flags
                        if tcp_flags & 0x02: flag_desc.append("SYN")
                        if tcp_flags & 0x10: flag_desc.append("ACK")
                        if tcp_flags & 0x04: flag_desc.append("RST")
                        if tcp_flags & 0x01: flag_desc.append("FIN")
                        if tcp_flags & 0x08: flag_desc.append("PSH")
                        if tcp_flags & 0x20: flag_desc.append("URG")
                        
                        flags_str = "+".join(flag_desc) if flag_desc else str(tcp_flags)
                        
                        # Create descriptive message based on flags
                        if tcp_flags & 0x02:  # SYN
                            if tcp_flags & 0x10:  # ACK
                                msg = "SYN-ACK (Step 2 of handshake)"
                            else:
                                msg = "SYN (Step 1 of handshake)"
                        elif tcp_flags & 0x10:  # ACK
                            if tcp_flags & 0x01:  # FIN
                                msg = "FIN-ACK (Connection termination)"
                            else:
                                msg = "ACK (Step 3 of handshake/Data)"
                        elif tcp_flags & 0x01:  # FIN
                            msg = "FIN (Connection termination initiated)"
                        elif tcp_flags & 0x04:  # RST
                            msg = "RST (Connection reset)"
                        else:
                            msg = f"TCP Flags: {flags_str}"

                        # Determine packet direction
                        direction = "→" if response[IP].src == src_ip else "←"
                        
                        # Create the log message
                        response_info = (
                            f"{msg} - {response[IP].src}:{response[TCP].sport} {direction} "
                            f"{response[IP].dst}:{response[TCP].dport} [Flags: {flags_str}]"
                        )
                        
                        if self.log_sent_callback:
                            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
                            self.log_sent_callback(
                                timestamp,
                                "TCP",
                                response[IP].src,
                                "N/A",  # src_mac not used for TCP
                                str(response[TCP].sport),
                                response[IP].dst,
                                str(response[TCP].dport),
                                response_info
                            )
            else:
                if self.log_sent_callback:
                    timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
                    self.log_sent_callback(
                        timestamp,
                        "TCP",
                        src_ip,
                        "N/A",  # src_mac not used for TCP
                        src_port,
                        dst_ip,
                        dst_port,
                        "No responses captured"
                    )

        except Exception as e:
            self.show_error(f"Failed to send TCP packet: {str(e)}")
            if self.log_sent_callback:
                timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
                self.log_sent_callback(
                    timestamp,
                    "TCP",
                    src_ip,
                    "N/A",  # src_mac not used for TCP
                    src_port,
                    dst_ip,
                    dst_port,
                    f"Error: {str(e)}"
                )
        finally:
            # Re-enable button
            self.send_button.setEnabled(True)
            self.send_button.setStyleSheet("background-color: black; color: white; font-weight: bold;")

    def reset_button(self):
        """Reset send button to its default state."""
        self.send_button.setEnabled(True)
        self.send_button.setStyleSheet("background-color: black; color: white; font-weight: bold;")

    def save_configuration(self):
        if not self.src_ip.text() or not self.src_port.text() or not self.dst_ip.text() or not self.dst_port_dropdown.currentText():
            QMessageBox.warning(self, "Save Config", "Please fill in all required fields before saving.")
            return

        config = {
            "src_ip": self.src_ip.text(),
            "src_port": self.src_port.text(),
            "dst_ip": self.dst_ip.text(),
            "dst_port": self.dst_port_dropdown.currentText(),
            "flags": [flag for flag, checkbox in self.flag_checkboxes.items() if checkbox.isChecked()],
            "seq_num": self.seq_num.value(),
            "ack_num": self.ack_num.value(),
            "window_size": self.window_size.value(),
            "payload": self.payload.toPlainText()
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
            self.src_ip.setText(config.get("src_ip", ""))
            self.src_port.setText(config.get("src_port", ""))
            self.dst_ip.setText(config.get("dst_ip", ""))
            self.dst_port_dropdown.setCurrentText(config.get("dst_port", ""))
            for flag in config.get("flags", []):
                self.flag_checkboxes[flag].setChecked(True)
            self.seq_num.setValue(config.get("seq_num", 0))
            self.ack_num.setValue(config.get("ack_num", 0))
            self.window_size.setValue(config.get("window_size", 8192))
            self.payload.setPlainText(config.get("payload", ""))
            QMessageBox.information(self, "Load Config", "Configuration loaded successfully.")

    def clear_fields(self):
        self.src_ip.clear()
        self.src_port.clear()
        self.dst_ip.clear()
        self.dst_port_dropdown.setCurrentIndex(0)
        for checkbox in self.flag_checkboxes.values():
            checkbox.setChecked(False)
        self.seq_num.setValue(0)
        self.ack_num.setValue(0)
        self.window_size.setValue(8192)
        self.payload.clear()

        # Set focus to Source IP field
        self.src_ip.setFocus()

    def validate_ip(self, ip):
        pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(pattern, ip):
            return all(0 <= int(num) <= 255 for num in ip.split('.'))
        return False

    def validate_port(self, port):
        return port.isdigit() and 49152 <= int(port) <= 65535

    def validate_input(self, field, input_type):
        """Validate IP and port fields and set their border color."""
        if input_type == "IP":
            valid = self.validate_ip(field.text())
        elif input_type == "Port":
            valid = self.validate_port(field.text())
        else:
            valid = False

        # Update field border color based on validation
        field.setStyleSheet(f"border: 1px solid {'green' if valid else 'red'};")

    def show_error(self, message):
        error_msg = QMessageBox()
        error_msg.setIcon(QMessageBox.Critical)
        error_msg.setWindowTitle("Validation Error")
        error_msg.setText(message)
        error_msg.exec_()

    def get_selected_dst_port(self):
        """Retrieve the destination port, handling custom input."""
        selected_port = self.dst_port_dropdown.currentText()
        if selected_port.endswith(")"):
            return int(selected_port.split()[0])  # Extract the port number before the description
        elif selected_port == "Custom":
            return int(self.dst_port.text())
        return int(selected_port)

    def on_port_selection_changed(self, text):
        """Handle port dropdown selection changes"""
        if text == "Custom":
            self.dst_port.show()
            self.dst_port.clear()
        else:
            self.dst_port.hide()
            # Extract port number from selection (e.g., "80 (HTTP)" -> "80")
            if text != "Select Port":
                port = text.split()[0]
                self.dst_port.setText(port)

    def handle_sent_packet_click(self, packet_info):
        """Handle when a sent packet is clicked in the log."""
        try:
            # Extract information from the packet info string
            # Example format: "TCP SYN packet from 192.168.1.1:12345 to 10.0.0.1:80"
            match = re.search(r"TCP (\w+) packet from ([^:]+):(\d+) to ([^:]+):(\d+)", packet_info)
            if match:
                flags, src_ip, src_port, dst_ip, dst_port = match.groups()
                
                # Populate the fields
                self.src_ip.setText(src_ip)
                self.src_port.setText(src_port)
                self.dst_ip.setText(dst_ip)
                
                # Set the destination port in the appropriate field
                if dst_port in ["80", "443", "22", "21", "25"]:
                    self.dst_port_dropdown.setCurrentText(f"{dst_port} ({['HTTP', 'HTTPS', 'SSH', 'FTP', 'SMTP'][['80', '443', '22', '21', '25'].index(dst_port)]})")
                    self.dst_port_dropdown.clearEditText()
                else:
                    self.dst_port_dropdown.setCurrentText("Custom")
                    self.dst_port_dropdown.clearEditText()
                    self.dst_port.setText(dst_port)
                
                # Set the flags dropdown
                for flag in flags:
                    self.flag_checkboxes[flag].setChecked(True)
                
                # Reset sequence, ack, and window to default values
                self.seq_num.setValue(0)
                self.ack_num.setValue(0)
                self.window_size.setValue(8192)
                
                # Clear the payload
                self.payload.clear()
        except Exception as e:
            print(f"Error populating TCP fields: {str(e)}")

    def showEvent(self, event):
        """Called when tab is shown. Update auto-populated fields."""
        super().showEvent(event)
        
        # Update fields with fresh values
        self.local_ip = self.get_local_ip()
        self.current_src_port = str(random.randint(49152, 65535))
        
        # Update UI
        self.src_ip.setText(self.local_ip)
        self.src_port.setText(self.current_src_port)

    def on_spoof_ip_changed(self, state):
        """Handle IP spoofing checkbox state change."""
        if state == Qt.Checked:
            reply = QMessageBox.warning(self,
                "IP Spoofing Warning",
                "IP spoofing allows you to send packets with a fake source IP address.\n\n"
                "Please note:\n"
                "- This should only be used for testing and educational purposes\n"
                "- Some networks may block spoofed packets\n"
                "- IP spoofing may be illegal in certain contexts\n\n"
                "Do you want to proceed?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No)
            
            if reply == QMessageBox.No:
                self.spoof_ip_checkbox.setChecked(False)
                self.src_ip.setText(self.local_ip)
                return
                
            self.src_ip.setStyleSheet("QLineEdit { background-color: #fff3e0; }")
            self.src_ip.setPlaceholderText("Enter spoofed IP address")
            self.src_ip.clear()
        else:
            self.src_ip.setStyleSheet("")
            self.src_ip.setText(self.local_ip)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TCPTab(log_sent_callback=None)
    window.setWindowTitle("TCP Packet Generator")
    window.show()
    sys.exit(app.exec_())
