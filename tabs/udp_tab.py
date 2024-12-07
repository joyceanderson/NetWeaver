import socket
import re
import json
import random
import psutil
import netifaces
import sys

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QLineEdit, QLabel, QPushButton,
    QComboBox, QTextEdit, QApplication, QHBoxLayout, QMessageBox, QFileDialog, QSpinBox, QGroupBox, QCheckBox, QMainWindow
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QDateTime
from scapy.all import IP, UDP, send, sniff, conf, Raw


class UDPTab(QWidget):
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

        # Title and description
        title_label = QLabel("UDP Packet Generator")
        title_label.setFont(QFont('Arial', 18, QFont.Bold))
        layout.addWidget(title_label, alignment=Qt.AlignCenter)

        layout.addSpacing(10)

        subheader_label = QLabel("Configure and send UDP packets")
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

        # Grid layout for UDP fields
        grid_layout = QGridLayout()

        # Create input fields
        self.src_ip = QLineEdit(self.local_ip)
        
        # Add IP spoofing checkbox
        self.spoof_ip_checkbox = QCheckBox("Enable IP Spoofing")
        self.spoof_ip_checkbox.setFont(QFont('Arial', 10))  
        self.spoof_ip_checkbox.stateChanged.connect(self.on_spoof_ip_changed)
        
        self.src_port = QLineEdit(self.current_src_port)
        self.dst_ip = QLineEdit()
        self.port_layout = QHBoxLayout()
        self.dst_port_dropdown = QComboBox()
        self.dst_port_dropdown.addItems([
            "49152 (Example 1)", 
            "49153 (Example 2)", 
            "49154 (Example 3)",
            "49155 (Example 4)",
            "Custom"
        ])
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
        grid_layout.addLayout(self.port_layout, 1, 3, 1, 2)

        content_layout.addLayout(grid_layout)
        content_layout.addSpacing(20)

        # Payload
        self.payload = QTextEdit()
        self.payload.setPlaceholderText("Optional payload data")
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
        self.dst_ip.setFocus()

        # Connect buttons to their respective methods
        self.send_button.clicked.connect(self.send_packet)
        self.clear_button.clicked.connect(self.clear_fields)
        self.save_button.clicked.connect(self.save_configuration)
        self.load_button.clicked.connect(self.load_configuration)

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
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "Unavailable"

    def update_ip_fields(self):
        """Update IP fields based on the selected network adapter."""
        selected_adapter = self.adapter_dropdown.currentText()
        addrs = psutil.net_if_addrs().get(selected_adapter, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                if not self.spoof_ip_checkbox.isChecked():
                    self.src_ip.setText(addr.address)
                break

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

    def on_port_selection_changed(self, text):
        """Handle port dropdown selection changes."""
        if "Custom" in text:
            self.dst_port.show()
            self.dst_port.clear()
        else:
            self.dst_port.hide()
            self.dst_port.clear()

    def get_selected_dst_port(self):
        """Retrieve the destination port, handling custom input."""
        text = self.dst_port_dropdown.currentText()
        if "Custom" in text:
            port = self.dst_port.text()
            if not port.isdigit() or not (0 <= int(port) <= 65535):
                raise ValueError("Invalid port number")
            return int(port)
        return int(text.split()[0])

    def send_packet(self):
        """Construct and send the UDP packet."""
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
            if not self.validate_ip(dst_ip):
                self.show_error("Invalid Destination IP address format.")
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

            # Create and send the packet
            payload = self.payload.toPlainText()
            
            # Create IP packet with UDP protocol explicitly set
            ip_packet = IP(src=src_ip, dst=dst_ip)
            
            # Create UDP packet
            udp_packet = UDP(
                sport=src_port,
                dport=dst_port
            )

            if payload:
                # Convert string payload to bytes if needed
                if isinstance(payload, str):
                    payload = payload.encode('utf-8')
                packet = ip_packet/udp_packet/Raw(load=payload)
            else:
                packet = ip_packet/udp_packet

            # Force packet assembly and checksum calculation
            packet = packet.__class__(bytes(packet))

            # Send the packet
            send(packet, verbose=False)

            # Log the sent packet
            if self.log_sent_callback:
                timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
                info = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                if payload:
                    info += f" Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}"
                
                self.log_sent_callback(
                    timestamp,
                    "UDP",
                    src_ip,
                    None,  # MAC address not needed for UDP
                    src_port,
                    dst_ip,
                    dst_port,
                    info
                )

            QMessageBox.information(self, "Success", "UDP packet sent successfully.")

        except Exception as e:
            self.show_error(f"Error sending packet: {str(e)}")
        finally:
            self.reset_button()

    def reset_button(self):
        """Reset send button to its default state."""
        self.send_button.setEnabled(True)
        self.send_button.setStyleSheet("background-color: black; color: white; font-weight: bold;")

    def save_configuration(self):
        """Save the current configuration to a JSON file."""
        try:
            config = {
                "src_ip": self.src_ip.text(),
                "src_port": self.src_port.text(),
                "dst_ip": self.dst_ip.text(),
                "dst_port": self.dst_port_dropdown.currentText(),
                "custom_port": self.dst_port.text(),
                "payload": self.payload.toPlainText(),
                "spoof_ip": self.spoof_ip_checkbox.isChecked()
            }
            
            file_name, _ = QFileDialog.getSaveFileName(
                self, "Save Configuration", "", "JSON Files (*.json)"
            )
            
            if file_name:
                if not file_name.endswith('.json'):
                    file_name += '.json'
                with open(file_name, 'w') as f:
                    json.dump(config, f, indent=4)
                QMessageBox.information(self, "Success", "Configuration saved successfully.")
        except Exception as e:
            self.show_error(f"Error saving configuration: {str(e)}")

    def load_configuration(self):
        """Load a configuration from a JSON file."""
        try:
            file_name, _ = QFileDialog.getOpenFileName(
                self, "Load Configuration", "", "JSON Files (*.json)"
            )
            
            if file_name:
                with open(file_name, 'r') as f:
                    config = json.load(f)
                
                self.src_ip.setText(config.get("src_ip", ""))
                self.src_port.setText(config.get("src_port", ""))
                self.dst_ip.setText(config.get("dst_ip", ""))
                self.dst_port_dropdown.setCurrentText(config.get("dst_port", "Custom"))
                self.dst_port.setText(config.get("custom_port", ""))
                self.payload.setPlainText(config.get("payload", ""))
                self.spoof_ip_checkbox.setChecked(config.get("spoof_ip", False))
                
                QMessageBox.information(self, "Success", "Configuration loaded successfully.")
        except Exception as e:
            self.show_error(f"Error loading configuration: {str(e)}")

    def clear_fields(self):
        """Clear all input fields."""
        self.src_ip.setText(self.local_ip)
        self.src_port.setText(self.current_src_port)
        self.dst_ip.clear()
        self.dst_port_dropdown.setCurrentIndex(0)
        self.dst_port.clear()
        self.payload.clear()
        self.spoof_ip_checkbox.setChecked(False)

    def validate_ip(self, ip):
        """Validate IP address format."""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (AttributeError, TypeError, ValueError):
            return False

    def show_error(self, message):
        """Show error message dialog."""
        QMessageBox.critical(self, "Error", message)

    def showEvent(self, event):
        """Called when tab is shown. Update auto-populated fields."""
        super().showEvent(event)
        if not self.spoof_ip_checkbox.isChecked():
            self.local_ip = self.get_local_ip()
            self.src_ip.setText(self.local_ip)
        self.current_src_port = str(random.randint(49152, 65535))
        self.src_port.setText(self.current_src_port)
        """Show error message dialog."""
        QMessageBox.critical(self, "Error", message)

    def showEvent(self, event):
        """Called when tab is shown. Update auto-populated fields."""
        super().showEvent(event)
        if not self.spoof_ip_checkbox.isChecked():
            self.local_ip = self.get_local_ip()
            self.src_ip.setText(self.local_ip)
        self.current_src_port = str(random.randint(49152, 65535))
        self.src_port.setText(self.current_src_port)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = QMainWindow()
    udp_tab = UDPTab()
    window.setCentralWidget(udp_tab)
    window.setWindowTitle("UDP Packet Generator")
    window.setGeometry(100, 100, 800, 600)
    window.show()
    sys.exit(app.exec_())
