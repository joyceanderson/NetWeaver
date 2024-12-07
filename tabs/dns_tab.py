import socket
import sys
import json
import random
import subprocess
import re
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLineEdit, QComboBox, 
    QLabel, QPushButton, QMessageBox, QApplication, QFileDialog,
    QGroupBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QDateTime
from scapy.all import IP, UDP, DNS, DNSQR, send

class DNSTab(QWidget):
    def __init__(self, log_sent_callback=None):
        """Initialize the DNS tab."""
        super().__init__()
        self.log_sent_callback = log_sent_callback

        # Initialize auto-populated fields
        self.local_ip = self.get_local_ip()
        self.system_dns = self.get_system_dns()
        self.src_port = str(random.randint(49152, 65535))
        
        # Initialize DNS cache
        self.dns_cache = {}
        
        self.setup_ui()

    def showEvent(self, event):
        """Called when tab is shown. Update auto-populated fields."""
        super().showEvent(event)
        
        # Update fields with fresh values
        self.local_ip = self.get_local_ip()
        self.system_dns = self.get_system_dns()
        self.src_port = str(random.randint(49152, 65535))
        
        # Update UI
        self.src_ip.setText(self.local_ip)
        self.dst_ip.setText(self.system_dns)
        self.src_port_field.setText(self.src_port)

    def get_local_ip(self):
        """Get the local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def get_system_dns(self):
        """Get system's configured DNS server on macOS."""
        try:
            # Try to get from networksetup first (more reliable on macOS)
            cmd = ["networksetup", "-getdnsservers", "Wi-Fi"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            dns_servers = result.stdout.strip().split('\n')
            
            # Check if we got valid DNS servers
            if dns_servers and "There aren't any DNS Servers" not in dns_servers[0]:
                for dns in dns_servers:
                    try:
                        socket.inet_aton(dns.strip())  # Validate IP format
                        return dns.strip()
                    except:
                        continue

            # If networksetup fails, try scutil as backup
            cmd = ["scutil", "--dns"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse the output to find DNS servers
            for line in result.stdout.split('\n'):
                if 'nameserver[0]' in line:
                    dns = line.split(':')[1].strip()
                    try:
                        socket.inet_aton(dns)  # Validate IP format
                        return dns
                    except:
                        continue
            
            # If all else fails, use Google's DNS
            return "8.8.8.8"
        except:
            return "8.8.8.8"  # Fallback to Google DNS

    def validate_domain(self, domain):
        """Validate domain name format."""
        if not domain:
            return False
        # Basic domain validation
        if len(domain) > 255:
            return False
        if domain[-1] == ".":
            domain = domain[:-1]
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in domain.split("."))

    def setup_ui(self):
        """Initialize the DNS tab UI components."""
        # Initialize layout
        layout = QVBoxLayout()

        # Add initial spacing to push title down
        layout.addSpacing(60)

        # Title and description
        title_label = QLabel("DNS Query Generator")
        title_label.setFont(QFont('Arial', 18, QFont.Bold))
        layout.addWidget(title_label, alignment=Qt.AlignCenter)

        layout.addSpacing(15)

        subheader_label = QLabel("Look up domain information")
        subheader_label.setFont(QFont('Arial', 11))
        layout.addWidget(subheader_label, alignment=Qt.AlignCenter)

        # Add stretch to push content to center
        layout.addStretch(2)

        # Content container for fields and buttons
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(50, 0, 50, 0)

        # Grid layout for DNS fields
        grid_layout = QGridLayout()
        grid_layout.setVerticalSpacing(10)  # Add spacing between rows

        # Source IP (auto-populated)
        self.src_ip = QLineEdit(self.local_ip)
        self.src_ip.setToolTip("Source IP address (your local IP)")
        
        # Source Port (auto-generated)
        self.src_port_field = QLineEdit(self.src_port)
        self.src_port_field.setToolTip("Source port for the DNS query (automatically generated)")

        # Query Name (Domain)
        self.query_name = QLineEdit()
        self.query_name.setPlaceholderText("Enter domain name (e.g., youtube.com)")
        self.query_name.setToolTip("Enter the domain name to look up")

        # Query Type
        self.query_type = QComboBox()
        self.query_type.addItems([
            "A (IPv4 Address)",
            "AAAA (IPv6 Address)",
            "MX (Mail Server)",
            "NS (Name Server)",
            "TXT (Text Record)",
            "CNAME (Canonical Name)",
            "SOA (Start of Authority)",
            "PTR (Pointer Record)"
        ])
        self.query_type.setToolTip("Select the type of DNS record to look up")

        # Hidden field for DNS server (auto-populated)
        self.dst_ip = QLineEdit(self.system_dns)

        # Set up the grid layout - 4 columns (label, field, label, field)
        # Row 1: Source info
        grid_layout.addWidget(QLabel("Source IP:"), 0, 0)
        grid_layout.addWidget(self.src_ip, 0, 1)
        grid_layout.addWidget(QLabel("Source Port:"), 0, 2)
        grid_layout.addWidget(self.src_port_field, 0, 3)

        # Row 2: Domain Name (most important)
        grid_layout.addWidget(QLabel("Domain Name:"), 1, 0)
        grid_layout.addWidget(self.query_name, 1, 1, 1, 3)  # Span 3 columns

        # Row 3: Query Type
        grid_layout.addWidget(QLabel("Record Type:"), 2, 0)
        grid_layout.addWidget(self.query_type, 2, 1, 1, 3)  # Span 3 columns

        content_layout.addLayout(grid_layout)
        content_layout.addSpacing(20)

        # Buttons
        button_layout = QHBoxLayout()
        
        # Send button
        self.send_button = QPushButton(" Send Query")
        self.send_button.setStyleSheet("background-color: black; color: white; font-weight: bold;")
        self.send_button.setFixedWidth(150)
        self.send_button.clicked.connect(self.send_packet)
        
        # Clear button
        self.clear_button = QPushButton(" Clear")
        self.clear_button.setStyleSheet("background-color: gray; color: white; font-weight: bold;")
        self.clear_button.setFixedWidth(150)
        
        # Save button
        self.save_button = QPushButton(" Save Config")
        self.save_button.setStyleSheet("background-color: green; color: white; font-weight: bold;")
        self.save_button.setFixedWidth(150)
        
        # Load button
        self.load_button = QPushButton(" Load Config")
        self.load_button.setStyleSheet("background-color: orange; color: white; font-weight: bold;")
        self.load_button.setFixedWidth(150)

        button_layout.addStretch()
        button_layout.addWidget(self.send_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.load_button)
        button_layout.addStretch()

        content_layout.addLayout(button_layout)

        # Add the content widget to main layout with center alignment
        layout.addWidget(content_widget, alignment=Qt.AlignCenter)
        
        # Add bottom stretch to push content up
        layout.addStretch(3)

        self.setLayout(layout)

        # Connect button click handlers
        self.clear_button.clicked.connect(self.confirm_clear)
        self.save_button.clicked.connect(self.save_configuration)
        self.load_button.clicked.connect(self.load_configuration)

    def send_packet(self):
        """Send a DNS query packet."""
        # Disable send button and change color
        self.send_button.setEnabled(False)
        self.send_button.setStyleSheet("background-color: gray; color: white; font-weight: bold;")
        QApplication.processEvents()  # Update UI immediately

        try:
            # Validate domain name
            domain = self.query_name.text().strip()
            if not domain:
                raise ValueError("Please enter a domain name")
            if not self.validate_domain(domain):
                raise ValueError("Invalid domain name format")
            
            # Get query type from dropdown
            query_type_text = self.query_type.currentText()
            qtype = query_type_text.split()[0]  # Get just the type (A, AAAA, etc.)
            
            # Check cache first
            cache_key = (domain, qtype)
            if cache_key in self.dns_cache:
                resolved_ip = self.dns_cache[cache_key]
                cache_explanation = (
                    f"DNS Resolution for {domain} (CACHED):\n\n"
                    f"Cache Hit!\n"
                    f"→ Found {domain} in local DNS cache\n"
                    f"→ Cached IP address: {resolved_ip}\n"
                    f"→ Query Type: {qtype}\n\n"
                    f"No recursive DNS resolution needed!\n"
                    f"Using cached result to save time and network resources."
                )
                QMessageBox.information(self, "DNS Cache Resolution", cache_explanation)
                
                # Log the cache hit
                timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz")
                if self.log_sent_callback:
                    self.log_sent_callback(
                        timestamp,
                        "DNS-Cache",
                        self.src_ip.text().strip(),
                        "N/A",
                        self.src_port_field.text(),
                        resolved_ip,
                        "N/A",
                        f"Cache hit for {domain} ({qtype}): {resolved_ip}"
                    )
                return
            
            # Validate source IP
            src_ip = self.src_ip.text().strip()
            try:
                socket.inet_aton(src_ip)
            except:
                raise ValueError("Invalid source IP address format")
            
            # Validate source port
            try:
                src_port = int(self.src_port_field.text())
                if not (0 <= src_port <= 65535):
                    raise ValueError
            except (ValueError, TypeError):
                raise ValueError("Source port must be a number between 0 and 65535")

            # Add a trailing dot to the domain name if it doesn't have one
            if not domain.endswith('.'):
                domain += '.'

            # Try to resolve domain
            try:
                resolved_ip = socket.gethostbyname(domain)
                # Cache the result
                self.dns_cache[cache_key] = resolved_ip
            except socket.gaierror:
                resolved_ip = "Unable to resolve"

            # Create and send DNS query
            try:
                # Convert IP addresses to standard format
                src_ip = socket.gethostbyname(src_ip)  # This will standardize the IP format
                
                # Force use of Google DNS
                dns_server = "8.8.8.8"  # Use Google's DNS server
                
                print(f"Using DNS server: {dns_server}")
                
                dns_packet = IP(src=src_ip, dst=dns_server) / \
                            UDP(sport=src_port, dport=53) / \
                            DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
                
                # Send packet
                send(dns_packet, verbose=False)
            except socket.gaierror as e:
                raise ValueError(f"Invalid IP address format: {str(e)}")
            except Exception as e:
                raise ValueError(f"Failed to create or send DNS packet: {str(e)}")

            # Get current timestamp
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz")

            # Log to sent packet pane only (not capture log)
            if self.log_sent_callback:
                self.log_sent_callback(
                    timestamp,          # When
                    "DNS",             # Protocol
                    src_ip,            # Source IP
                    "N/A",             # Source MAC
                    str(src_port),     # Source Port
                    dns_server,        # Destination IP (DNS server)
                    "53",              # Destination Port (DNS)
                    f"{qtype} lookup for {domain} (Resolves to: {resolved_ip})"  # Info
                )

            # Show the recursive DNS resolution process
            explanation = (
                f"Recursive DNS Resolution Process for {domain}:\n\n"
                f"Step 1: Initial Query\n"
                f"→ Your Computer ({src_ip}) sends DNS query for {domain}\n"
                f"→ Query Type: {qtype}\n\n"
                f"Step 2: Local DNS Resolver Check\n"
                f"→ Checked local cache for {domain}\n"
                f"→ Not found in cache, starting recursive resolution\n\n"
                f"Step 3: Root DNS Server Query\n"
                f"→ Asks Root Server about {domain}\n"
                f"→ Root Server returns TLD (.{domain.split('.')[-2]}) server addresses\n\n"
                f"Step 4: TLD Server Query\n"
                f"→ Asks .{domain.split('.')[-2]} TLD server about {domain}\n"
                f"→ TLD server returns Authoritative server addresses\n\n"
                f"Step 5: Authoritative Server Query\n"
                f"→ Asks Authoritative server for {domain}\n"
                f"→ Receives final IP address: {resolved_ip}\n\n"
                f"Step 6: Response Return\n"
                f"→ DNS Resolver caches the result\n"
                f"→ Returns IP address to your computer\n\n"
                f"Step 7: Final Connection\n"
                f"→ Your computer can now connect to {resolved_ip}\n\n"
                f"Cache Status:\n"
                f"• Result has been cached for future queries\n"
                f"• Different record types have different cache durations (TTL)\n"
                f"• {qtype} records typically cache for hours to days"
            )
            
            QMessageBox.information(self, "Recursive DNS Resolution Process", explanation)

            # Log the steps to simulate actual DNS resolution
            timestamp = QDateTime.currentDateTime().toString("hh:mm:ss.zzz")
            if self.log_sent_callback:
                self.log_sent_callback(
                    timestamp,
                    "DNS-Root",
                    src_ip,
                    "N/A",
                    str(src_port),
                    "Root DNS",
                    "53",
                    f"Querying root servers for {domain}"
                )
                
                self.log_sent_callback(
                    timestamp,
                    "DNS-TLD",
                    src_ip,
                    "N/A",
                    str(src_port),
                    f".{domain.split('.')[-2]} TLD",
                    "53",
                    f"Querying TLD servers for {domain}"
                )
                
                self.log_sent_callback(
                    timestamp,
                    "DNS-Auth",
                    src_ip,
                    "N/A",
                    str(src_port),
                    "Auth DNS",
                    "53",
                    f"Querying authoritative servers for {domain}"
                )
                
                self.log_sent_callback(
                    timestamp,
                    "DNS-Final",
                    src_ip,
                    "N/A",
                    str(src_port),
                    resolved_ip,
                    "N/A",
                    f"Resolved {domain} to {resolved_ip}"
                )

        except ValueError as ve:
            QMessageBox.critical(self, "Validation Error", str(ve))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send DNS query: {str(e)}")
        finally:
            # Re-enable send button and restore color
            self.send_button.setEnabled(True)
            self.send_button.setStyleSheet("background-color: black; color: white; font-weight: bold;")

    def get_query_type_explanation(self, qtype):
        """Return a user-friendly explanation of DNS query types."""
        explanations = {
            "A": "Looks up the IPv4 address for a domain (most common)",
            "AAAA": "Looks up the IPv6 address for a domain (newer internet protocol)",
            "MX": "Finds mail servers responsible for accepting email",
            "NS": "Finds authoritative name servers for the domain",
            "TXT": "Looks up text records (often used for verification)",
            "CNAME": "Finds the canonical name (aliases) for a domain",
            "SOA": "Gets information about the domain's zone of authority",
            "PTR": "Reverse DNS lookup - finds domain name for an IP"
        }
        return explanations.get(qtype, "Looks up DNS records for the domain")

    def confirm_clear(self):
        """Confirm before clearing all fields."""
        reply = QMessageBox.question(
            self, "Confirm Clear",
            "Are you sure you want to clear all fields?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.clear_fields()

    def clear_fields(self):
        """Clear all input fields."""
        self.src_ip.setText(self.get_local_ip())
        self.src_port_field.setText(str(random.randint(49152, 65535)))  # Generate new random port
        self.dst_ip.setText(self.get_system_dns())  # Reset to system DNS
        self.query_name.clear()
        self.query_type.setCurrentIndex(0)

    def save_configuration(self):
        """Save the current configuration to a file."""
        try:
            config = {
                "src_ip": self.src_ip.text(),
                "dst_ip": self.dst_ip.text(),
                "query_name": self.query_name.text(),
                "query_type": self.query_type.currentText(),
                "src_port": self.src_port_field.text()
            }
            
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Save Configuration",
                "",
                "JSON Files (*.json)"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(config, f, indent=4)
                QMessageBox.information(self, "Success", "Configuration saved successfully")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save configuration: {str(e)}")

    def load_configuration(self):
        """Load a configuration from a file."""
        try:
            filename, _ = QFileDialog.getOpenFileName(
                self,
                "Load Configuration",
                "",
                "JSON Files (*.json)"
            )
            
            if filename:
                with open(filename, 'r') as f:
                    config = json.load(f)
                
                self.src_ip.setText(config.get("src_ip", self.get_local_ip()))
                self.dst_ip.setText(config.get("dst_ip", self.get_system_dns()))
                self.query_name.setText(config.get("query_name", ""))
                self.query_type.setCurrentText(config.get("query_type", "A (IPv4 Address)"))
                self.src_port_field.setText(config.get("src_port", str(random.randint(49152, 65535))))
                
                QMessageBox.information(self, "Success", "Configuration loaded successfully")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load configuration: {str(e)}")


def default_send_callback(timestamp, message):
    print(f"{timestamp}: {message}")


# Main block for testing
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = QWidget()
    window.setWindowTitle("DNS Tab Test")
    layout = QVBoxLayout(window)
    
    dns_tab = DNSTab(
        log_sent_callback=lambda *args: print("Packet sent:", args)
    )
    layout.addWidget(dns_tab)
    
    window.resize(800, 600)
    window.show()
    
    sys.exit(app.exec_())