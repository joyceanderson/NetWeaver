from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, 
    QLabel, QHeaderView, QPushButton, QHBoxLayout, QMenu,
    QMessageBox, QListWidget, QLineEdit, QComboBox, QFileDialog, QTreeWidget, QTreeWidgetItem
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QDateTime
from PyQt5.QtGui import QFont, QColor
import json
import re
import subprocess

class PacketLogger(QWidget):
    row_selected = pyqtSignal(dict)
    packet_clicked = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.packet_count = 0
        self.selected_row = None
        self.is_capturing = False
        self.capture_thread = None

    def setup_ui(self):
        """Setup the UI components."""
        layout = QVBoxLayout()

        # Create Sent Packets section
        sent_label = QLabel("Sent Packets")
        sent_label.setFont(QFont('Arial', 10, QFont.Bold))
        layout.addWidget(sent_label)

        # Create sent packets table
        self.packet_log_table = QTableWidget()
        self.packet_log_table.setColumnCount(8)
        self.packet_log_table.setHorizontalHeaderLabels([
            "Timestamp", "Protocol", "Source IP", "Source MAC",
            "Source Port", "Destination IP", "Destination Port", "Info"
        ])
        
        # Enable column moving and resizing
        header = self.packet_log_table.horizontalHeader()
        header.setSectionsMovable(True)  # Allow column reordering
        header.setStretchLastSection(False)  # Last section (Info) stretches
        
        # Set initial column widths
        timestamp_width = 150  # Width for timestamp
        protocol_width = 70   # Width for protocol
        ip_width = 120       # Width for IP addresses
        mac_width = 130      # Width for MAC address
        port_width = 100     # Width for ports
        
        # Set specific widths for each column
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # Timestamp
        header.setSectionResizeMode(1, QHeaderView.Interactive)  # Protocol
        header.setSectionResizeMode(2, QHeaderView.Interactive)  # Source IP
        header.setSectionResizeMode(3, QHeaderView.Interactive)  # Source MAC
        header.setSectionResizeMode(4, QHeaderView.Interactive)  # Source Port
        header.setSectionResizeMode(5, QHeaderView.Interactive)  # Destination IP
        header.setSectionResizeMode(6, QHeaderView.Interactive)  # Destination Port
        header.setSectionResizeMode(7, QHeaderView.Stretch)      # Info (stretches to fill space)
        
        # Set initial column widths
        self.packet_log_table.setColumnWidth(0, timestamp_width)
        self.packet_log_table.setColumnWidth(1, protocol_width)
        self.packet_log_table.setColumnWidth(2, ip_width)
        self.packet_log_table.setColumnWidth(3, mac_width)
        self.packet_log_table.setColumnWidth(4, port_width)
        self.packet_log_table.setColumnWidth(5, ip_width)
        self.packet_log_table.setColumnWidth(6, port_width)
        
        # Enable sorting
        self.packet_log_table.setSortingEnabled(True)
        
        # Connect double click on header to reset column sizes
        header.sectionDoubleClicked.connect(self.reset_column_width)
        
        self.packet_log_table.itemClicked.connect(self._handle_item_click)
        layout.addWidget(self.packet_log_table)

        # Search bar layout
        search_layout = QHBoxLayout()

        # Search bar for filtering packets
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search Sent Packets...")
        self.search_bar.setFixedWidth(200)  # Set a fixed width in pixels, adjust as needed
        self.search_bar.setClearButtonEnabled(True)
        self.search_bar.textChanged.connect(self.filter_packets)  # Connect to filter function
        search_layout.addWidget(self.search_bar)

        # Spacer to push the delete button to the far right
        search_layout.addStretch()

        # Delete button for deleting selected packets
        self.delete_button = QPushButton("Delete Saved Packets")
        self.delete_button.clicked.connect(self.delete_selected_packets)
        search_layout.addWidget(self.delete_button)

        # Add search layout to the main layout
        layout.addLayout(search_layout)

        # Create Capture Log section
        capture_label = QLabel("Capture Log")
        capture_label.setFont(QFont('Arial', 10, QFont.Bold))
        layout.addWidget(capture_label)

        # Create capture log tree widget
        self.capture_log = QTreeWidget()
        self.capture_log.setHeaderLabels(["Field", "Value"])
        self.capture_log.setColumnCount(2)
        
        # Set column widths: Field column smaller than Value column
        header = self.capture_log.header()
        header.setSectionResizeMode(0, QHeaderView.Fixed)  # Field column fixed width
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Value column stretches
        self.capture_log.setColumnWidth(0, 100)  # Set Field column to 100 pixels
        
        layout.addWidget(self.capture_log)

        # Controls for capture, clear, save, and protocol filter
        control_layout = QHBoxLayout()
        self.capture_button = QPushButton("Start Capture")
        self.capture_button.clicked.connect(self.toggle_capture)
        control_layout.addWidget(self.capture_button)

        self.clear_button = QPushButton("Clear Log")
        self.clear_button.clicked.connect(self.clear_log)
        control_layout.addWidget(self.clear_button)

        self.save_button = QPushButton("Save Log")
        self.save_button.clicked.connect(self.save_log)
        control_layout.addWidget(self.save_button)

        # Launch Wireshark button
        self.wireshark_button = QPushButton("Launch Wireshark")
        self.wireshark_button.clicked.connect(self.launch_wireshark)
        control_layout.addWidget(self.wireshark_button)

        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems(["All", "ARP", "TCP", "UDP", "DNS"])

        # Add tool-tips to describe the layer for each protocol
        self.protocol_filter.setItemData(1, "Link Layer - ARP", Qt.ToolTipRole)  # ARP
        self.protocol_filter.setItemData(2, "Transport Layer - TCP", Qt.ToolTipRole)  # TCP
        self.protocol_filter.setItemData(3, "Transport Layer - UDP", Qt.ToolTipRole)  # UDP
        self.protocol_filter.setItemData(4, "Application Layer - DNS", Qt.ToolTipRole)  # DNS

        control_layout.addWidget(QLabel("Filter by Protocol:"))
        control_layout.addWidget(self.protocol_filter)

        self.status_label = QLabel("Capture Inactive")
        control_layout.addWidget(self.status_label)
        control_layout.setAlignment(Qt.AlignLeft)

        layout.addLayout(control_layout)

        self.setLayout(layout)
        
        # Keep track of protocol items and their details
        self.protocol_items = {}
        self.protocol_details = {}

    def launch_wireshark(self):
        """Launch Wireshark if installed."""
        try:
            subprocess.Popen(["wireshark"])
        except FileNotFoundError:
            QMessageBox.critical(self, "Error", "Wireshark is not installed or not found in PATH.")

    @pyqtSlot()
    def toggle_capture(self):
        if not self.is_capturing:
            self.start_capture()
        else:
            self.stop_capture()

    @pyqtSlot()
    def start_capture(self):
        """Start capturing packets."""
        self.is_capturing = True
        self.capture_button.setText("Stop Capture")
        self.status_label.setText("Capture Active")

        # Start packet capture
        filter_protocol = self.protocol_filter.currentText()
        filter_protocol = None if filter_protocol == "All" else filter_protocol

        # Implement capture thread here
        # self.capture_thread = CaptureThread('en0', filter_protocol=filter_protocol)
        # self.capture_thread.packet_captured.connect(self.log_packet)
        # self.capture_thread.start()

    @pyqtSlot()
    def stop_capture(self):
        """Stop capturing packets."""
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()

        self.is_capturing = False
        self.capture_button.setText("Start Capture")
        self.status_label.setText("Capture Inactive")

    def log_packet(self, packet_type, packet_info):
        """Add a packet to the appropriate log."""
        current_time = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")

        # If it's a sent packet (dictionary format)
        if isinstance(packet_info, dict):
            # Add to sent packets table
            row_position = self.packet_log_table.rowCount()
            self.packet_log_table.insertRow(row_position)

            # Create read-only items for each column
            timestamp_item = QTableWidgetItem(packet_info.get('timestamp', current_time))
            timestamp_item.setFlags(timestamp_item.flags() & ~Qt.ItemIsEditable)
            self.packet_log_table.setItem(row_position, 0, timestamp_item)

            protocol_item = QTableWidgetItem(packet_info.get('protocol', packet_type))
            protocol_item.setFlags(protocol_item.flags() & ~Qt.ItemIsEditable)
            self.packet_log_table.setItem(row_position, 1, protocol_item)

            src_ip_item = QTableWidgetItem(packet_info.get('src_ip', ''))
            src_ip_item.setFlags(src_ip_item.flags() & ~Qt.ItemIsEditable)
            self.packet_log_table.setItem(row_position, 2, src_ip_item)

            src_mac_item = QTableWidgetItem(packet_info.get('src_mac', ''))
            src_mac_item.setFlags(src_mac_item.flags() & ~Qt.ItemIsEditable)
            self.packet_log_table.setItem(row_position, 3, src_mac_item)

            src_port_item = QTableWidgetItem(str(packet_info.get('src_port', '')))
            src_port_item.setFlags(src_port_item.flags() & ~Qt.ItemIsEditable)
            self.packet_log_table.setItem(row_position, 4, src_port_item)

            dst_ip_item = QTableWidgetItem(packet_info.get('dst_ip', ''))
            dst_ip_item.setFlags(dst_ip_item.flags() & ~Qt.ItemIsEditable)
            self.packet_log_table.setItem(row_position, 5, dst_ip_item)

            dst_port_item = QTableWidgetItem(str(packet_info.get('dst_port', '')))
            dst_port_item.setFlags(dst_port_item.flags() & ~Qt.ItemIsEditable)
            self.packet_log_table.setItem(row_position, 6, dst_port_item)

            info_item = QTableWidgetItem(packet_info.get('info', ''))
            info_item.setFlags(info_item.flags() & ~Qt.ItemIsEditable)
            self.packet_log_table.setItem(row_position, 7, info_item)

            # Get or create protocol item and its details in capture log
            if packet_type not in self.protocol_items:
                protocol_item = QTreeWidgetItem(self.capture_log)
                protocol_item.setText(0, packet_type)  # Protocol in Field column
                protocol_item.setText(1, "")  # Empty Value column
                self.protocol_items[packet_type] = protocol_item
                
                # Create single Details item
                details = QTreeWidgetItem(protocol_item)
                details.setText(0, "Details")
                self.protocol_details[packet_type] = details

            # Update the details text
            self.protocol_details[packet_type].setText(1, packet_info.get('info', ''))

        else:
            # Get or create protocol item and its details for captured packet
            if packet_type not in self.protocol_items:
                protocol_item = QTreeWidgetItem(self.capture_log)
                protocol_item.setText(0, packet_type)
                protocol_item.setText(1, "")
                self.protocol_items[packet_type] = protocol_item
                
                # Create single Details item
                details = QTreeWidgetItem(protocol_item)
                details.setText(0, "Details")
                self.protocol_details[packet_type] = details

            # Update the details text
            self.protocol_details[packet_type].setText(1, str(packet_info))

        # Scroll logs to bottom
        self.packet_log_table.scrollToBottom()
        self.capture_log.scrollToBottom()
        
        # Expand the protocol item to show details
        self.protocol_items[packet_type].setExpanded(True)

    def _handle_item_click(self, item):
        """Handle clicks on sent packet table items."""
        row = item.row()
        
        # Get data from the row
        row_data = {
            'packet_type': self.packet_log_table.item(row, 1).text(),
            'src_ip': self.packet_log_table.item(row, 2).text(),
            'src_mac': self.packet_log_table.item(row, 3).text(),
            'src_port': self.packet_log_table.item(row, 4).text(),
            'dst_ip': self.packet_log_table.item(row, 5).text(),
            'dst_port': self.packet_log_table.item(row, 6).text(),
            'info': self.packet_log_table.item(row, 7).text()
        }
        
        # Emit signals
        self.row_selected.emit(row_data)
        self.packet_clicked.emit(self.packet_log_table.item(row, 7).text())

    def filter_packets(self):
        """Filter sent packets in the packet log table based on search query."""
        query = self.search_bar.text().lower()
        for row in range(self.packet_log_table.rowCount()):
            match = False
            for column in range(self.packet_log_table.columnCount()):
                item = self.packet_log_table.item(row, column)
                if item and query in item.text().lower():
                    match = True
                    break
            self.packet_log_table.setRowHidden(row, not match)

    @pyqtSlot()
    def delete_selected_packets(self):
        """Delete selected packets from the packet log table."""
        selected_rows = self.packet_log_table.selectionModel().selectedRows()
        rows_to_delete = sorted([row.row() for row in selected_rows], reverse=True)

        # Remove rows in reverse order to prevent index errors
        for row in rows_to_delete:
            self.packet_log_table.removeRow(row)

    def clear_log(self):
        """Clear both the sent packet log and capture log."""
        reply = QMessageBox.question(
            self,
            "Clear Log",
            "Are you sure you want to clear all logs?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.packet_log_table.setRowCount(0)
            self.capture_log.clear()
            self.protocol_items = {}  # Reset protocol items dictionary
            self.protocol_details = {}  # Reset protocol details dictionary

    def save_log(self):
        """Save the captured log to a JSON file."""
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Log", "", "JSON Files (*.json);;All Files (*)",
                                                   options=options)
        if file_path:
            packets = []
            for i in range(self.packet_log_table.rowCount()):
                packet = {}
                for j in range(self.packet_log_table.columnCount()):
                    packet[self.packet_log_table.horizontalHeaderItem(j).text()] = self.packet_log_table.item(i, j).text()
                packets.append(packet)

            with open(file_path, 'w') as f:
                json.dump(packets, f, indent=4)
            QMessageBox.information(self, "Save Log", "Log saved successfully.")

    def reset_column_width(self, logical_index):
        """Reset column width to its default value when double-clicking the header."""
        default_widths = {
            0: 150,  # Timestamp
            1: 70,   # Protocol
            2: 120,  # Source IP
            3: 130,  # Source MAC
            4: 100,  # Source Port
            5: 120,  # Destination IP
            6: 100,  # Destination Port
            7: -1    # Info (stretch)
        }
        
        if logical_index in default_widths:
            if default_widths[logical_index] == -1:
                self.packet_log_table.horizontalHeader().setSectionResizeMode(logical_index, QHeaderView.Stretch)
            else:
                self.packet_log_table.setColumnWidth(logical_index, default_widths[logical_index])


if __name__ == "__main__":
    from PyQt5.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)
    logger = PacketLogger()

    # Display PacketLogger
    logger.show()

    sys.exit(app.exec_())
