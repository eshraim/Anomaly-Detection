import ipaddress
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import numpy as np
import psutil
import socket

# Get network interfaces and their friendly names
def get_interfaces():
    interfaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interfaces[iface] = addr.address
    return interfaces

# Convert IP address to a numeric representation
def ip_to_numeric(ip):
    return int(ipaddress.IPv4Address(ip))

# Capture network traffic
def capture_packets(interface, packet_count):
    packets = scapy.sniff(iface=interface, count=packet_count)
    return packets

# Extract features from captured packets
def extract_features(packets):
    features = []
    for packet in packets:
        feature = []
        feature.append(len(packet))  # Packet length
        if IP in packet:
            feature.append(packet[IP].ttl)  # Time to live
            feature.append(packet[IP].proto)  # Protocol
        else:
            feature.extend([0, 0])
        features.append(feature)
    return features

# Train an Isolation Forest model for anomaly detection
def train_model(features):
    iso_forest = IsolationForest(contamination=0.1)
    iso_forest.fit(features)
    return iso_forest

# Detect anomalies in network traffic
def detect_anomalies(model, features):
    predictions = model.predict(features)
    return predictions

# Visualize anomalies
def visualize_anomalies(features, predictions):
    features = np.array(features)
    anomalies = features[predictions == -1]
    plt.figure(figsize=(12, 8))
    plt.scatter(features[:, 0], features[:, 1], color='blue', label='Normal')
    plt.scatter(anomalies[:, 0], anomalies[:, 1], color='red', label='Anomalies')
    plt.xlabel('Packet Length')
    plt.ylabel('Time to Live (TTL)')
    plt.legend()
    plt.title('Network Traffic Anomalies')
    plt.show()

# Main function
def main():
    # Get network interfaces
    interfaces = get_interfaces()
    print("Available interfaces:")
    for name, ip in interfaces.items():
        print(f"{name}: {ip}")

    # Select the interface to use
    interface_name = 'Wi-Fi'  # Example: 'Wi-Fi'
    if interface_name not in interfaces:
        print(f"Error: Interface '{interface_name}' not found. Please use a valid interface name from the list above.")
        return

    interface = interface_name
    packet_count = 100

    # Capture packets
    packets = capture_packets(interface, packet_count)
    print(f"Captured {len(packets)} packets from {interface_name}")

    # Extract features
    features = extract_features(packets)

    # Train model
    model = train_model(features)

    # Detect anomalies
    predictions = detect_anomalies(model, features)

    # Visualize anomalies
    visualize_anomalies(features, predictions)

    # Print results
    print("Anomalies detected:", sum(predictions == -1))
    print("Normal traffic detected:", sum(predictions == 1))

# Run the main function
if __name__ == "__main__":
    main()
