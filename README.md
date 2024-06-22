
# Network Traffic Anomaly Detection

This project detects anomalies in network traffic using an Isolation Forest machine learning model. It captures network packets, extracts features, trains a model, and visualizes anomalies.

## Requirements

Ensure you have the following Python packages installed:

- `scapy`
- `pandas`
- `scikit-learn`
- `matplotlib`
- `psutil`
- `numpy`

Install them with:

```
pip install scapy pandas scikit-learn matplotlib psutil numpy
```

## Running the Script

1. **Clone the Repository**:

```
git clone https://github.com/eshraim/Anomaly-Detection.git
cd Anomaly-Detection
```

2. **Run the Script**:

```
python anomaly_detection.py
```

## How It Works

1. **Get Network Interfaces**: Lists available network interfaces.
2. **Capture Packets**: Captures network packets from the selected interface.
3. **Extract Features**: Extracts features such as packet length, TTL, and protocol.
4. **Train Model**: Trains an Isolation Forest model on the extracted features.
5. **Detect Anomalies**: Uses the model to detect anomalies in the network traffic.
6. **Visualize Anomalies**: Plots anomalies using Matplotlib.

## Configuration

- Set the `interface_name` variable to your network interface (e.g., 'Wi-Fi').

```python
interface_name = 'Wi-Fi'
```

- Set the `packet_count` variable to the number of packets to capture.

```python
packet_count = 100
```

## Output

- Prints available network interfaces.
- Displays the number of captured packets.
- Shows the number of detected anomalies and normal traffic.
- Plots a graph of the detected anomalies.
