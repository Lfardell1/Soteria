# **Soteria**

**Soteria** is a tool for those who value their anonymity and seek freedom from the constraints of a tracked digital existence. This tool embodies a programmer’s vision to create a sanctuary for digital privacy and security, enabling users to operate without leaving a trace. Designed with privacy and security at its core, Soteria provides a robust, ephemeral environment for anonymous actions.

---

## **Why Soteria?**

Soteria is built for individuals who demand:

- **Untraceable Digital Operations**: All actions occur within an in-memory ephemeral filesystem, ensuring no data remains after use.
- **Secure Networking**: Enforced routing through Proxychains (optional) VPNs & Tor + DNSCrypt for complete anonymity. - More Features to come in this area
- **Real-Time Awareness**: Instant alerts and monitoring to ensure all systems are operating securely.

In a world where privacy is increasingly compromised, Soteria offers a way to take back control.

---

## **Features**

### **Privacy and Anonymity**
- **Ephemeral Environment**: Every action occurs within a secure `tmpfs`, ensuring no trace remains on the host system.
- **Isolation**: Tools, processes, and files are entirely confined to a secure memory space.
- **Networking Anonymity**: All traffic is securely routed through VPN or Tor, with strict enforcement to prevent leaks.

### **Robust Monitoring**
- **Process Tracking**: Monitors critical processes such as VPN and Tor, ensuring they’re active and functional.
- **Network Integrity**: Continuously validates that all traffic is anonymized and routed through secure gateways.
- **Real-Time Alerts**: Provides immediate warnings for any anomalies, such as broken network links or critical process failures.

### **Text User Interface (TUI)**
- **Full-Screen Experience**: A beautifully styled interface provides an overview of the system’s state.
- **Live Updates**: Displays real-time stats on filesystem usage, process statuses, and network connectivity.
- **User-Friendly**: Intuitive design with color-coded alerts and minimal interaction requirements.

### **Modular and Configurable**
- **User-Defined Monitoring**: Easily configure the processes and thresholds to monitor.
- **Extensible**: Built to integrate seamlessly with additional tools or workflows.
- **Customizable Networking**: Supports various VPN configurations and Tor integration.

---

## **Getting Started**

### **Prerequisites**
- Linux system with root access.
- Installed dependencies:
  - `Go 1.20+`
  - `rsync`
  - `iptables`
  - `openvpn`
  - `tor` (optional for anonymity)

### **Installation**
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/soteria.git
   cd soteria
   ```

2. Build the project:
   ```bash
   go build -o soteria cmd/main.go
   ```

3. Install dependencies:
   ```bash
   sudo ./scripts/install_dependencies.sh
   ```

4. Set up the configuration file:
   ```bash
   cp config/config.example.json config/config.json
   ```

---

## **Configuration**

Soteria uses a JSON configuration file located at `config/config.json`. Below is an example configuration:

```json
{
  "filesystem": {
    "tmpfs_size": "2G",
    "mount_point": "/mnt/secure",
    "tools_dir": "/usr/local/tools"
  },
  "monitoring": {
    "processes": ["openvpn", "tor", "tor-browser"],
    "tmpfs_free_space_min": "100M"
  },
  "vpn": {
    "config_file": "/etc/openvpn/client.conf",
    "interface": "tun0"
  },
  "network": {
    "check_connectivity": true,
    "gateway": "8.8.8.8"
  }
}
```

### **Key Configuration Options**
- `filesystem.tmpfs_size`: Size of the temporary filesystem.
- `monitoring.processes`: List of critical processes to monitor.
- `vpn.config_file`: Path to the VPN configuration file.
- `network.gateway`: IP address to check for connectivity.

---

## **Usage**

1. **Start Secure Mode**:
   ```bash
   ./soteria
   ```

2. **Quit Secure Mode**:
   - Press `q` in the TUI to safely unmount and clean up the environment.

3. **Monitor Logs**:
   - Real-time alerts and stats are displayed in the TUI.

---

## **How It Works**

1. **Ephemeral Environment**:
   - Soteria mounts a `tmpfs` at `/mnt/secure`.
   - All tools and files are loaded into this memory-only filesystem.

2. **Networking**:
   - Traffic is routed through the VPN interface (e.g., `tun0`) or Tor.
   - `iptables` rules enforce that no traffic bypasses secure routes.

3. **Monitoring**:
   - The system continuously checks process health and network integrity.
   - Alerts are generated for any security risks or failures.

---

## **Contributing**

Contributions are welcome! If you’d like to improve Soteria or report an issue, please:
1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request with detailed explanations.

---

## **License**

Soteria is released under the MIT License. See `LICENSE` for details.

---

## **Disclaimer**

Soteria is a tool for privacy-conscious users. It is the responsibility of the user to ensure compliance with applicable laws and regulations in their jurisdiction. The creators of Soteria are not liable for any misuse of this tool.
```

