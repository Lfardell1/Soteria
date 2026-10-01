# **Soteria**

**Soteria** is a tool for those who value their anonymity and seek freedom from the constraints of a tracked digital existence. This tool embodies a programmer’s vision to create a sanctuary for digital privacy and security, enabling users to operate without leaving a trace. Designed with privacy and security at its core, Soteria provides a robust, ephemeral environment for anonymous actions.

Soteria offers a robust solution for Unix-based systems to transition into a "secure mode" with ease. This tool leverages a sophisticated combination of anonymity frameworks, encryption protocols, and a dynamically created ephemeral file system. The environment operates entirely in the system's RAM, ensuring no data persists beyond the session.

Soteria acts as a self-contained micro-environment, providing users with familiar Unix commands and tools while integrating additional sandboxed layers for enhanced protection. Networking capabilities are seamlessly incorporated, featuring built-in support for privacy-enhancing tools such as Tor and VPNs, enabling secure and anonymous communication. Network traffic is routed through encrypted tunnels, ensuring no identifiable metadata escapes the secure environment.

Every component runs in isolation to minimize vulnerabilities, offering a secure workspace for sensitive tasks. Once the session concludes, the environment is completely erased—data in RAM is zeroed out, and no trace of the session remains. Inspired by the amnesiac capabilities of TailsOS, Soteria brings similar functionality as a lightweight program designed specifically for Linux. It’s the ideal tool for privacy-conscious users who need a temporary, secure workspace without the overhead of a full OS.

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
  - `Go 1.22+`
  - `rsync`
  - `iptables`
  - `openvpn`
  - `tor` (optional)
  - `dnscrypt-proxy` (optional)
  - `proxychains4` (optional)

### **Installation**
1. Clone the repository:
   ```bash
   git clone https://github.com/Lfardell1/Soteria.git
   cd Soteria
   ```

2. Install host dependencies:
   ```bash
   sudo ./scripts/install_dependencies.sh
   ```

3. Build the project:
   ```bash
   make build
   # or: go build -o soteria ./cmd/soteria
   ```

4. Set up the configuration file:
   ```bash
   cp config/config.example.json config/config.json
   # Edit config/config.json — point vpn.config_file at your OpenVPN client config
   # and enable the layers you need (vpn / tor / dnscrypt / proxychains).
   ```

---

## **Configuration**

Soteria uses a JSON configuration file located at `config/config.json`. Below is an example configuration:

```json
{
  "filesystem": {
    "tmpfs_size": "2G",
    "mount_point": "/mnt/secure",
    "tools_dir": "/usr/local/tools",
    "populate_paths": ["/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib"]
  },
  "monitoring": {
    "processes": ["openvpn", "tor"],
    "tmpfs_free_space_min": "100M",
    "poll_interval_seconds": 2
  },
  "vpn": {
    "enabled": true,
    "config_file": "/etc/openvpn/client.conf",
    "interface": "tun0"
  },
  "tor": {
    "enabled": false,
    "socks_port": 9050
  },
  "dnscrypt": {
    "enabled": false,
    "config_file": "/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
  },
  "proxychains": {
    "enabled": false,
    "config_file": "/etc/proxychains4.conf"
  },
  "network": {
    "check_connectivity": true,
    "gateway": "1.1.1.1",
    "kill_switch": true
  }
}
```

### **Key Configuration Options**
- `filesystem.tmpfs_size`: Size of the temporary filesystem.
- `filesystem.populate_paths`: Host paths rsynced into the ephemeral workspace.
- `monitoring.processes`: List of critical processes to monitor.
- `vpn.enabled` / `vpn.config_file`: OpenVPN client bring-up.
- `tor.enabled` / `dnscrypt.enabled` / `proxychains.enabled`: Optional anonymity layers.
- `network.kill_switch`: Fail-closed iptables policy (requires VPN and/or Tor).
- `network.gateway`: IP address used for connectivity checks.

---

## **Usage**

1. **Start Secure Mode** (root required):
   ```bash
   sudo ./soteria -config config/config.json
   ```

2. **Quit Secure Mode**:
   - Press `q` in the TUI to safely unmount and clean up the environment.
   - `Ctrl+C` / `SIGTERM` also trigger ordered teardown.

3. **Monitor Logs**:
   - Real-time alerts and stats are displayed in the TUI (kept in memory; no host disk log by default).

---

## **How It Works**

1. **Ephemeral Environment**:
   - Soteria mounts a `tmpfs` at `/mnt/secure` (configurable).
   - Host tool paths from `populate_paths` are rsynced into this memory-only filesystem.

2. **Networking**:
   - An iptables kill-switch is applied first (fail-closed).
   - Traffic is then routed through the VPN interface (e.g., `tun0`) and/or Tor SOCKS.
   - Optional DNSCrypt replaces cleartext DNS; Proxychains can wrap individual apps.

3. **Monitoring**:
   - The system continuously checks process health, tmpfs free space, and network integrity.
   - Typed alerts (`ProcessDown`, `DiskLow`, `LeakRisk`, `ConnectivityLost`) feed the TUI.

4. **Teardown**:
   - Pressing `q` stops the TUI, cancels monitors, stops network services, restores iptables, zeroes small files in the tmpfs, and unmounts.

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

