import threading
from dataclasses import dataclass
import tkinter as tk
from tkinter import ttk
import nmcli
from mac_vendor_lookup import MacLookup

# =======================
# Data Models
# =======================

@dataclass
class NetworkInfo:
    ssid: str
    bssid: str
    signal: int
    requires_password: bool
    frequency: int | None = None
    security: str | None = None
    vendor: str | None = None

    @classmethod
    def from_wifi_device(cls, wifi_device):
        vendor = get_vendor_from_bssid(wifi_device.bssid)
        return cls(
            ssid=wifi_device.ssid,
            bssid=wifi_device.bssid,
            signal=wifi_device.signal,
            requires_password=bool(wifi_device.security),
            frequency=wifi_device.freq,
            security=wifi_device.security,
            vendor=vendor
        )

# =======================
# Vendor Lookup Function
# =======================

mac_lookup = MacLookup()

def get_vendor_from_bssid(bssid: str) -> str:
    """
    Looks up and returns the vendor name associated with a given BSSID (MAC address).

    Args:
        bssid (str): The BSSID (MAC address) to look up.

    Returns:
        str: The vendor name if found, otherwise "Unknown".
    """
    try:
        return mac_lookup.lookup(bssid)
    except Exception:
        return "Unknown"

# =======================
# Signal Conversion
# =======================

def signal_to_bars(signal_strength: int) -> str:
    levels = [
        "▂",        # 0–20
        "▂▃",       # 21–40
        "▂▃▄",      # 41–60
        "▂▃▄▅",     # 61–80
        "▂▃▄▅▆",    # 81–100
    ]
    index = min(signal_strength // 20, 4)
    return levels[index]

# =======================
# Network Functions
# =======================

def get_wifi_status() -> bool:
    """Check if Wi-Fi is enabled."""
    try:
        return nmcli.radio.wifi()
    except Exception as e:
        print(f"[Error] Unable to get Wi-Fi status: {e}")
        return False

def scan_networks() -> list[NetworkInfo]:
    """Scan and return available Wi-Fi networks."""
    networks = []
    try:
        for wifi in nmcli.device.wifi():
            if not wifi.ssid:
                continue
            network = NetworkInfo.from_wifi_device(wifi)
            networks.append(network)
        print(f"[Info] Found {len(networks)} networks.")
    except Exception as e:
        print(f"[Error] Scanning networks failed: {e}")
    return networks

def get_connected_bssid() -> tuple[bool, str | None]:
    """Get the BSSID of the currently connected Wi-Fi network."""
    try:
        for wifi in nmcli.device.wifi():
            if getattr(wifi, "in_use", False):
                return True, wifi.bssid
        return False, None
    except Exception as e:
        print(f"[Error] Unable to get current BSSID: {e}")
        return False, None

# =======================
# UI Functions
# =======================

def load_networks():
    """Load available networks into the UI."""
    loading_label.config(text="Loading networks...")

    is_connected, connected_bssid = get_connected_bssid()

    # Update Wi-Fi status label
    wifi_status_content.config(text="On" if get_wifi_status() else "Off")

    # Clear existing rows
    for row in networks_tree.get_children():
        networks_tree.delete(row)

    # Scan and display networks
    for network in scan_networks():
        is_current = is_connected and network.bssid == connected_bssid
        networks_tree.insert(
            "",
            tk.END,
            values=(
                network.ssid,
                network.bssid,
                signal_to_bars(network.signal),
                network.requires_password,
                network.frequency,
                network.security,
                network.vendor
            ),
            tags=("highlight",) if is_current else ()
        )

    loading_label.config(text="")

def load_networks_async():
    """Run load_networks in a background thread."""
    threading.Thread(target=load_networks, daemon=True).start()


# =======================
# UI Setup
# =======================

root = tk.Tk()
root.geometry("600x600")
root.title("Wi-Fi Scanner")

# Wi-Fi status label
tk.Label(root, text="Wi-Fi Status").pack(padx=20, pady=10)
wifi_status_content = tk.Label(root, text="Loading...")
wifi_status_content.pack()

# Loading message
loading_label = tk.Label(root, text="", fg="blue")
loading_label.pack(pady=(0, 10))

# Refresh button
refresh_button = ttk.Button(root, text="Refresh", command=load_networks_async)
refresh_button.pack()

columns = ("SSID", "BSSID", "Signal", "Password Required", "Frequency", "Security", "Vendor")
networks_tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    networks_tree.heading(col, text=col)
    networks_tree.column(col, stretch=True)

networks_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
networks_tree.tag_configure("highlight", background="#d0e7ff")  # Light blue row for current network

# Start scanning after window is displayed
root.after(1, load_networks_async)

# Run the app
root.mainloop()
