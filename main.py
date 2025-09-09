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
        wifi_devices = nmcli.device.wifi()

        for wifi in wifi_devices:
            if not wifi.ssid or wifi.ssid.strip() == "":
                continue

            try:
                network = NetworkInfo.from_wifi_device(wifi)
                # Avoid duplicates by checking if BSSID already exists
                if not any(n.bssid == network.bssid for n in networks):
                    networks.append(network)
            except Exception as e:
                print(f"[Warning] Failed to process network {wifi.ssid}: {e}")
                continue

        print(f"[Info] Found {len(networks)} unique networks.")
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
    """Scan for networks in a background thread, then update UI in main thread."""
    def do_scan():
        is_connected, connected_bssid = get_connected_bssid()
        networks = scan_networks()
        wifi_status = "On" if get_wifi_status() else "Off"
        # Schedule UI update in main thread
        root.after(0, lambda: update_networks_ui(networks, is_connected, connected_bssid, wifi_status))

    loading_label.config(text="Loading networks...")
    threading.Thread(target=do_scan, daemon=True).start()

def update_networks_ui(networks, is_connected, connected_bssid, wifi_status):
    wifi_status_content.config(text=wifi_status)
    # Clear existing rows
    for row in networks_tree.get_children():
        networks_tree.delete(row)
    # Scan and display networks
    for network in networks:
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
    """Trigger a network scan and UI update."""
    load_networks()

def on_row_double_click(event):
    selected_item = networks_tree.selection()
    if not selected_item:
        return

    item = networks_tree.item(selected_item)
    values = item["values"]

    detail_window = tk.Toplevel(root)
    detail_window.title(f"Network Details: {values[0]}")
    detail_window.geometry("400x300")

    labels = [
        "SSID", "BSSID", "Signal", "Requires Password", "Frequency", "Security", "Vendor"
    ]
    for i, (label, value) in enumerate(zip(labels, values)):
        tk.Label(detail_window, text=f"{label}: {value}", anchor="w").pack(fill="x", padx=20, pady=5)

#    ttk.Button(detail_window, text="Conectar", command=lambda: print(f"Connecting to {values[0]}...")).pack(pady=20)

# =======================
# UI Setup
# =======================

root = tk.Tk()
root.geometry("800x600")
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

networks_tree.bind("<Double-1>", on_row_double_click)

for col in columns:
    networks_tree.heading(col, text=col)
    networks_tree.column(col, stretch=True)

networks_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
networks_tree.tag_configure("highlight", background="#d0e7ff")  # Light blue row for current network

# Start scanning after window is displayed
root.after(1, load_networks_async)

# Run the app
root.mainloop()
