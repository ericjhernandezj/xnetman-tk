import threading
from dataclasses import dataclass
import tkinter as tk
from tkinter import ttk, messagebox
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
        wifi_devices = nmcli.device.wifi()
        for wifi in wifi_devices:
            if wifi.in_use:
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
        try:
            is_connected, connected_bssid = get_connected_bssid()
            networks = scan_networks()
            wifi_status = "On" if get_wifi_status() else "Off"
            # Schedule UI update in main thread
            root.after(0, lambda: update_networks_ui(networks, is_connected, connected_bssid, wifi_status))
        except Exception as e:
            root.after(0, lambda: show_error(f"Failed to scan networks: {e}"))

    loading_label.config(text="Scanning networks...")
    refresh_button.config(state="disabled")
    threading.Thread(target=do_scan, daemon=True).start()

def show_error(message: str):
    """Show error message to user."""
    loading_label.config(text="")
    refresh_button.config(state="normal")
    messagebox.showerror("Error", message)

def update_networks_ui(networks, is_connected, connected_bssid, wifi_status):
    """Update the UI with scanned networks."""
    try:
        wifi_status_content.config(text=wifi_status)
        # Clear existing rows
        for row in networks_tree.get_children():
            networks_tree.delete(row)
        
        # Sort networks by signal strength (descending)
        networks.sort(key=lambda x: x.signal, reverse=True)
        
        # Scan and display networks
        for network in networks:
            is_current = is_connected and network.bssid == connected_bssid
            networks_tree.insert(
                "",
                tk.END,
                values=(
                    network.ssid,
                    network.bssid,
                    f"{network.signal}% {signal_to_bars(network.signal)}",
                    "Yes" if network.requires_password else "No",
                    f"{network.frequency} MHz" if network.frequency else "Unknown",
                    network.security or "Open",
                    network.vendor or "Unknown"
                ),
                tags=("highlight",) if is_current else ()
            )
        
        loading_label.config(text=f"Found {len(networks)} networks")
        refresh_button.config(state="normal")
    except Exception as e:
        show_error(f"Failed to update UI: {e}")

def load_networks_async():
    """Trigger a network scan and UI update."""
    load_networks()

def on_network_select(event):
    """Handle single click on network item to show details."""
    # Get the item that was clicked
    item_id = networks_tree.identify_row(event.y) if hasattr(event, 'y') else None
    
    if not item_id:
        # If no specific item clicked, check current selection
        selected_items = networks_tree.selection()
        if not selected_items:
            return
        item_id = selected_items[0]
    
    # Select the item
    networks_tree.selection_set(item_id)
    networks_tree.focus(item_id)
    
    # Get item data
    item = networks_tree.item(item_id)
    values = item["values"]
    
    if not values or len(values) < 7:
        return
    
    # Create network info object from the selected values
    network_info = {
        'ssid': values[0],
        'bssid': values[1],
        'signal': values[2],
        'requires_password': values[3],
        'frequency': values[4],
        'security': values[5],
        'vendor': values[6]
    }
    
    # Update the detail frame with selected network info
    show_network_details(network_info)
    
    # Switch to detail frame
    switch_frame(network_detailed_frame, main_frame)

def show_network_details(network_info):
    """Populate the detail frame with network information."""
    # Clear existing content widgets in detail frame
    for widget in network_detailed_frame.winfo_children():
        widget.destroy()
    
    # Create main container
    container = tk.Frame(network_detailed_frame)
    container.pack(fill="both", expand=True, padx=20, pady=20)
    
    # Header with back button
    header_frame = tk.Frame(container)
    header_frame.pack(fill="x", pady=(0, 20))
    
    back_button = ttk.Button(header_frame, text="← Back to Networks", 
                            command=lambda: switch_frame(main_frame, network_detailed_frame))
    back_button.pack(side="left")
    
    # Title
    title_label = tk.Label(container, text=f"Network Details", 
                          font=("Arial", 16, "bold"))
    title_label.pack(pady=(0, 10))
    
    # Network name (SSID) prominently displayed
    ssid_label = tk.Label(container, text=network_info['ssid'], 
                         font=("Arial", 14, "bold"))
    ssid_label.pack(pady=(0, 20))
    
    # Network information in a nice layout
    info_frame = tk.LabelFrame(container, text="Network Information", 
                              font=("Arial", 12, "bold"), padx=20, pady=15)
    info_frame.pack(fill="x", pady=(0, 20))
    
    # Create info rows
    info_data = [
        ("BSSID:", network_info['bssid']),
        ("Signal Strength:", network_info['signal']),
        ("Security:", network_info['security']),
        ("Password Required:", network_info['requires_password']),
        ("Frequency:", network_info['frequency']),
        ("Vendor:", network_info['vendor'])
    ]
    
    for i, (label_text, value_text) in enumerate(info_data):
        row_frame = tk.Frame(info_frame)
        row_frame.pack(fill="x", pady=8)
        
        label = tk.Label(row_frame, text=label_text, font=("Arial", 10, "bold"), 
                        width=18, anchor="w")
        label.pack(side="left")
        
        value = tk.Label(row_frame, text=str(value_text), anchor="w",
                        font=("Arial", 10))
        value.pack(side="left", fill="x", expand=True)
    
    # Action buttons
    button_frame = tk.Frame(container)
    button_frame.pack(fill="x", pady=20)
    
    # Connect button (centered)
    connect_button = ttk.Button(button_frame, text="Connect to Network", 
                               command=lambda: connect_to_network(network_info['ssid']))
    connect_button.pack(pady=10)
    
    # Refresh this network button
    refresh_network_button = ttk.Button(button_frame, text="Refresh Network Info", 
                                       command=lambda: refresh_single_network(network_info['bssid']))
    refresh_network_button.pack(pady=5)

def connect_to_network(ssid):
    """Attempt to connect to the selected network."""
    try:
        # This is a placeholder - you might want to implement password dialog
        # and actual connection logic here
        messagebox.showinfo("Connect", f"Attempting to connect to '{ssid}'...\n\n"
                           "Note: Full connection implementation would require "
                           "password handling and nmcli connection commands.")
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect: {e}")

def refresh_single_network(bssid):
    """Refresh information for a single network."""
    messagebox.showinfo("Refresh", f"Refreshing network info for BSSID: {bssid}\n\n"
                       "This would scan for updated information about this specific network.")

def switch_frame(show, hide):
    """Switch between frames smoothly."""
    hide.pack_forget()
    show.pack(fill="both", expand=True)

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
