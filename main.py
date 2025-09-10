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
        if wifi_status == "Off":
            messagebox.showwarning("Wi-Fi Disabled", "Wi-Fi is turned off. Enable Wi-Fi to scan for networks.")
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
                    "Yes" if network.requires_password else "No",                ),
                tags=("highlight",) if is_current else ()
            )
        
        loading_label.config(text=f"Found {len(networks)} networks")
        refresh_button.config(state="normal")
    except Exception as e:
        show_error(f"Failed to update UI: {e}")

def load_networks_async():
    """Trigger a network scan and UI update."""
    load_networks()

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

class WiFiScannerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.setup_main_window()
        self.create_main_frame()
        
    def setup_main_window(self):
        """Configure the main window."""
        self.root.geometry("900x700")
        self.root.title("WiFi Network Scanner")
        self.root.minsize(800, 600)
    
    def create_main_frame(self):
        """Create the main frame with network list."""
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill="both", expand=True)
        
        # Header section
        header_frame = tk.Frame(self.main_frame)
        header_frame.pack(fill="x", padx=20, pady=20)
        
        title_label = tk.Label(header_frame, text="WiFi Network Scanner", 
                              font=("Arial", 18, "bold"))
        title_label.pack()
        
        # Status and controls section
        controls_frame = tk.Frame(self.main_frame)
        controls_frame.pack(fill="x", padx=20, pady=(0, 10))
        
        # WiFi status
        status_frame = tk.Frame(controls_frame)
        status_frame.pack(fill="x", pady=5)
        
        tk.Label(status_frame, text="WiFi Status:", font=("Arial", 10, "bold")).pack(side="left")
        self.wifi_status_content = tk.Label(status_frame, text="Loading...")
        self.wifi_status_content.pack(side="left", padx=(10, 0))
        
        # Loading and refresh controls
        control_buttons_frame = tk.Frame(controls_frame)
        control_buttons_frame.pack(fill="x", pady=5)
        
        self.refresh_button = ttk.Button(control_buttons_frame, text="🔄 Refresh Networks", 
                                        command=load_networks_async)
        self.refresh_button.pack(side="left")
        
        self.loading_label = tk.Label(control_buttons_frame, text="")
        self.loading_label.pack(side="left", padx=(20, 0))
        
        # Instructions
        instructions = tk.Label(self.main_frame, 
                               text="Click on any network to view detailed information",
                               font=("Arial", 10))
        instructions.pack(pady=(0, 10))
        
        # Networks table
        self.create_networks_table()
        
    def create_networks_table(self):
        """Create the networks treeview table."""
        # Frame for treeview and scrollbar
        table_frame = tk.Frame(self.main_frame)
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Define columns
        columns = ("SSID", "BSSID", "Signal", "Password Required")
        self.networks_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        # Configure column headings and widths
        column_configs = {
            "SSID": {"width": 150, "anchor": "w"},
            "BSSID": {"width": 140, "anchor": "center"},
            "Signal": {"width": 100, "anchor": "center"},
            "Password Required": {"width": 120, "anchor": "center"}
        }
        
        for col in columns:
            self.networks_tree.heading(col, text=col)
            config = column_configs.get(col, {"width": 100, "anchor": "center"})
            self.networks_tree.column(col, width=config["width"], anchor=config["anchor"])
                
        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.networks_tree.yview)
        self.networks_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack table and scrollbar
        self.networks_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Configure row highlighting
        self.networks_tree.tag_configure("highlight", background="lightblue")  # Standard light blue for current network

    def create_detail_frame(self):
        """Create the detail frame for showing network information."""
        self.network_detailed_frame = tk.Frame(self.root)

    def run(self):
        """Start the application."""
        # Start initial network scan
        self.main_frame.after(1000, load_networks_async)
        self.root.mainloop()

# Initialize the app
app = WiFiScannerApp()

# Make global references for backward compatibility
root = app.root
main_frame = app.main_frame
networks_tree = app.networks_tree
wifi_status_content = app.wifi_status_content
loading_label = app.loading_label
refresh_button = app.refresh_button

# Run the application
if __name__ == "__main__":
    app.run()
