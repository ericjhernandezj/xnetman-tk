import logging
import threading
from dataclasses import dataclass
from typing import Dict, List, Literal, Optional, Tuple, TypedDict
import tkinter as tk
from tkinter import ttk, messagebox
from nmcli.data.device import DeviceWifi
from nmcli.data.connection import Connection

import nmcli
from mac_vendor_lookup import MacLookup

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

nmcli.disable_use_sudo()

# =======================
# Type Definitions
# =======================

class ColumnConfig(TypedDict):
    width: int
    anchor: Literal["nw", "n", "ne", "w", "center", "e", "sw", "s", "se"]


# =======================
# Data Models
# =======================

@dataclass
class NetworkInfo:
    ssid: str
    bssid: str
    signal: int
    requires_password: bool

    @classmethod
    def from_wifi_device(cls, wifi_device: DeviceWifi) -> "NetworkInfo":
        return cls(
            ssid=wifi_device.ssid,
            bssid=wifi_device.bssid,
            signal=wifi_device.signal,
            requires_password=bool(wifi_device.security),
        )

@dataclass
class NetworkInfoExtended(NetworkInfo):
    frequency: Optional[int] = None
    security: Optional[str] = None
    vendor: Optional[str] = None

    @classmethod
    def from_wifi_device(cls, wifi_device: DeviceWifi) -> "NetworkInfoExtended":
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
# Network Services
# =======================

class NetworkService:    
    def __init__(self) -> None:
        self._mac_lookup = MacLookup()
        
    def get_vendor_from_bssid(self, bssid: str) -> str:
        try:
            return self._mac_lookup.lookup(bssid)
        except Exception:
            return "Unknown"
            
    def get_wifi_status(self) -> bool:
        try:
            return nmcli.radio.wifi()
        except Exception as e:
            logger.error(f"Unable to get Wi-Fi status: {e}")
            return False

    def scan_networks(self) -> List[NetworkInfo]:
        networks: List[NetworkInfo] = []

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
                    logger.warning(f"Failed to process network {wifi.ssid}: {e}")
                    continue

            logger.info(f"Found {len(networks)} unique networks.")
        except Exception as e:
            logger.error(f"Scanning networks failed: {e}")
        
        return networks

    def get_connected_bssid(self) -> Tuple[bool, Optional[str]]:
        try:
            wifi_devices = nmcli.device.wifi()
            for wifi in wifi_devices:
                if wifi.in_use:
                    return True, wifi.bssid
            return False, None
        except Exception as e:
            logger.error(f"Unable to get current BSSID: {e}")
            return False, None
        
    def get_network_by_bssid(self, target_bssid: str) -> Optional[NetworkInfoExtended]:
        try:
            for wifi in nmcli.device.wifi():
                if wifi.bssid.lower() == target_bssid.lower():
                    return NetworkInfoExtended.from_wifi_device(wifi)
            return None
        except Exception as e:
            logger.error(f"Error getting network by BSSID: {e}")
            return None

    def get_saved_connections(self) -> List[Connection]:
        try:
            saved_connections: List[Connection] = []
            for conn in nmcli.connection():
                if conn.conn_type == "wifi":
                    saved_connections.append(conn)
            return saved_connections
        except Exception as e:
            logger.error(f"Unable to get saved connections: {e}")
            return []

    def connect_to_network(self, ssid: str, saved_connection: bool, password: Optional[str] = None) -> bool:
        if saved_connection:
            try:
                nmcli.connection.up(name=ssid)
                return True
            except Exception as e:
                logger.error(f"Unable to connect to saved network '{ssid}': {e}")
                return False
        else:
            try:
                if password:
                    nmcli.device.wifi_connect(ssid=ssid, password=password)
                else:
                    nmcli.device.wifi_connect(ssid=ssid)
                logger.info(f"Connected to network '{ssid}' successfully.")
                return True
            except Exception as e:
                logger.error(f"Unable to connect to network '{ssid}': {e}")
                return False

# =======================
# Utility Functions
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


network_service = NetworkService()
get_vendor_from_bssid = network_service.get_vendor_from_bssid


# =======================
# UI Components
# =======================

class WiFiScannerApp:
    def __init__(self) -> None:
        self.network_service = NetworkService()
        self.root = tk.Tk()
        self.setup_main_window()
        self.create_main_frame()

    def setup_main_window(self) -> None:
        self.root.geometry("600x400")
        self.root.title("xNetMan (Tkinter Edition)")
        self.root.minsize(600, 400)
    
    def create_main_frame(self) -> None:
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill="both", expand=True)
        
        header_frame = tk.Frame(self.main_frame)
        header_frame.pack(fill="x", padx=20, pady=20)
        
        title_label = tk.Label(
            header_frame, 
            text="WiFi Network Scanner", 
            font=("Arial", 18, "bold")
        )
        title_label.pack()
        
        controls_frame = tk.Frame(self.main_frame)
        controls_frame.pack(fill="x", padx=20, pady=(0, 10))
        
        status_frame = tk.Frame(controls_frame)
        status_frame.pack(fill="x", pady=5)
        
        tk.Label(
            status_frame, 
            text="WiFi Status:", 
            font=("Arial", 10, "bold")
        ).pack(side="left")
        
        self.wifi_status_content = tk.Label(status_frame, text="Loading...")
        self.wifi_status_content.pack(side="left", padx=(10, 0))
        
        control_buttons_frame = tk.Frame(controls_frame)
        control_buttons_frame.pack(fill="x", pady=5)
        
        self.refresh_button = ttk.Button(
            control_buttons_frame, 
            text="Refresh", 
            command=self.load_networks_async
        )
        self.refresh_button.pack(side="left")
        
        self.loading_label = tk.Label(control_buttons_frame, text="")
        self.loading_label.pack(side="left", padx=(20, 0))

        self.show_saved_connections_button = tk.Button(
            control_buttons_frame,
            text="Saved Connections",
            command=self.show_saved_connections
        )
        self.show_saved_connections_button.pack(side="right")
        
        instructions = tk.Label(
            self.main_frame, 
            text="Double-click on any network to view more details or connect.",
            font=("Arial", 10)
        )
        instructions.pack(pady=(0, 10))
        
        self.create_networks_table()

    def create_networks_table(self) -> None:
        table_frame = tk.Frame(self.main_frame)
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        columns = ("SSID", "BSSID", "Signal", "Protected")
        self.networks_tree = ttk.Treeview(
            table_frame, 
            columns=columns, 
            show="headings", 
            height=15
        )
        
        column_configs: Dict[str, ColumnConfig] = {
            "SSID": {"width": 150, "anchor": "w"},
            "BSSID": {"width": 140, "anchor": "center"},
            "Signal": {"width": 100, "anchor": "center"},
            "Protected": {"width": 120, "anchor": "center"}
        }
        
        for col in columns:
            self.networks_tree.heading(col, text=col)
            config = column_configs.get(col, {"width": 100, "anchor": "center"})
            self.networks_tree.column(col, width=config["width"], anchor=config["anchor"])
                
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.networks_tree.yview)
        self.networks_tree.configure(yscrollcommand=scrollbar.set)
        
        self.networks_tree.pack(side="left", fill="both", expand=True)
        self.networks_tree.bind("<Double-1>", self.on_network_double_click)
        scrollbar.pack(side="right", fill="y")
        
        self.networks_tree.tag_configure("highlight", background="lightblue")

    def on_network_double_click(self, event: tk.Event) -> None:
        selected_item = self.networks_tree.focus()
        if not selected_item:
            return
        values = self.networks_tree.item(selected_item, "values")
        if not values or len(values) < 2:
            return
        
        bssid = values[1]
        NetworkDetailWindow.show_network_details(self.root, self.network_service, bssid)

    def show_saved_connections(self) -> None:
        SavedConnectionsWindow._create_window(self.root)

    def show_error(self, message: str) -> None:
        self.loading_label.config(text="")
        self.refresh_button.config(state="normal")
        messagebox.showerror("Error", message)

    def update_networks_ui(
        self, 
        networks: List[NetworkInfo], 
        is_connected: bool, 
        connected_bssid: Optional[str], 
        wifi_status: str
    ) -> None:
        try:
            self.wifi_status_content.config(text=wifi_status)
            if wifi_status == "Off":
                messagebox.showwarning(
                    "Wi-Fi Disabled", 
                    "Wi-Fi is turned off. Enable Wi-Fi to scan for networks."
                )
                
            for row in self.networks_tree.get_children():
                self.networks_tree.delete(row)
            
            networks.sort(key=lambda x: x.signal, reverse=True)
            
            for network in networks:
                is_current = is_connected and network.bssid == connected_bssid
                self.networks_tree.insert(
                    "",
                    tk.END,
                    values=(
                        network.ssid,
                        network.bssid,
                        f"{signal_to_bars(network.signal)}",
                        "Yes" if network.requires_password else "No",
                    ),
                    tags=("highlight",) if is_current else ()
                )
            
            self.loading_label.config(text=f"Found {len(networks)} networks")
            self.refresh_button.config(state="normal")
        except Exception as e:
            self.show_error(f"Failed to update UI: {e}")

    def load_networks(self) -> None:
        def do_scan() -> None:
            try:
                is_connected, connected_bssid = self.network_service.get_connected_bssid()
                networks = self.network_service.scan_networks()
                wifi_status = "On" if self.network_service.get_wifi_status() else "Off"
                
                self.root.after(0, lambda: self.update_networks_ui(
                    networks, is_connected, connected_bssid, wifi_status
                ))
            except Exception as e:
                logger.exception("Error scanning networks")
                self.root.after(0, lambda: self.show_error(f"Failed to scan networks: {str(e)}"))

        self.loading_label.config(text="Scanning networks...")
        self.refresh_button.config(state="disabled")
        threading.Thread(target=do_scan, daemon=True).start()

    def load_networks_async(self) -> None:
        self.load_networks()

    def run(self) -> None:
        self.root.after(1000, self.load_networks_async)
        self.root.mainloop()


class NetworkDetailWindow:
    @classmethod
    def show_network_details(cls, parent: tk.Tk, network_service: NetworkService, network_bssid: str) -> None:
        if not network_bssid:
            messagebox.showerror(title="No Network Selected", message="No network BSSID provided")
            return

        target_network = network_service.get_network_by_bssid(network_bssid)
        if not target_network:
            messagebox.showerror(title="Network Not Found", message="Could not find the network details.")
            return
        
        # Now create the window since we know the network exists
        window = cls._create_window(parent, network_service, target_network)
        
        # Wait for this window to be destroyed before returning to main window
        parent.wait_window(window)
    
    @classmethod
    def _create_window(cls, parent: tk.Tk, network_service: NetworkService, target_network: NetworkInfoExtended) -> tk.Toplevel:
        window = tk.Toplevel(parent)
        
        window.transient(parent)
        
        window.title("Network Details")
        window.minsize(500, 350)
        window.resizable(True, True)
        
        # Position window in the center of parent
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()
        
        window_width = 500
        window_height = 350
        
        position_x = parent_x + (parent_width - window_width) // 2
        position_y = parent_y + (parent_height - window_height) // 2
        
        window.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")
        
        # Create content
        cls._create_content(window, target_network)
        
        # Make sure the window is fully created and visible before grabbing focus
        window.update()
        window.deiconify()
        window.focus_force()
        
        # Schedule grab_set after the window is fully drawn
        window.after_idle(lambda: window.grab_set())
        
        return window
        
    @classmethod
    def _create_content(cls, window: tk.Toplevel, target_network: NetworkInfoExtended) -> None:
        main_frame = tk.Frame(window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        title_label = tk.Label(
            main_frame, 
            text="Network Details",
            font=("Arial", 18, "bold")
        )
        title_label.pack(pady=(0, 20))

        details_frame = tk.Frame(main_frame)
        details_frame.pack(fill="both", expand=True, padx=10)
        
        left_frame = tk.Frame(details_frame)
        left_frame.pack(side="left", fill="both", expand=True)
        
        right_frame = tk.Frame(details_frame)
        right_frame.pack(side="left", fill="both", expand=True)
        
        # Left column - Basic info
        tk.Label(left_frame, text="SSID:", font=("Arial", 10, "bold"), anchor="w").pack(fill="x", pady=2)
        tk.Label(left_frame, text=target_network.ssid, anchor="w").pack(fill="x", pady=2)
        
        tk.Label(left_frame, text="BSSID:", font=("Arial", 10, "bold"), anchor="w").pack(fill="x", pady=2)
        tk.Label(left_frame, text=target_network.bssid, anchor="w").pack(fill="x", pady=2)
        
        tk.Label(left_frame, text="Signal Strength:", font=("Arial", 10, "bold"), anchor="w").pack(fill="x", pady=2)
        tk.Label(left_frame, text=f"{target_network.signal} ({signal_to_bars(target_network.signal)})", anchor="w").pack(fill="x", pady=2)
        
        # Right column - Additional info
        tk.Label(right_frame, text="Frequency:", font=("Arial", 10, "bold"), anchor="w").pack(fill="x", pady=2)
        tk.Label(right_frame, text=f"{target_network.frequency or 'Unknown'} MHz", anchor="w").pack(fill="x", pady=2)
        
        tk.Label(right_frame, text="Security:", font=("Arial", 10, "bold"), anchor="w").pack(fill="x", pady=2)
        tk.Label(right_frame, text=f"{target_network.security or 'None'}", anchor="w").pack(fill="x", pady=2)
        
        tk.Label(right_frame, text="Vendor:", font=("Arial", 10, "bold"), anchor="w").pack(fill="x", pady=2)
        tk.Label(right_frame, text=f"{target_network.vendor or 'Unknown'}", anchor="w").pack(fill="x", pady=2)
        
        # Bottom section - Button
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(20, 0))
        
        close_btn = ttk.Button(
            button_frame, 
            text="Close",
            command=window.destroy,
            width=15
        )
        close_btn.pack(pady=5)

class SavedConnectionsWindow:
    @classmethod
    def _create_window(cls, parent: tk.Tk) -> tk.Toplevel:
        window = tk.Toplevel(parent)

        window.transient(parent)

        window.title("Saved Connections")
        window.minsize(500, 350)
        window.resizable(True, True)

        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()

        window_width = 500
        window_height = 350

        position_x = parent_x + (parent_width - window_width) // 2
        position_y = parent_y + (parent_height - window_height) // 2

        window.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")

        # Create content
        cls._create_content(window)

        # Make sure the window is fully created and visible before grabbing focus
        window.update()
        window.deiconify()
        window.focus_force()

        # Schedule grab_set after the window is fully drawn
        window.after_idle(lambda: window.grab_set())

        return window

    @classmethod
    def _create_content(cls, window: tk.Toplevel) -> None:
        service = NetworkService()

        main_frame = tk.Frame(window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)

        title_label = tk.Label(
            main_frame,
            text="Saved Connections",
            font=("Arial", 18, "bold")
        )
        title_label.pack(pady=(0, 20))

        details_frame = tk.Frame(main_frame)
        details_frame.pack(fill="both", expand=True, padx=10)

        saved_conns = service.get_saved_connections()

        if not saved_conns:
            tk.Label(
                details_frame,
                text="No saved connections found.",
                anchor="w"
            ).pack(fill="x", pady=2)

        # Table for saved connections
        columns = ("Name", "Device")
        tree = ttk.Treeview(
            details_frame,
            columns=columns,
            show="headings",
            height=15
        )

        column_configs: Dict[str, ColumnConfig] = {
            "Name": {"width": 100, "anchor": "w"},
            "Device": {"width": 100, "anchor": "center"},
        }

        for col in columns:
            tree.heading(col, text=col)
            config = column_configs.get(col, {"width": 100, "anchor": "center"})
            tree.column(col, width=config["width"], anchor=config["anchor"], stretch=True)

        scrollbar = ttk.Scrollbar(details_frame, orient="vertical", command=tree.yview)

        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)

        scrollbar.pack(side="right", fill="y")

        for conn in saved_conns:
            tree.insert(
                "",
                tk.END,
                values=(
                    conn.name,
                    conn.device
                )
            )

        # Bottom section - Button
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(20, 0))

        close_btn = ttk.Button(
            button_frame,
            text="Close",
            command=window.destroy,
            width=15
        )
        close_btn.pack(pady=5)

# =======================
# Application Entry Point
# =======================

def main() -> None:
    try:
        app = WiFiScannerApp()
        app.run()
    except Exception as e:
        logger.critical(f"Application crashed: {e}", exc_info=True)
        messagebox.showerror("Critical Error", f"Application crashed: {str(e)}")


if __name__ == "__main__":
    main()
