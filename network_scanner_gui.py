import tkinter as tk
from tkinter import messagebox
from network_scanner import *

def perform_scan(scan_type, host, port=None):
    if scan_type == "ICMP Ping":
        result = icmp_ping(host)
    elif scan_type == "TCP ACK Ping":
        result = tcp_ack_ping(host)
    elif scan_type == "SCTP Init Ping":
        result = sctp_init_ping(host)
    elif scan_type == "ICMP Timestamp Ping":
        result = icmp_timestamp_ping(host)
    elif scan_type == "ICMP Address Mask Ping":
        result = icmp_address_mask_ping(host)
    elif scan_type == "ARP Ping":
        result = arp_ping(host)
    elif scan_type == "Find MAC Address":
        result = get_mac_address(host)
        if result:
            messagebox.showinfo("Scan Result", f"MAC Address: {result}")
        else:
            messagebox.showinfo("Scan Result", "No response or host is down.")
        return
    elif scan_type == "OS Detection":
        result = os_detection(host)
        if result:
            messagebox.showinfo("Scan Result", f"Operating System: {result}")
        else:
            messagebox.showinfo("Scan Result", "No response or host is down.")
        return
    elif scan_type == "TCP Connect Scan":
        result = tcp_connect_scan(host, port)
    elif scan_type == "UDP Scan":
        result = udp_scan(host, port)
    elif scan_type == "TCP Null Scan":
        result = tcp_null_scan(host, port)
    elif scan_type == "TCP FIN Scan":
        result = tcp_fin_scan(host, port)
    elif scan_type == "Xmas Scan":
        result = xmas_scan(host, port)
    elif scan_type == "TCP ACK Scan":
        result = tcp_ack_scan(host, port)
    elif scan_type == "TCP Window Scan":
        result = tcp_window_scan(host, port)
    elif scan_type == "TCP Maimon Scan":
        result = tcp_maimon_scan(host, port)
    elif scan_type == "IP Protocol Scan":
        result = ip_protocol_scan(host)
    else:
        result = None

    if result:
        messagebox.showinfo("Scan Result", f"Response: {result}")
    else:
        messagebox.showinfo("Scan Result", "No response or host is down.")

def create_gui():
    root = tk.Tk()
    root.title("Network Scanner")

    tk.Label(root, text="Host:").grid(row=0, column=0)
    host_entry = tk.Entry(root)
    host_entry.grid(row=0, column=1)

    tk.Label(root, text="Port (optional):").grid(row=1, column=0)
    port_entry = tk.Entry(root)
    port_entry.grid(row=1, column=1)

    # Scan Category Frame
    scan_category_frame = tk.LabelFrame(root, text="Scan Category")
    scan_category_frame.grid(row=2, column=0, columnspan=2, pady=10, padx=10, sticky="ew")

    scan_categories = ["Host Discovery", "OS Discovery", "Port Scanning"]
    scan_category = tk.StringVar(root)
    scan_category.set(scan_categories[0])
    tk.OptionMenu(scan_category_frame, scan_category, *scan_categories, command=lambda _: update_scan_methods()).grid(row=0, column=0, padx=10, pady=5)

    # Scan Methods Frame
    scan_methods_frame = tk.LabelFrame(root, text="Scan Methods")
    scan_methods_frame.grid(row=3, column=0, columnspan=2, pady=10, padx=10, sticky="ew")

    scan_methods = tk.StringVar(root)
    scan_methods.set("ICMP Ping")
    scan_methods_menu = tk.OptionMenu(scan_methods_frame, scan_methods, "ICMP Ping")
    scan_methods_menu.grid(row=0, column=0, padx=10, pady=5)

    def update_scan_methods():
        category = scan_category.get()
        if category == "Host Discovery":
            options = ["ICMP Ping", "TCP ACK Ping", "SCTP Init Ping", "ICMP Timestamp Ping", "ICMP Address Mask Ping", "ARP Ping", "Find MAC Address"]
        elif category == "OS Discovery":
            options = ["OS Detection"]
        elif category == "Port Scanning":
            options = ["TCP Connect Scan", "UDP Scan", "TCP Null Scan", "TCP FIN Scan", "Xmas Scan", "TCP ACK Scan", "TCP Window Scan", "TCP Maimon Scan", "IP Protocol Scan"]
        else:
            options = []

        scan_methods.set(options[0])
        menu = scan_methods_menu["menu"]
        menu.delete(0, "end")
        for option in options:
            menu.add_command(label=option, command=lambda value=option: scan_methods.set(value))

    def scan():
        scan_type = scan_methods.get()
        perform_scan(scan_type, host_entry.get(), int(port_entry.get()) if port_entry.get() else None)

    tk.Button(root, text="Scan", command=scan).grid(row=4, column=0, columnspan=2, pady=10)

    update_scan_methods()
    root.mainloop()

if __name__ == "__main__":
    create_gui()
