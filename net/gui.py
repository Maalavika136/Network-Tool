import socket
import whois
import requests
import tkinter as tk
from tkinter import messagebox
import pcapy

def ip_domain_analysis():
    window = tk.Toplevel(root)
    window.title("IP and Domain Analysis")
    window.geometry("400x200")

    def reverse_dns_lookup():
        ip = ip_entry.get()
        try:
            hostname = socket.gethostbyaddr(ip)
            messagebox.showinfo("Reverse DNS Lookup Result", f"The hostname for IP {ip} is {hostname[0]}")
        except socket.herror:
            messagebox.showerror("Error", f"Failed to resolve hostname for IP {ip}")

    def whois_lookup():
        domain = domain_entry.get()
        try:
            whois_info = whois.whois(domain)
            messagebox.showinfo("WHOIS Lookup Result", whois_info.text)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to perform WHOIS lookup for domain {domain}")

    def geolocation():
        ip = ip_entry.get()
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}')
            geolocation_info = response.json()
            messagebox.showinfo("Geolocation Result", f"Country: {geolocation_info['country']}, City: {geolocation_info['city']}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve geolocation for IP {ip}")

    ip_label = tk.Label(window, text="Enter IP address:")
    ip_label.grid(row=0, column=0, padx=10, pady=10)
    ip_entry = tk.Entry(window)
    ip_entry.grid(row=0, column=1, padx=10, pady=10)

    domain_label = tk.Label(window, text="Enter domain:")
    domain_label.grid(row=1, column=0, padx=10, pady=10)
    domain_entry = tk.Entry(window)
    domain_entry.grid(row=1, column=1, padx=10, pady=10)

    dns_button = tk.Button(window, text="Reverse DNS Lookup", command=reverse_dns_lookup)
    dns_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    whois_button = tk.Button(window, text="WHOIS Lookup", command=whois_lookup)
    whois_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    geo_button = tk.Button(window, text="Geolocation", command=geolocation)
    geo_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

def packet_sniffing():
    window = tk.Toplevel(root)
    window.title("Packet Sniffing")
    window.geometry("500x300")

    text_box = tk.Text(window)
    text_box.pack(expand=True, fill='both')

    def packet_handler(header, data):
        text_box.insert(tk.END, f"{data}\n")

    # Adjust the device name and buffer size as needed
    cap = pcapy.open_live("wlan0", 65536, 1, 0)

    print("Sniffing packets... (Press Ctrl+C to stop)")
    while True:
        try:
            header, data = cap.next()
            packet_handler(header, data)
        except KeyboardInterrupt:
            break

def banner_grabbing():
    pass

def arp_detection():
    pass

def wifi_scanning():
    pass

def main():
    global root
    root = tk.Tk()
    root.title("Network Security Toolkit")

    title_label = tk.Label(root, text="Network Security Toolkit", font=("Helvetica", 16))
    title_label.pack(pady=10)

    ip_domain_analysis_button = tk.Button(root, text="IP and Domain Analysis", command=ip_domain_analysis, width=20)
    ip_domain_analysis_button.pack(pady=5)

    packet_sniffing_button = tk.Button(root, text="Packet Sniffing", command=packet_sniffing, width=20)
    packet_sniffing_button.pack(pady=5)

    banner_grabbing_button = tk.Button(root, text="Banner Grabbing", command=banner_grabbing, width=20)
    banner_grabbing_button.pack(pady=5)

    arp_detection_button = tk.Button(root, text="ARP Cache Poisoning Detection", command=arp_detection, width=20)
    arp_detection_button.pack(pady=5)

    wifi_scanning_button = tk.Button(root, text="Wi-Fi Scanning", command=wifi_scanning, width=20)
    wifi_scanning_button.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()
