import tkinter as tk
import customtkinter as ctk
import socket
import geocoder
import folium
import os
import scapy.all as scapy
import banner_grabber  # Import the banner_grabber function
import packet_sniff  # Import the packet function

# Function to display output text in a new window
def display_output(output_text):
    output_window = ctk.CTkToplevel(app)
    output_window.title("Output")
    output_window.geometry("400x300")
    output_window.resizable(False, False)

    output_label = ctk.CTkLabel(output_window, text=output_text, font=("Arial", 12), wraplength=380)
    output_label.pack(pady=20)

# Banner grabber function
def get_ban():
    try:
        # Prompt user for URL or IP
        get0 = ctk.CTkInputDialog(text="Enter a URL or IP: ", title="Banner Grabber")
        url = socket.gethostbyname(get0.get_input())
        # Prompt user for port
        get1 = ctk.CTkInputDialog(text="Enter a port: ", title="Banner Grabber")
        port = int(get1.get_input())
        # Call banner grabber function
        output = banner_grabber.banner_grabber(url, port)
        display_output(output)
    except Exception as e:
        display_output(f"Error: Please enter a valid URL or IP and port. {e}")

# GeoIP function
def get_loc():
    try:
        # Prompt the user to enter a URL
        get = ctk.CTkInputDialog(text="Enter a URL: ", title="GeoIP")
        url = get.get_input()
        
        # Prompt the user to enter a path for saving the file
        get_path = ctk.CTkInputDialog(text="Enter the path to save the HTML file (leave blank for current directory): ", title="GeoIP")
        path = get_path.get_input().strip()
        
        # Prompt the user to enter a file name
        get_file_name = ctk.CTkInputDialog(text="Enter the file name (without extension): ", title="GeoIP")
        file_name = get_file_name.get_input()
        
        # Perform DNS lookup to get the IP address
        ip = socket.gethostbyname(url)

        # Perform IP geocoding to get the latitude and longitude
        g = geocoder.ip(ip)
        myaddress = g.latlng

        # Create a folium map centered at the obtained coordinates
        myMap = folium.Map(location=myaddress, zoom_start=12)
        
        # Add a marker for the location and save it to an HTML file
        folium.Marker(myaddress, popup="My Location").add_to(myMap)
        folium.CircleMarker(myaddress, radius=50, color='red', fill_color='red').add_to(myMap)

        # Ensure the directory exists before saving the file
        if not os.path.exists(path):
            os.makedirs(path)

        # Save the map to an HTML file
        file_path = os.path.join(path, f"{file_name}.html")
        myMap.save(file_path)

        # Return the output with latitude, longitude, and file path
        output = f'Latitude: {myaddress[0]} Longitude: {myaddress[1]}\nLocation saved to {file_path}'

        # Display the output using the existing display_output function
        display_output(output)
    
    except Exception as e:
        # Display an error message if there's an exception
        display_output(f'Error: {str(e)}')

# Function to scan the network and display connected devices
def scan_network():
    # Prompt the user for the IP range to scan
    get = ctk.CTkInputDialog(text="Enter an IP range (e.g., '192.168.1.0/24'): ", title="Device Scanner")
    ip_range = get.get_input()

    # If the user input is empty, calculate the current IP range
    if not ip_range:
        # Retrieve the current IP address
        hostname = socket.gethostname()
        current_ip = socket.gethostbyname(hostname)
        
        # Determine the subnet mask (e.g., for local networks, it is usually '255.255.255.0')
        subnet_mask = '255.255.255.0'  # Modify this value based on your network configuration
        
        # Calculate the network address and CIDR notation
        ip_parts = [int(part) for part in current_ip.split('.')]
        mask_parts = [int(part) for part in subnet_mask.split('.')]
        
        # Calculate network address
        network_address_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        network_address = '.'.join(map(str, network_address_parts))
        
        # Calculate CIDR notation from subnet mask
        cidr_notation = sum([bin(mask_part).count('1') for mask_part in mask_parts])
        
        # Form the IP range in CIDR notation
        ip_range = f"{network_address}/{cidr_notation}"
    
    # Perform an ARP scan on the specified IP range
    arp_result = scapy.arping(ip_range, verbose=False)[0]

    # Initialize a list to store the output for all devices
    output_list = []

    # Loop through the ARP results and gather information
    for sent, received in arp_result:
        ip = received.psrc
        mac = received.hwsrc
        try:
            # Attempt to resolve the hostname
            hostname, _, _ = socket.gethostbyaddr(ip)
        except socket.herror:
            hostname = "Unknown"

        # Append the IP, MAC, and hostname to the output list
        output_list.append(f"IP: {ip} | MAC: {mac} | Hostname: {hostname}")

    # Display the output in a new window
    display_output("\n".join(output_list))

# Packet sniffer function
def sniff():
    try:
        get = ctk.CTkInputDialog(text="Enter the number of packets to sniff: ", title="Packet Sniffer")
        packet_count = int(get.get_input())
        output = packet_sniff.packet(packet_count)
        display_output(output)
    except Exception as e:
        display_output("Error: Please enter a valid number of packets.")

# Configure the appearance and color theme of the application
ctk.set_appearance_mode("system")
ctk.set_default_color_theme("night_purple.json")

# Initialize the main application window
app = ctk.CTk()
app.geometry("720x720")
app.resizable(False, False)
app.title("Network Tool")

# Add a title label to the application window
title = ctk.CTkLabel(app, text="Network Tool", font=("Century Gothic", 20))
title.place(relx=0.5, rely=0.15, anchor=tk.CENTER)

# Create a frame for buttons
button_frame = ctk.CTkFrame(app)
button_frame.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

# Create buttons for each functionality and place them in the button frame
ban = ctk.CTkButton(button_frame, text="Banner Grabber", command=get_ban)
ban.pack(pady=10)

loc = ctk.CTkButton(button_frame, text="GeoIP", command=get_loc)
loc.pack(pady=10)

scan = ctk.CTkButton(button_frame, text="Device Scanner", command=scan_network)
scan.pack(pady=10)

pack = ctk.CTkButton(button_frame, text="Packet Sniffer", command=sniff)
pack.pack(pady=10)

# Quit button to close the application
quit = ctk.CTkButton(app, text="Quit", command=app.quit)
quit.place(relx=0.5, rely=0.7, anchor=tk.CENTER)

# Start the main application loop
app.mainloop()
