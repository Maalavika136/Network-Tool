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
