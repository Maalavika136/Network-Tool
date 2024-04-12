import geocoder
import folium
import socket
import os

def get_loc(url, path, file):
    try:
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
        file_path = os.path.join(path, f"{file}.html")
        myMap.save(file_path)

        return f'Latitude: {myaddress[0]} Longitude: {myaddress[1]}\nLocation saved to {file_path}'
    
    except Exception as e:
        return f'Error: {str(e)}'

if __name__ == "__main__":
    url = input("Enter a URL: ")
    path = input("Enter the path to save the HTML file (leave blank for current directory): ").strip()
    file_name = input("Enter the file name (without extension): ")
    
    print(get_loc(url, path, file_name))
