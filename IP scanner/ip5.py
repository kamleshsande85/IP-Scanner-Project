import pandas as pd
import tkinter as tk
from tkinter import messagebox

import scapy.all as scapy

import threading

import socket
from scapy.all import ARP, Ether, srp

import sqlite3
from datetime import datetime


from urllib.parse import urlparse

from tkinter import ttk

import csv


# Create a lock object to prevent simultaneous writes
lock = threading.Lock()

# Create or connect to the database
conn = sqlite3.connect('ip_scanner.db')
cursor = conn.cursor()


# ========================================ip scanner in a range how many host are connect that network============================================================
def scan_ip(ip):
    try:
        hostname = socket.gethostbyaddr(ip)
        listbox.insert(tk.END, f"{ip}: {hostname[0]}")
        content = f"IP: {ip} - hostname : {hostname[0]}\n"
        mac_address = ""
        # Insert data into 'scan_history'
        # cursor.execute('''
        #     INSERT INTO scan_history (ip_address, hostname)
        #     VALUES (?, ?)
        # ''', (ip, hostname))

        # Write to file in a thread-safe manner
        # with lock:  # Ensures only one thread can write at a time
        #     with open('ip.txt', 'a') as file:
        #         file.write(content)

    except socket.herror:
        listbox2.insert(tk.END, f"IP: {ip} - hostname : unknown")


def ipscanner2(address, start_ip, end_ip):
    listbox.insert(tk.END, "Range ip scanner")
    for last_octet in range(start_ip, end_ip + 1):  # Include end_ip
        ip = f"{address}.{last_octet}"
        thread = threading.Thread(target=scan_ip, args=(ip,))
        thread.start()


def ipscanner():
    entry_text = ipAddres.get()
    entry_text3 = int(startRange.get())
    entry_text2 = int(endrange.get())
    ipscanner2(entry_text, entry_text3, entry_text2)

# ================================Clear Button===============================================================================


def clear():
    listbox.delete(0, tk.END)
    listbox2.delete(0, tk.END)


# ========================================Mac Address============================================================
def macAdddess(ip_address):
    conn = sqlite3.connect('ip_scanner.db')
    cursor = conn.cursor()

    listbox.insert(tk.END, "Mac address detection")
    # Create an ARP request
    arp = ARP(pdst=ip_address)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    packet = ether / arp

    # Send the packet and capture the response
    result = srp(packet, timeout=2, verbose=False)[0]

    # Check if any response was received
    if result:
        for sent, received in result:
            content = f"IP: {received.psrc}, MAC: {received.hwsrc}"
            listbox.insert(tk.END, content)
            cursor.execute("""
            UPDATE scan_history
            SET mac_address = (?)
            WHERE ip_address = (?)
        """, (received.hwsrc, ip_address))
            # Commit the transaction to save the changes
            conn.commit()
            conn.close()

    else:
        messagebox.showinfo(
            "No Response", "No response received from the IP address.")
        cursor.execute("""
            UPDATE scan_history
            SET mac_address = (?)
            WHERE ip_address = (?)
        """, ("No mac address", ip_address))
        conn.commit()
        conn.close()


def HostDetection():
    ip = ipAddres.get()  # Get the IP address from the Entry widget
    macAdddess(ip)  # Call the function to get MAC address

# ========================================which ports id open or not "single port"============================================================


lock = threading.Lock()  # Thread lock to synchronize access to shared resources


def scan_port(ip, port):
    try:
        # Create connection in the thread
        conn = sqlite3.connect("ip_scanner.db")
        cursor = conn.cursor()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection attempt

        result = sock.connect_ex((ip, port))  # Attempt to connect to the port
        scan_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
        protocol = "TCP"  # For now, we're scanning TCP ports

        if result == 0:  # Port is open
            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown Service"

            with lock:  # Ensure thread-safe access to shared resources
                listbox.insert(tk.END, f"Port {
                               port} is open - Service: {service}")
                cursor.execute("""
                    INSERT INTO port_details (scan_id, ip_address, port_number, protocol, service, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (scan_id, ip, port, protocol, service, "open"))

        else:  # Port is closed
            service = "N/A"
            with lock:
                listbox2.insert(tk.END, f"Port {port} is off")
                cursor.execute("""
                    INSERT INTO port_details (scan_id, ip_address, port_number, protocol, service, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (scan_id, ip, port, protocol, service, "closed"))

        conn.commit()  # Save changes to the database
        conn.close()  # Ensure the connection is closed
        sock.close()

    except Exception as e:
        # Print the error for debugging
        print(f"Error scanning port {port}: {e}")

# Function to handle port scanning


def portScanning():
    ip = ipAddres.get()  # Get IP address from user input
    start_port = int(startRange.get())  # Get starting port range
    end_port = int(endrange.get())  # Get ending port range

    # Clear previous results
    listbox.delete(0, tk.END)
    listbox2.delete(0, tk.END)

    # Scan ports in the specified range
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port))
        thread.start()  # Start the scanning in a separate thread for each port

# ======================================tcp==============================================================

# Function to scan a single port


def scan_tcp_port(ip, port):
    # listbox.insert(tk.END, "Port scan")
    conn = sqlite3.connect("ip_scanner.db")  # Create connection in the thread
    cursor = conn.cursor()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            with lock:
                listbox.insert(tk.END, f"Port {port} is open (TCP)")
                cursor.execute(
                    "update scan_history set open_ports = (?),scan_type=(?) where ip_address = (?) ", (port, "TCP", ip))
                conn.commit()
                conn.close()

        sock.close()
    except socket.error:
        pass

# Function to initiate the TCP scan over a range of ports


def tcp_scan():
    ip = ipAddres.get()
    start_port = int(startRange.get())
    end_port = int(endrange.get())

    # Clear previous results
    listbox.delete(0, tk.END)
    listbox.insert(tk.END, "TCP scan")

    # Scan each port in the specified range
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_tcp_port, args=(ip, port))
        thread.start()


# ====================================UDP port================================================================
# Function to scan a single UDP port


def scan_udp_port(ip, port):
    try:
        # Create a new database connection for each thread
        conn = sqlite3.connect("ip_scanner.db")
        cursor = conn.cursor()

        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        # Send a dummy message (empty) to the target port
        sock.sendto(b'', (ip, port))

        # Try to receive a response
        try:
            data, addr = sock.recvfrom(1024)
            with lock:
                listbox.insert(tk.END, f"Port {port} is open (UDP)")
                cursor.execute(
                    "UPDATE scan_history SET open_ports = ?, scan_type = ? WHERE ip_address = ?",
                    (port, "UDP", ip)
                )
                conn.commit()
        except socket.timeout:
            with lock:
                listbox.insert(tk.END, f"Port {
                               port} is open or filtered (UDP)")
        except Exception as e:
            with lock:
                listbox.insert(tk.END, f"Port {port} is closed (UDP)")
    except Exception as e:
        # Handle general exceptions here if needed
        pass
    finally:
        conn.close()  # Ensure connection is closed
        sock.close()


def udp_scan():
    ip = ipAddres.get()
    start_port = int(startRange.get())
    end_port = int(endrange.get())

    # Clear previous results
    listbox.delete(0, tk.END)

    # Scan each port in the specified range
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_udp_port, args=(ip, port))
        thread.start()


# =============================== url se ip============================================================


def urlToIp(url):
    try:
        # URL se domain extract karna
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Domain ka IP address find karna
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "Invalid URL or Hostname"
    except Exception as e:
        return str(e)


def setUrl():
    # Example
    conn = sqlite3.connect("ip_scanner.db")
    cursor = conn.cursor()
    url = urlipAddres.get()
    ip_address = urlToIp(url)
    ipAddres.delete(0, tk.END)
    ipAddres.insert(0, ip_address)
    date = datetime.now()
    cursor.execute(
        "INSERT INTO url_resolution (url, ip_address) VALUES (?, ?)",
        (url, ip_address)
    )
    conn.commit()
    # hostname = socket.gethostbyaddr(ip_address)
    hostname = "Unknown"  # hostname[0]
    cursor.execute(
        "INSERT INTO scan_history (ip_address,hostname,mac_address) VALUES (?, ?,?)", (ip_address, hostname, None))
    conn.commit()
    conn.close()
# print(f"IP address of {url} is: {ip_address}")


# ==========================History management==========================================================================
def scan_history():
    try:
        conn = sqlite3.connect('ip_scanner.db')  # Connect to your database
        cursor = conn.cursor()

        # Fetch all rows from the scan_history table
        cursor.execute("SELECT * FROM scan_history")
        rows = cursor.fetchall()
        conn.close()

        # Create a new top-level window for history
        historyFrame = tk.Toplevel(root)
        historyFrame.title("Scan History")
        historyFrame.geometry("800x400")

        generateBTN = tk.Button(
            historyFrame, text="Generate Report", command=generateScanReport)
        generateBTN.grid(row=0, column=0, padx=20, pady=10)

        # Add Treeview with Scrollbars
        tree_frame = tk.Frame(historyFrame)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        # tree_frame.pack(fill=tk.BOTH, expand=True)

        # Set up scrollbars
        vsb = tk.Scrollbar(tree_frame, orient="vertical")
        hsb = tk.Scrollbar(tree_frame, orient="horizontal")

        # Define Treeview columns
        tree = ttk.Treeview(
            tree_frame,
            columns=("id", "ip_address", "hostname", "mac_address",
                     "open_ports", "scan_type", "timestamp"),
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
        )

        # Configure Scrollbars
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        # Define column headings
        columns = {
            "id": "ID",
            "ip_address": "IP Address",
            "hostname": "Hostname",
            "mac_address": "MAC Address",
            "open_ports": "Open Ports",
            "scan_type": "Scan Type",
            "timestamp": "Timestamp",
        }

        for col, header in columns.items():
            tree.heading(col, text=header, anchor="center")
            # Adjust width as needed
            tree.column(col, anchor="center", width=100)

        # Insert data into the Treeview
        for row in rows:
            tree.insert("", tk.END, values=row)

        # Apply styling to the Treeview for better readability
        style = ttk.Style()
        style.configure("Treeview", rowheight=25)  # Increase row height
        style.configure("Treeview.Heading", font=(
            "Arial", 10, "bold"))  # Bold headings
        tree.tag_configure("odd", background="#E8E8E8")  # Add row striping

        # Alternate row colors
        for index, item in enumerate(tree.get_children()):
            if index % 2 == 0:
                tree.item(item, tags=("odd",))

        # Pack the Treeview widget
        tree.pack(fill=tk.BOTH, expand=True)

    except sqlite3.Error as e:
        messagebox.showerror(
            "Database Error", f"Error accessing the database: {e}")


def ports_details():
    try:
        conn = sqlite3.connect('ip_scanner.db')  # Connect to your database
        cursor = conn.cursor()

        # Fetch all rows from the scan_history table
        cursor.execute("SELECT * FROM port_details")
        rows = cursor.fetchall()
        conn.close()

        # Create a new top-level window for history
        historyFrame = tk.Toplevel(root)
        historyFrame.title("Port details History")
        historyFrame.geometry("800x400")

        # Generate report button
        generateBTN = tk.Button(
            historyFrame, text="Generate Report", command=generatePortReport)
        generateBTN.grid(row=0, column=0, padx=20, pady=10)

        # Add Treeview with Scrollbars
        tree_frame = tk.Frame(historyFrame)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        # tree_frame.pack(fill=tk.BOTH, expand=True)

        # Set up scrollbars
        vsb = tk.Scrollbar(tree_frame, orient="vertical")
        hsb = tk.Scrollbar(tree_frame, orient="horizontal")

        # Define Treeview columns
        tree = ttk.Treeview(
            tree_frame,
            columns=("id", "scan_id", "ip_address", "port_number", "protocol",
                     "service", "status"),
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
        )

        # Configure Scrollbars
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        # Define column headings
        columns = {
            "id": "id", "scan_id": "scan_id", "ip_address": "ip_address", "port_number": "port_number", "protocol": "protocol",
            "service": "service", "status": "status"
        }

        for col, header in columns.items():
            tree.heading(col, text=header, anchor="center")
            # Adjust width as needed
            tree.column(col, anchor="center", width=100)

        # Insert data into the Treeview
        for row in rows:
            tree.insert("", tk.END, values=row)

        # Apply styling to the Treeview for better readability
        style = ttk.Style()
        style.configure("Treeview", rowheight=25)  # Increase row height
        style.configure("Treeview.Heading", font=(
            "Arial", 10, "bold"))  # Bold headings
        tree.tag_configure("odd", background="#E8E8E8")  # Add row striping

        # Alternate row colors
        for index, item in enumerate(tree.get_children()):
            if index % 2 == 0:
                tree.item(item, tags=("odd",))

        # Pack the Treeview widget
        tree.pack(fill=tk.BOTH, expand=True)

    except sqlite3.Error as e:
        messagebox.showerror(
            "Database Error", f"Error accessing the database: {e}")


def url_history():
    try:
        # Connect to the database
        conn = sqlite3.connect('ip_scanner.db')
        cursor = conn.cursor()

        # Fetch all rows from the url_resolution table
        cursor.execute("SELECT * FROM url_resolution")
        rows = cursor.fetchall()
        conn.close()

        # Create a new top-level window for history
        historyFrame = tk.Toplevel(root)
        historyFrame.title("URL History")
        historyFrame.geometry("800x400")

        # Generate report button
        generateBTN = tk.Button(
            historyFrame, text="Generate Report", command=generateUrlReport)
        generateBTN.grid(row=0, column=0, padx=20, pady=10)

        # Frame for Treeview with Scrollbars
        tree_frame = tk.Frame(historyFrame)
        tree_frame.grid(row=1, column=0, sticky="nsew")

        # Configure Scrollbars
        vsb = tk.Scrollbar(tree_frame, orient="vertical")
        hsb = tk.Scrollbar(tree_frame, orient="horizontal")

        # Define Treeview columns and settings
        tree = ttk.Treeview(
            tree_frame,
            columns=("id", "url", "ip_address", "timestamp"),
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
        )
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        # Define column headings and format
        columns = {"id": "ID", "url": "URL",
                   "ip_address": "IP Address", "timestamp": "Timestamp"}
        for col, header in columns.items():
            tree.heading(col, text=header, anchor="center")
            tree.column(col, anchor="center", width=150)

        # Insert data into the Treeview
        for row in rows:
            tree.insert("", tk.END, values=row)

        # Styling for readability
        style = ttk.Style()
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))
        tree.tag_configure("odd", background="#E8E8E8")

        # Alternate row colors
        for index, item in enumerate(tree.get_children()):
            if index % 2 == 0:
                tree.item(item, tags=("odd",))

        # Pack the Treeview
        tree.pack(fill=tk.BOTH, expand=True)

    except sqlite3.Error as e:
        messagebox.showerror(
            "Database Error", f"Error accessing the database: {e}")

# import sqlite3


def generateUrlReport():
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect('ip_scanner.db')
        query = "SELECT * FROM url_resolution"

        # Read data from the database into a pandas DataFrame
        df = pd.read_sql_query(query, conn)

        # Save the DataFrame to a CSV file in a tabular format
        df.to_csv("report.csv", index=False)

        print("Report generated successfully as 'report.csv' in table format.")

    except sqlite3.Error as e:
        print(f"An error occurred with SQLite: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the database connection is closed
        if conn:
            conn.close()


def generateScanReport():
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect('ip_scanner.db')
        query = "SELECT * FROM scan_history"

        # Read data from the database into a pandas DataFrame
        df = pd.read_sql_query(query, conn)

        # Save the DataFrame to a CSV file in a tabular format
        df.to_csv("scan_history_report.csv", index=False)

        print("Report generated successfully as 'report.csv' in table format.")

    except sqlite3.Error as e:
        print(f"An error occurred with SQLite: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the database connection is closed
        if conn:
            conn.close()


def generatePortReport():
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect('ip_scanner.db')
        query = "SELECT * FROM port_details"

        # Read data from the database into a pandas DataFrame
        df = pd.read_sql_query(query, conn)

        # Save the DataFrame to a CSV file in a tabular format
        df.to_csv("port_report.csv", index=False)

        print("Report generated successfully as 'report.csv' in table format.")

    except sqlite3.Error as e:
        print(f"An error occurred with SQLite: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the database connection is closed
        if conn:
            conn.close()


# ====================================================================================================


# Create the main application window
root = tk.Tk()
root.title("IP Scanner")
root.geometry("800x700")
root.minsize(800, 700)
root.maxsize(800, 700)
root.config(bg="#2C302E")

# Create a menu bar
menu_bar = tk.Menu(root)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Url to IP address", command=setUrl)
file_menu.add_command(label="IP Scan (Range))", command=ipscanner)


sub_menu = tk.Menu(file_menu, tearoff=0)
sub_menu.add_command(label="Every Single Port", command=portScanning)
sub_menu.add_command(label="TCP scan", command=tcp_scan)
sub_menu.add_command(label="UDP scan", command=udp_scan)
sub_menu.add_command(label="Mac Address Detection", command=HostDetection)
file_menu.add_cascade(label="Port Analysis", menu=sub_menu)


sub_menu2 = tk.Menu(file_menu, tearoff=0)
sub_menu2.add_command(label="Scan history", command=scan_history)
sub_menu2.add_command(label="Port details", command=ports_details)
sub_menu2.add_command(label="Url to IP history", command=url_history)
# sub_menu2.add_command(label="generate Report", command=generateReport)
file_menu.add_cascade(label="History Management", menu=sub_menu2)
# file_menu.add_command(label="TCP", command=tcp_scan)
# file_menu.add_command(label="UDP", command=udp_scan)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)
menu_bar.add_cascade(label="File", menu=file_menu)
root.config(menu=menu_bar)

# Create the input frame
inputFrame = tk.Frame(root, bg="#2C302E")
inputFrame.grid(row=0, padx=20, pady=10, sticky='ew')

# Labels and entries for IP address input
ipLabel = tk.Label(inputFrame, text="IP Address", bg="#2C302E", fg="white")
ipLabel.grid(row=0, column=2, padx=5, pady=5, sticky='e')
ipAddres = tk.Entry(inputFrame)
ipAddres.grid(row=0, column=3, padx=5, pady=5, sticky='ew')
ipAddres.insert(0, "192.168.1")

urlipLabel = tk.Label(inputFrame, text="URL to IP ", bg="#2C302E", fg="white")
urlipLabel.grid(row=0, column=0, padx=5, pady=5, sticky='e')
urlipAddres = tk.Entry(inputFrame)
urlipAddres.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
# urlipAddres.insert(0, "192.168.1")

startLabel = tk.Label(inputFrame, text="Start Range", bg="#2C302E", fg="white")
startLabel.grid(row=1, column=0, padx=5, pady=5, sticky='e')
startRange = tk.Entry(inputFrame)
startRange.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
startRange.insert(0, "1")

endLabel = tk.Label(inputFrame, text="End Range", bg="#2C302E", fg="white")
endLabel.grid(row=1, column=2, padx=5, pady=5, sticky='e')
endrange = tk.Entry(inputFrame)
endrange.grid(row=1, column=3, padx=5, pady=5, sticky='ew')
endrange.insert(0, "254")

# # Submit button
# subBtn = tk.Button(inputFrame, text="Range Ip scanner", command=ipscanner)
# subBtn.grid(row=2, column=0, pady=10)

buttonClear = tk.Button(inputFrame, text="Clear", width=5,
                        command=clear, bg='black', fg="white")
buttonClear.grid(row=2, column=1)

# Create Listboxes
listbox = tk.Listbox(root, width=30, height=30)
listbox.grid(row=1, column=0, padx=(20, 10), pady=10, sticky='nsew')

listbox2 = tk.Listbox(root, width=30, height=30)
listbox2.grid(row=1, column=1, padx=(10, 20), pady=10, sticky='nsew')

# Configure grid to expand
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(1, weight=1)

root.mainloop()
