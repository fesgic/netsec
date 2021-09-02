import sys
import threading
import tkinter as tk
from tkinter import CENTER
from tkinter import ttk

from PIL import Image, ImageTk
from datetime import datetime
from threading import Thread
#scapy and network processing modules
from scapy.layers.inet import IP
from scapy.layers.http import *
from scapy.layers.l2 import ARP
from scapy.sessions import TCPSession
from scapy.sendrecv import sniff
from scapy.all import rdpcap

# self defined modules imports
from scapy.utils import wrpcap

from interfaces.interfaces import addrs

#connect to database
import mysql.connector
from mysql.connector import errors, Error

# define root UI
root = tk.Tk()
root.title("NetSec")
load = Image.open('./logos/logo.png')
render = ImageTk.PhotoImage(load)
root.iconphoto(False, render)
root.resizable(width=True, height=True)
root.geometry('{}x{}'.format(1366, 748))

# functions performing network analysis and processing
def select_interf(interf):
    if interf == 'Select Interface':
        # create a top level window
        popup = tk.Toplevel(root)
        popup.geometry("550x250")
        # create entry widget into top level
        label = tk.Label(popup, text="Please Select a Valid Interface")
        label.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
    elif capture_text.get() == "Stop Capture":
            capture_text.set("Capture Traffic")

def capture_traffic(interf):
    if interf != "Select Interface":
        sniffThread = threading.Thread(target=traffic_scapy, args=(interf,))
        if capture_text.get() == "Capture Traffic":
            sniffThread.start()
        elif capture_text.get() == "Stop Capture":
            sniffThread.stop()
            capture_text.set("Capture Traffic")

global file
file = "fes.pcap"
def traffic_scapy(interf):
    capture_text.set("Stop Capture")
    import logging
    import os
    logging.getLogger("scapy").setLevel(logging.CRITICAL)

    def packet_capture(pkt):
        try:
            now = datetime.now()
            formatted_date = now.strftime("%Y-%m-%d %H-%M-%S")
            connection = mysql.connector.connect(host='localhost',
                                                 database='netsec',
                                                 user='xxxxxx',
                                                 password='xxxxxxxx')
            if connection.is_connected():
                db_Info = connection.get_server_info()
                print("Connected to mysql server version", db_Info)
            cursor =  connection.cursor()
            if TCP in pkt:
                insert_query = f"""
                           insert into traffic (src, dst, src_ip, dst_ip, protocol, time_stamp)
                                       values ("{pkt.src}","{pkt.dst}","{pkt[IP].src}", "{pkt[IP].dst}", "TCP", "{formatted_date}");
                            """
                cursor.execute(insert_query)
            connection.commit()
        #wrpcap(file, pkt)
        except Error as e:
           print("Error while connecting to mysql", e)
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()
                print("Mysql connection closed")

    sniff(iface=interf, prn=packet_capture, store=0)
    #import capture
    #import capture.capture as packets_cap
    #packets_cap.interface = interf
    #packets_cap.file = "festus.pcap"
    #packets_cap.packet_capture()
    #packets_cap.permissions()
    #print("Please Select an Interface")


# define main frames/containers
topmost_frame = tk.Frame(root, bg='purple', width=1366, height=30, pady=3)
top_frame = tk.Frame(root, bg='blue', width=1366, height=90, pady=3)
left_frame = tk.Frame(root, bg='white', width=150, height=555, pady=3)
canvas_frame = tk.Frame(root, bg='green', width=1216, height=555, pady=3)
report_frame = tk.Frame(root, bg='orange', width=1366, height=45, pady=3)

# define layout of the frames
root.grid_rowconfigure(1, weight=1)
root.grid_columnconfigure(0, weight=1)

topmost_frame.grid(row=0, sticky='ew')
top_frame.grid(row=1, sticky='news')
left_frame.grid(row=3, sticky='nsw')
canvas_frame.grid(row=3, sticky='nse')
report_frame.grid(row=5, sticky='ew')

# create widgets for topmost frame
interfaces_label = tk.Label(topmost_frame, text='Select interface', width=15, height=2)
interface_chosen = tk.StringVar()
interface = ttk.Combobox(topmost_frame, textvariable=interface_chosen)
interface_chosen.set('Select Interface')
# chose from available interfaces
interface['values'] = tuple(addrs)
capture_text = tk.StringVar()
capture_button = tk.Button(topmost_frame, textvariable=capture_text, command=lambda:[capture_traffic(interface_chosen.get()), select_interf(interface_chosen.get())])
capture_text.set("Capture Traffic")

# layout for topmost frame widgets
interfaces_label.grid(column=1, row=0)
interface.grid(column=3, row=0)
capture_button.place(relx=0.5, rely=0.5, anchor=CENTER)

# create frames to hold contents of top frame organised
top_frame.grid_rowconfigure(0, weight=1)
top_frame.grid_columnconfigure(1, weight=1)

top_frame_left = tk.Frame(top_frame, bg="red", padx=3, pady=3)
top_frame_center = tk.Frame(top_frame, bg="cyan", padx=3, pady=3)
top_frame_right = tk.Frame(top_frame, bg="yellow", padx=3, pady=3)

# layout of frames in top frame
top_frame_left.grid(row=0, column=0, sticky='nswe')
top_frame_center.grid(row=0, column=1, sticky='nswe')
top_frame_right.grid(row=0, column=2, sticky='nswe')

# create widgets for top frame
time_label = tk.Label(top_frame_left, text='Time:', width=15, height=2)
from_time_label = tk.Label(top_frame_center, text='From:', width=15, height=2)
from_time_entry = tk.Entry(top_frame_center, background='pink', width=15)
to_time_label = tk.Label(top_frame_center, text='To', width=15, height=2)
to_time_entry = tk.Entry(top_frame_center, background="pink", width=15)
analyze_text = tk.StringVar()
analyze_button = tk.Button(top_frame_right, textvariable=analyze_text)
analyze_text.set("Analyze")

# layout for top_frame widgets
time_label.grid(columnspan=2, row=0, pady=15)
from_time_label.grid(columnspan=2, row=0, column=0, padx=300)
from_time_entry.grid(columnspan=2, row=1, column=0)
to_time_label.grid(columnspan=2, row=0, column=2)
to_time_entry.grid(columnspan=2, row=1, column=2)
analyze_button.grid(columnspan=2, row=0, column=12, padx=30, pady=15)

# create widgets for left frame
livecap_text = tk.StringVar()
livecap_button = tk.Button(left_frame, textvariable=livecap_text, padx=0, pady=0)
livecap_text.set("Live Capture")
trafficview_text = tk.StringVar()
trafficview_button = tk.Button(left_frame, textvariable=trafficview_text, padx=0, pady=0)
trafficview_text.set("Traffic Overview")
protocolview_text = tk.StringVar()
protocolview_button = tk.Button(left_frame, textvariable=protocolview_text, padx=0, pady=0)
protocolview_text.set("Protocol Overview")

# layout for left frame widgets
livecap_button.grid(row=0, column=1, columnspan=2)
trafficview_button.grid(row=1, column=1, columnspan=2)
protocolview_button.grid(row=3, column=1, columnspan=2)

# create widgets for right frame
reports_canvas = tk.Canvas(canvas_frame, bg="red")

# layout for right frame widgets
# reports_canvas.grid()

# create widgets for report_frame
download_report_text = tk.StringVar()
download_report = tk.Button(report_frame, textvariable=download_report_text)
download_report_text.set("Download Report")

# layout for report_frame widgets
download_report.place(relx=0.5, rely=0.5, anchor=CENTER)

root.mainloop()
