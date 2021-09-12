import sys
import threading

import matplotlib.pyplot
from matplotlib.backends._backend_tk import NavigationToolbar2Tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from scapy.layers.dns import DNS

lock = threading.Lock()
import tkinter as tk
from time import strftime
from tkinter import CENTER, END, LEFT, DISABLED, ACTIVE, NORMAL, RIGHT, Y, X, BOTH
from tkinter import ttk

import canvas as canvas
from PIL import Image, ImageTk
from datetime import datetime
from threading import Thread
# scapy and network processing modules
from scapy.layers.inet import IP
from scapy.layers.http import *
from scapy.layers.tls import *
from scapy.layers.l2 import ARP, Ether
from scapy.layers.tls.record import TLS
from scapy.sessions import TCPSession
from scapy.sendrecv import sniff
from scapy.all import rdpcap

# self defined modules imports
from scapy.utils import wrpcap

from interfaces.interfaces import addrs
import matplotlib.pyplot as plt

# connect to database
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
                                                 user='festus',
                                                 password='fg68211h')
            if connection.is_connected():
                db_Info = connection.get_server_info()
                print("Connected to mysql server version", db_Info)
            cursor = connection.cursor()
            if HTTP in pkt:
                reports_canvas.create_text(100, 10, fill="darkblue", font="Times 20 italic bold",
                                           text="Click the bubbles that are multiples of two.\n")
                insert_query = f"""
                           insert into traffic (src, dst, src_ip, dst_ip, protocol, time_stamp)
                                       values ("{pkt.src}","{pkt.dst}","{pkt[IP].src}", "{pkt[IP].dst}", "HTTP", "{formatted_date}");
                            """
                cursor.execute(insert_query)
                connection.commit()
                if HTTPRequest in pkt:
                    insert_query = f"""
                           insert into http_request (src, dst, src_ip, dst_ip, protocol, http_method, request_path, time_stamp)
                                       values ("{pkt.src}","{pkt.dst}","{pkt[IP].src}", "{pkt[IP].dst}", "HTTP", 
                                       "{pkt[HTTPRequest].Method.decode()}", "{pkt[HTTPRequest].Path.decode()}", "{formatted_date}");
                            """
                    cursor.execute(insert_query)
                    connection.commit()
                if HTTPResponse in pkt:
                    insert_query = f"""
                           insert into http_response (src, dst, src_ip, dst_ip, protocol, http_statuscode, status_code_reason, time_stamp)
                                       values ("{pkt.src}","{pkt.dst}","{pkt[IP].src}", "{pkt[IP].dst}", "HTTP", 
                                       "{pkt[HTTPResponse].Status_Code.decode()}" , "{pkt[HTTPResponse].Reason_Phrase.decode()}", "{formatted_date}");
                            """
                    cursor.execute(insert_query)
                    connection.commit()
            elif ARP in pkt and pkt[ARP].op == 1:
                insert_query = f"""
                           insert into traffic (src, dst, src_ip, dst_ip, protocol, time_stamp)
                                       values ("{pkt[Ether].src}","{pkt[Ether].dst}","{pkt[ARP].psrc}", "{pkt[ARP].pdst}", "ARP", "{formatted_date}");
                            """
                cursor.execute(insert_query)
                connection.commit()
            elif ARP in pkt and pkt[ARP].op == 2:
                insert_query = f"""
                           insert into traffic (src, dst, src_ip, dst_ip, protocol, time_stamp)
                                       values ("{pkt[Ether].hwsrc}","{pkt[Ether].hwdst}","{pkt[ARP].psrc}", "{pkt[ARP].pdst}", "ARP", "{formatted_date}");
                            """
                cursor.execute(insert_query)
                connection.commit()
            elif TLS in pkt:
                reports_canvas.create_text(100, 10, fill="darkblue", font="Times 20 italic bold",
                                           text="Click the bubbles that are multiples of two.\n")
                insert_query = f"""
                           insert into traffic (src, dst, src_ip, dst_ip, protocol, time_stamp)
                                       values ("{pkt.src}","{pkt.dst}","{pkt[IP].src}", "{pkt[IP].dst}", "HTTPS", "{formatted_date}");
                            """
                cursor.execute(insert_query)
                connection.commit()



        # wrpcap(file, pkt)
        except Error as e:
            print("Error while connecting to mysql", e)
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()
                print("Mysql connection closed")

    sniff(iface=interf, prn=packet_capture, store=0)
    # import capture
    # import capture.capture as packets_cap
    # packets_cap.interface = interf
    # packets_cap.file = "festus.pcap"
    # packets_cap.packet_capture()
    # packets_cap.permissions()
    # print("Please Select an Interface")


# display live traffic to interface
def live_traffic():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            database="netsec",
            user="festus",
            password="fg68211h"
        )
        if connection.is_connected():
            db_Info = connection.get_server_info()
            print("Connected to mysql Server", db_Info)
        cursor = connection.cursor()
        traffic_query = 'select * from traffic;'
        cursor.execute(traffic_query)
        # get all records
        records = cursor.fetchall()
        print("Total number of rows is ", cursor.rowcount)
        print(records)
        print("Printing Each Row")
        print("Src\tDst\tSrc_IP\tDst_IP\tProtocol\tTimestamp\n")
        # for row in records:
        #    time = row[5].strftime("%H:%M: hrs")
        #    print(f'{row[0]}\t{row[1]}\t{row[2]}\t{row[3]}\t{row[4]}\t{time}')
        tree = ttk.Treeview(reports_canvas, column=("c1", "c2", "c3", "c4", "c5", "c6"), show='headings', height=30)

        tree.column("#1", anchor=tk.CENTER)
        tree.heading("#1", text="SRC")
        tree.column("#2", anchor=tk.CENTER)
        tree.heading("#2", text="DST")
        tree.column("#3", anchor=tk.CENTER)
        tree.heading("#3", text="SRC_IP")
        tree.column("#4", anchor=tk.CENTER)
        tree.heading("#4", text="DST_IP")
        tree.column("#5", anchor=tk.CENTER)
        tree.heading("#5", text="PROTOCOL")
        tree.column("#6", anchor=tk.CENTER)
        tree.heading("#6", text="TIMESTAMP")
        tree.pack(side='left')
        scroll = ttk.Scrollbar(reports_canvas, orient="vertical", command=tree.yview)
        scroll.pack(side='right', fill='y')

        tree.configure(yscrollcommand=scroll.set)
        for row in records:
            tree.insert("", tk.END, values=row)


        #lst = records

        #for i in range(len(records)):
        #    for j in range(len(records[0])):
          #      live_tr = tk.Entry(reports_canvas, width=1, fg='blue',
        #                           font=('Arial', 16))
         #       live_tr.grid(row=i, column=j)
          #      live_tr.insert(END, lst[i][j])


    except Error as e:
        print("Error Connecting to Mysql", e)
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("My sql connection closed")


# traffic_overview
# graph of traffic capture over time(count)
def traffic_overview():
    print("a")


# protocol_overview
# graph of protocol type over time
def protocol_overview():
    #protocolview_button["state"] = ACTIVE
    #livecap_button["state"] = NORMAL
    #trafficview_button["state"] = NORMAL
    #reports_canvas.delete("all")
    def plotting_traf():
        while protocolview_button["state"] == ACTIVE:
            try:
                lock.acquire()
                connection = mysql.connector.connect(
                    host="localhost",
                    database="netsec",
                    user="festus",
                    password="fg68211h"
                )
                if connection.is_connected():
                    db_Info = connection.get_server_info()
                    print("Connected to mysql Server", db_Info)
                cursor = connection.cursor()
                traffic_query = 'select time_stamp,protocol,count(protocol) from traffic group by time_stamp;'
                cursor.execute(traffic_query)
                # get all records
                records = cursor.fetchall()
                print("Total number of rows is ", cursor.rowcount)
                print(f"aaa{records[0]}, {records[1]},{records[2]}")
                timex = []
                httpy = []
                arpy = []
                httpsy = []
                dnsy = []
                # fig = plt.figure()
                # ax1 = fig.add_subplot(1, 1, 1)
                for i in records:
                    a = i[0].strftime("%H:%M:")
                    if i[1] == "HTTP":
                        httpy.append(i[2])
                        arpy.append(0)
                        httpsy.append(0)
                        dnsy.append(0)
                    elif i[1] == "ARP":
                        arpy.append(i[2])
                        httpy.append(0)
                        httpsy.append(0)
                        dnsy.append(0)
                    elif i[1] == "HTTPS":
                        httpsy.append(i[2])
                        arpy.append(0)
                        httpy.append(0)
                        dnsy.append(0)
                    elif i[1] == "DNS":
                        dnsy.append(i[2])
                        httpy.append(0)
                        httpsy.append(0)
                        arpy.append(0)
                    timex.append(a)
                fig = Figure(figsize=(12, 6),
                             dpi=100)
                plt1 = fig.add_subplot(1,1,1)

                plt1.cla()
                print(f"{httpy}\n{arpy}\n{dnsy}\n{timex}")
                plt1.set_title("Protocol Graph")
                plt1.set_xlabel("Time")
                plt1.set_ylabel("Protocol")
                plt1.plot(timex, arpy, label="ARP", color="blue")
                plt1.plot(timex, httpy, label="HTTP", linestyle=":", color="red")
                plt1.plot(timex, httpsy, label="HTTPS", linestyle="-.", color="green")
                plt1.plot(timex, dnsy, label="DNS", color="yellow")
                # creating the Tkinter canvas
                # containing the Matplotlib figure
                canvas = FigureCanvasTkAgg(fig,
                                           master=reports_canvas)
                canvas.draw()
                # placing the canvas on the Tkinter window
                canvas.get_tk_widget().pack()
                # creating the Matplotlib toolbar
                #toolbar = NavigationToolbar2Tk(canvas,
                 #                              reports_canvas)
                # placing the toolbar on the Tkinter window
                #toolbar.update()
                #canvas.get_tk_widget().pack()

                lock.release()
            except Error as e:
                print("Error Connecting to Mysql", e)
            finally:
                if connection.is_connected():
                    cursor.close()
                    connection.close()
                    print("My sql connection closed")

    graph_plot = threading.Thread(target=plotting_traf)
    graph_plot.start()


def http_request_report():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            database="netsec",
            user="festus",
            password="fg68211h"
        )
        if connection.is_connected():
            db_Info = connection.get_server_info()
            print("Connected to mysql Server", db_Info)
        cursor = connection.cursor()
        traffic_query = 'select src_ip,dst_ip,protocol,request_path,http_method,time_stamp from http_request;'
        cursor.execute(traffic_query)
        # get all records
        records = cursor.fetchall()
        print("Total number of rows is ", cursor.rowcount)

        tree = ttk.Treeview(reports_canvas, column=("c1", "c2", "c3", "c4", "c5", "c6"), show='headings', height=30)

        tree.column("#1", anchor=tk.CENTER)
        tree.heading("#1", text="SRC_IP")
        tree.column("#2", anchor=tk.CENTER)
        tree.heading("#2", text="DST_IP")
        tree.column("#3", anchor=tk.CENTER)
        tree.heading("#3", text="PROTOCOL")
        tree.column("#4", anchor=tk.CENTER)
        tree.heading("#4", text="HTTP_METHOD")
        tree.column("#5", anchor=tk.CENTER)
        tree.heading("#5", text="REQUEST_PATH")
        tree.column("#6", anchor=tk.CENTER, stretch="True")
        tree.heading("#6", text="TIMESTAMP")
        tree.pack(side=LEFT)

        scroll = ttk.Scrollbar(reports_canvas, orient="vertical", command=tree.yview)
        scroll.pack(side=RIGHT, fill='y')
        tree.configure(yscrollcommand=scroll.set, style="Treeview")
        for row in records:
            tree.insert("", tk.END, values=row)


    except Error as e:
        print("Error Connecting to Mysql", e)
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("My sql connection closed")

def http_response_report():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            database="netsec",
            user="festus",
            password="fg68211h"
        )
        if connection.is_connected():
            db_Info = connection.get_server_info()
            print("Connected to mysql Server", db_Info)
        cursor = connection.cursor()
        traffic_query = 'select src_ip,dst_ip,protocol,http_statuscode,status_code_reason,time_stamp from http_response;'
        cursor.execute(traffic_query)
        # get all records
        records = cursor.fetchall()
        print("Total number of rows is ", cursor.rowcount)

        tree = ttk.Treeview(reports_canvas, column=("c1", "c2", "c3", "c4", "c5", "c6"), show='headings', height=30)

        tree.column("#1", anchor=tk.CENTER)
        tree.heading("#1", text="SRC_IP")
        tree.column("#2", anchor=tk.CENTER)
        tree.heading("#2", text="DST_IP")
        tree.column("#3", anchor=tk.CENTER)
        tree.heading("#3", text="PROTOCOL")
        tree.column("#4", anchor=tk.CENTER)
        tree.heading("#4", text="STATUS_CODE")
        tree.column("#5", anchor=tk.CENTER)
        tree.heading("#5", text="CODE_REASON")
        tree.column("#6", anchor=tk.CENTER, stretch="True")
        tree.heading("#6", text="TIMESTAMP")
        tree.pack(side=LEFT, fill=BOTH)

        scroll = ttk.Scrollbar(reports_canvas, orient="vertical", command=tree.yview)
        scroll.pack(side=RIGHT, fill='y')
        tree.configure(yscrollcommand=scroll.set, style="Treeview")
        for row in records:
            tree.insert("", tk.END, values=row)


    except Error as e:
        print("Error Connecting to Mysql", e)
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("My sql connection closed")


# define main frames/containers
topmost_frame = tk.Frame(root, bg='purple', width=1366, height=30, pady=0.5)
# top_frame = tk.Frame(root, bg='blue', width=1366, height=90, pady=3)
left_frame = tk.Frame(root, bg='blue', width=150, height=600, pady=0, padx=0.5)
canvas_frame = tk.Frame(root, width=1216, height=600, bg='yellow', pady=0.5)
report_frame = tk.Frame(root, bg='orange', width=1366, height=45, pady=0.5)
# define layout of the frames
root.grid_rowconfigure(1, weight=1)
root.grid_columnconfigure(0, weight=1)

topmost_frame.grid(row=0, sticky='ew')
# top_frame.grid(row=1, sticky='new')
left_frame.grid(row=2, sticky='nsw')
canvas_frame.grid(row=2, sticky='ne')
report_frame.grid(row=5, sticky='ew')

# create widgets for topmost frame
interfaces_label = tk.Label(topmost_frame, text='Select interface', width=15, height=2)
interface_chosen = tk.StringVar()
interface = ttk.Combobox(topmost_frame, textvariable=interface_chosen)
interface_chosen.set('Select Interface')
# chose from available interfaces
interface['values'] = tuple(addrs)
capture_text = tk.StringVar()
capture_button = tk.Button(topmost_frame, textvariable=capture_text,
                           command=lambda: [capture_traffic(interface_chosen.get()),
                                            select_interf(interface_chosen.get())])
capture_text.set("Capture Traffic")

# layout for topmost frame widgets
interfaces_label.grid(column=1, row=0)
interface.grid(column=3, row=0)
capture_button.place(relx=0.5, rely=0.5, anchor=CENTER)

# create frames to hold contents of top frame organised
# top_frame.grid_rowconfigure(0, weight=1)
# top_frame.grid_columnconfigure(1, weight=1)

# top_frame_left = tk.Frame(top_frame, bg="red", padx=3, pady=3)
# top_frame_center = tk.Frame(top_frame, bg="cyan", padx=3, pady=3)
# top_frame_right = tk.Frame(top_frame, bg="yellow", padx=3, pady=3)

# layout of frames in top frame
# top_frame_left.grid(row=0, column=0, sticky='nwe')
# top_frame_center.grid(row=0, column=1, sticky='nwe')
# top_frame_right.grid(row=0, column=2, sticky='nwe')

# create widgets for top frame
# time_label = tk.Label(top_frame_left, text='Time:', width=15, height=2)
# from_time_label = tk.Label(top_frame_center, text='From:', width=15, height=2)
# from_time_entry = tk.Entry(top_frame_center, background='pink', width=15)
# to_time_label = tk.Label(top_frame_center, text='To', width=15, height=2)
# to_time_entry = tk.Entry(top_frame_center, background="pink", width=15)
# analyze_text = tk.StringVar()
# analyze_button = tk.Button(top_frame_right, textvariable=analyze_text)
# analyze_text.set("Analyze")

# layout for top_frame widgets
# time_label.grid(columnspan=2, row=0, pady=15)
# from_time_label.grid(columnspan=2, row=0, column=0, padx=300)
# from_time_entry.grid(columnspan=2, row=1, column=0)
# to_time_label.grid(columnspan=2, row=0, column=2)
# to_time_entry.grid(columnspan=2, row=1, column=2)
# analyze_button.grid(columnspan=2, row=0, column=12, padx=30, pady=15)

# create widgets for left frame
livecap_text = tk.StringVar()
livecap_button = tk.Button(left_frame, textvariable=livecap_text, padx=0, pady=0, command=lambda: [live_traffic()])
livecap_text.set("Live Capture")
trafficview_text = tk.StringVar()
trafficview_button = tk.Button(left_frame, textvariable=trafficview_text, padx=0, pady=0,
                               command=lambda: [traffic_overview()])
trafficview_text.set("Traffic Overview")

http_label = tk.Label(left_frame, text='HTTP Protocol', width=15, height=2, bg="blue", fg="white")
http_request_text = tk.StringVar()
http_request_button = tk.Button(left_frame, textvariable=http_request_text, padx=0, pady=0, command=lambda:[http_request_report()])
http_request_text.set("HTTP Requests")
http_response_text = tk.StringVar()
http_response_button = tk.Button(left_frame, textvariable=http_response_text, padx=0, pady=0,
                                 command=lambda: [http_response_report()])
http_response_text.set("HTTP Responses")
protocolview_text = tk.StringVar()
protocol_graphs = tk.Label(left_frame, text="Protocol Graphs", bg="blue", fg="white")
protocolview_button = tk.Button(left_frame, textvariable=protocolview_text, padx=0, pady=0,
                                command=lambda: [protocol_overview()])
protocolview_text.set("Protocol Overview")

# layout for left frame widgets
livecap_button.grid(row=0, column=1, columnspan=2)
trafficview_button.grid(row=1, column=1, columnspan=2)
http_label.grid(row=2, column=1, columnspan=2)
http_request_button.grid(row=3, column=1, columnspan=2)
http_response_button.grid(row=4, column=1, columnspan=2)
protocol_graphs.grid(row=5, column=1, rowspan=2)
protocolview_button.grid(row=6, column=1, columnspan=2)

# create widgets for right frame
#v = tk.Scrollbar(canvas_frame, orient='vertical')
#v.pack(side=RIGHT, fill=Y)
# v.grid(column=6,rowspan=5, row=0)
reports_canvas = tk.Canvas(canvas_frame, bg="green", width=1216, height=600)
#v.config(command=reports_canvas.yview)
reports_canvas.pack(side=LEFT, fill=BOTH)


# reports_canvas.grid(columnspan=5, rowspan=5, column=1, row=1)


# e = tk.Entry(reports_canvas, width=10, fg='blue')
# e.grid(columnspan=6, column=5, row=5)
# scrollbar = ttk.Scrollbar(reports_canvas, orient="vertical", command=reports_canvas.yview)

# layout for right frame widgets
# reports_canvas.grid()

def download_reports():
    answer = tk.simpledialog.askstring("Input", "Enter name of report",
                                    parent=root)
    try:
        def fetch_table_data(table_name):
            connection = mysql.connector.connect(host='localhost',
                                             database='netsec',
                                             user='festus',
                                             password='fg68211h')
            if connection.is_connected():
                db_Info = connection.get_server_info()
                print("Connected to mysql server version", db_Info)

            cursor = connection.cursor()
            cursor.execute(f"select * from {table_name};")

            header = [row[0] for row in cursor.description]

            rows = cursor.fetchall()

            connection.close()
            cursor.close()
            return header, rows

        def export_table(table_name):
            header, rows = fetch_table_data(table_name)

            #create csv file
            f = open(f"{answer}_{table_name}.csv", "w")

            #write header
            f.write(','.join(header) + '\n')

            #insert data
            for row in rows:
                f.write(','.join(str(r) for r in row) +'\n')

            f.close()


        export_table("traffic")
        export_table("http_request")
        export_table("http_response")

    except Error as e:
        print(e)



# create widgets for report_frame
download_report_text = tk.StringVar()
download_report = tk.Button(report_frame, textvariable=download_report_text, command=lambda: [download_reports()])
download_report_text.set("Download Report")

# layout for report_frame widgets
download_report.place(relx=0.5, rely=0.5, anchor=CENTER)

root.mainloop()
