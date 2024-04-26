import pyshark
import matplotlib.pyplot as plt
import time
import argparse
import os
import pathlib

def func_duration_decorator(func): 
    argnames = func.__code__.co_varnames[:func.__code__.co_argcount] 
    fname = func.__name__ 
    def inner_func(*args, **kwargs): 
        start_time = time.time()
        return_value = func(*args, **kwargs)
        end_time = time.time()-start_time
        argnames_params = ', '.join( '% s = % r' % entry for entry in zip(argnames, args[:len(argnames)]))
        args = list(args[len(argnames):])
        kwargs = kwargs
        time_duration_string = f"time duration of {fname}({argnames_params}, args = {str(list(args[len(argnames):]))}, kwargs = {kwargs}:\n{round(end_time,2)}" 
        print(time_duration_string)
        return return_value
    return inner_func

# @func_duration_decorator
def get_mac_time_and_channel_utilization_lists(pcap_path, max_packets_to_plot = float("inf"), use_timestamp_ts_instead_of_mactime = False):
    mac_time_list = []
    channel_utilization_list = []
    # with pyshark.FileCapture(pcap_path,  display_filter="wlan.fc.type_subtype == 0x0008") as cap:
    cap = pyshark.FileCapture(pcap_path)
    try:
        with pyshark.FileCapture(pcap_path,  display_filter="wlan.fc.type_subtype == 0x0008") as cap:
            for i, packet in enumerate(cap):
                try:
                    if not use_timestamp_ts_instead_of_mactime:
                        mac_time = int(packet.radiotap.timestamp_ts)
                    else:
                        mac_time = int(packet.radiotap.mactime)
                    channel_utilization = int(packet["wlan.mgt"].wlan_qbss_cu)/262*100
                    mac_time_list.append(mac_time)
                    channel_utilization_list.append(channel_utilization)
                except:
                    do_nothing = 1
                if i > max_packets_to_plot:
                    break
    except Exception as e:
        do_nothing = 1
    # try:
    #     cap.close()
    # except Exception as e:
    #     do_nothing = 1
    return mac_time_list, channel_utilization_list

def plot_x_y_coordinates(x,y, title, x_label = "", y_label = "", bringup_plot_figure = False, folder_to_save_path = ""):
    plt.plot(x, y)
    if x_label:
        plt.xlabel(x_label)
    if y_label:
        plt.ylabel(y_label)
    if title:
        plt.title(title)
    image_file_name = title.replace(" ", "_")
    if not folder_to_save_path:
        plt.savefig(f"{image_file_name}.png")
    else:
        plt.savefig(os.path.join(folder_to_save_path, f"{image_file_name}.png"))
    if bringup_plot_figure:
        plt.show()    
    plt.close()
# def plot_

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='plotting_channel_utilization_from_pcaps',
                    description='plots channel utilization field over time from a pcap',
                    )
    parser.add_argument('path_to_pcap_file_or_folder_of_pcaps', help="path to pcap file or folder of pcaps")  
    parser.add_argument('--max_num_beacon_packets_to_parse', help="max_num_beacon_packets_to_parse", default=-1, type=int)  
    parser.add_argument('--use_timestamp_ts_instead_of_mactime', help="bool to indicate use_timestamp_ts_instead_of_mactime from radiotap", action='store_true')  
    parser.add_argument('--bringup_plot_figure', help="decide to plt.show and bringup a plot figure", action='store_true')  
    args = parser.parse_args()
    max_packets_to_plot = args.max_num_beacon_packets_to_parse
    bringup_plot_figure = args.bringup_plot_figure
    if max_packets_to_plot == -1:
        max_packets_to_plot = float("inf")
    use_timestamp_ts_instead_of_mactime = args.use_timestamp_ts_instead_of_mactime
    path_to_pcap_file_or_folder_of_pcaps = args.path_to_pcap_file_or_folder_of_pcaps
    if os.path.isfile(path_to_pcap_file_or_folder_of_pcaps):
        file_name = pathlib.Path(os.path.basename(path_to_pcap_file_or_folder_of_pcaps)).stem
        dirname = os.path.dirname(path_to_pcap_file_or_folder_of_pcaps)
        start_time = time.time()
        mac_time_list, channel_utilization_list = get_mac_time_and_channel_utilization_lists(path_to_pcap_file_or_folder_of_pcaps, max_packets_to_plot=max_packets_to_plot, use_timestamp_ts_instead_of_mactime=use_timestamp_ts_instead_of_mactime)
        mac_time_list = [(x-mac_time_list[0])/1000 for x in mac_time_list]
        end_time = time.time()-start_time
        print(f"time duration of {path_to_pcap_file_or_folder_of_pcaps}:\n{round(end_time,2)} seconds" )
        plot_x_y_coordinates(mac_time_list,channel_utilization_list, file_name, x_label = "mac_time (ms)", y_label = "channel utilization % from ap beacon", bringup_plot_figure = bringup_plot_figure, folder_to_save_path=dirname)
    elif os.path.isdir(path_to_pcap_file_or_folder_of_pcaps):
        for root, d_names, f_names in os.walk(path_to_pcap_file_or_folder_of_pcaps):
            for f_name in f_names:
                if f_name.endswith(".pcap") or f_name.endswith(".pcapng"):
                    pcap_path = os.path.join(root, f_name)
                    file_name = pathlib.Path(os.path.basename(pcap_path)).stem
                    dirname = os.path.dirname(pcap_path)
                    start_time = time.time()
                    mac_time_list, channel_utilization_list = get_mac_time_and_channel_utilization_lists(pcap_path, max_packets_to_plot=max_packets_to_plot, use_timestamp_ts_instead_of_mactime=use_timestamp_ts_instead_of_mactime)
                    mac_time_list = [x-mac_time_list[0] for x in mac_time_list]
                    end_time = time.time()-start_time
                    print(f"time duration of {pcap_path}:\n{round(end_time,2)} seconds" )
                    plot_x_y_coordinates(mac_time_list,channel_utilization_list, file_name, x_label = "mac_time (ms)", y_label = "channel utilization % from ap beacon", bringup_plot_figure = bringup_plot_figure, folder_to_save_path=dirname)