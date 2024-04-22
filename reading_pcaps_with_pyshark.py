import pyshark
import matplotlib.pyplot as plt

def get_mac_time_and_channel_utilization_lists(pcap_path, max_packets_to_plot = float("inf")):
    mac_time_list = []
    channel_utilization_list = []
    cap = pyshark.FileCapture(pcap_path)
    # iterator = 
    try:
        for i, packet in enumerate(cap):
            try:
                # print(i)
                mac_time = int(packet.radiotap.mactime)
                channel_utilization = int(packet["wlan.mgt"].wlan_qbss_cu)/262*100
                mac_time_list.append(mac_time)
                channel_utilization_list.append(channel_utilization)
                # print(channel_utilization)
            except:
                do_nothing = 1
            if i > max_packets_to_plot:
                break
    except:
        do_nothing = 1
    return mac_time_list, channel_utilization_list
            

if __name__ == "__main__":
    mac_time_list, channel_utilization_list = get_mac_time_and_channel_utilization_lists('sudhayakumar-mbp_ch157_2024-04-21_20.54.14.345.pcap', 1000)
    mac_time_list_with_start_time_0 = [(x-mac_time_list[0])/1000 for x in mac_time_list]
    plt.plot(mac_time_list_with_start_time_0, channel_utilization_list)
    plt.xlabel("mac_time (ms)")
    plt.ylabel("channel utilization % from ap beacon")
    plt.savefig("channel_utilization_over_time.png")
    plt.show()
    # print(channel_utilization_list)