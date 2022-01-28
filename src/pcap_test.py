import pyshark
import asyncio
import itertools
from tabulate import tabulate
import sys
from bisect import bisect_left ,bisect
import time

call_ID = []
call_ID2 = []

ip_data = [[]]
ip_data2 = [[]]

src_ip = [] 
dst_ip = []

src_ip2 = []
dst_ip2 = []

def sip_pkts_and_integrity(capture, capture2):

    """ Counts the number of SIP packets before and after 
        Anonymization and tests for integrity """

    print("Counting SIP packets...\n")
    sip_pkts = 0
    sip_pkts2 = 0
    start = time.time()
    for packet, packet2 in itertools.zip_longest(capture, capture2):
        try:
            if hasattr(packet, 'sip') :
                sip_pkts += 1
                field_names = packet.sip._all_fields
                field_values = packet.sip._all_fields.values()

                for field_name, field_value in zip(field_names, field_values):
                    if field_name == "sip.Call-ID":
                        call_ID.sort()
                        if bisect_left(call_ID, field_value)!=bisect(call_ID, field_value):
                            call_ID.append(field_value)
                
            if hasattr(packet2, 'sip'):
                sip_pkts2 += 1
                field_names2 = packet2.sip._all_fields
                field_values2 = packet2.sip._all_fields.values()

                for field_name2, field_value2 in zip(field_names2, field_values2):
                    if field_name2 == "sip.Call-ID":
                        call_ID2.sort()
                        if bisect_left(call_ID2, field_value2)!=bisect(call_ID2, field_value2):
                            call_ID2.append(field_value2)
        except OSError:
            pass
        except asyncio.TimeoutError:
            pass
    #capture.close()
    #print("Call-ID: {}\nCall-ID2: {}".format(call_ID, call_ID2))
    end = time.time()
    print("Runtime: {} secs.".format(end-start))
    print("SIP packets before Anonymization: {} \nSIP packets after Anonymization: {}\n".format(sip_pkts, sip_pkts2))
    print("Checking for integrity...\n")

    if (sip_pkts == sip_pkts2) and (len(call_ID) == len(call_ID2)):
        print("Call-ID integrity maintained.\nNo SIP packet loss.\n")
    elif sip_pkts != sip_pkts2:
        missing_pkts = sip_pkts - cap_pkts2
        print("Sanitised file has {} missing packets.\n".format(missing_pkts))
        cap.close()
        cap2.close()
        sys.exit(1)
    else:
        print("SIP packets compromised after Anonymization.\n")
    #print(tabulate(call_ID, headers=["Call-ID"], tablefmt='orgtbl'))


def ip_mapping(capture, capture2):

    """ Maps the IP adresses before and after Anonymization"""
    
    print("IP mapping...\n")
    for (packet, packet2) in itertools.zip_longest(capture, capture2):
        try:
            if hasattr(packet, 'sip'):
                ip_temp = []
                
                src_addr = packet.ip.src
                dst_addr = packet.ip.dst
                
                if (src_addr not in src_ip) and (dst_addr not in dst_ip):
                    src_ip.append(src_addr)
                    dst_ip.append(dst_ip)
                    ip_temp.append(src_addr)
                    ip_temp.append(dst_addr)
                
                ip_data.append(ip_temp)

            if hasattr(packet2, 'sip'):
                ip_temp2 = []

                src_addr2 = packet2.ip.src
                dst_addr2 = packet2.ip.dst

                if (src_addr2 not in src_ip2) and (dst_addr2 not in dst_ip2):
                    src_ip2.append(src_addr2)
                    dst_ip2.append(dst_ip2)
                    ip_temp2.append(src_addr2)
                    ip_temp2.append(dst_addr2)

                ip_data2.append(ip_temp2)
        except OSError:
            pass
        except asyncio.TimeoutError:
            pass

    #capture.close()
    print("|{:>20} | {:>15} | {:>20} | {:>15} |".format("Original Src IP", "Anon Src IP", "Original Dst IP", "Anon Dst IP"))
    print("|{:>20} | {:>15} | {:>20} | {:>15} |".format("_"*20, "_"*15, "_"*20, "_"*15))
    for ips, ips2 in itertools.zip_longest(ip_data, ip_data2):
        #print("{} {}".format(ips, ips2))
        if (len(ips) == 0) and (len(ips2) == 0):
            continue
        elif (len(ips) == 0) and (len(ips2) != 0):
            print("|{:>20} | {:>15} | {:>20} | {:>15} |".format("None", ips2[0], "None", ips2[1]))
        elif (len(ips) > 0) and (ips2 is None):
            print("|{:>20} | {:>15} | {:>20} | {:>15} |".format(ips[0], "None", ips[1], "None"))
        else:
            print("|{:>20} | {:>15} | {:>20} | {:>15} |".format(ips[0], ips2[0], ips[1], ips2[1]))

if __name__ == '__main__':
    pcap_file = sys.argv[1]
    pcap_file2 = sys.argv[2]
    cap = pyshark.FileCapture(pcap_file)
    cap2 = pyshark.FileCapture(pcap_file2)
    sip_pkts_and_integrity(cap, cap2)
    ip_mapping(cap, cap2)
    cap.close()
    cap2.close()
   
