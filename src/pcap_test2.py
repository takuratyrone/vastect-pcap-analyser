import pyshark
import asyncio
import itertools
from tabulate import tabulate
import sys
import time


org_file = {}
anon_file = {}

org_sens_info = {}
anon_info = {}

ip_map = {}

def sip_pkts_and_integrity(capture, capture2):

    """ Counts and compares the number of SIP packets before and after 
        Anonymization and tests for integrity using Call-ID """

    print("Counting SIP packets...\n")
    sip_pkts = 0
    sip_pkts2 = 0
    mac_anonymized = True
    sensitive_info_anon = True
    global start 
    start = time.time()
    for packet, packet2 in itertools.zip_longest(capture, capture2):
        try:
            #print("Timestamp: {}   {}  Tag: ".format(packet.sniff_timestamp, packet2.sniff_timestamp))
            if hasattr(packet, 'sip') :
                """ Counting SIP packets and Collecting Unique Call-IDs in Original pcap file """
                sip_pkts += 1
                time_stamp = packet.sniff_timestamp
                tag = packet.sip.tag
                src_addr = packet.ip.src
                dst_addr = packet.ip.dst

                #print("Timestamp: {}   {}  Tag: {}   {}".format(packet.sniff_timestamp, packet2.sniff_timestamp, packet.sip.tag, packet2.sip.tag))
                field_names = packet.sip._all_fields
                field_values = packet.sip._all_fields.values()

                mac = packet.eth.src
                via = packet.sip.Via
                from_ = packet.sip.From 
                to = packet.sip.To 

                org_file_temp = {}
                org_sens_info_temp = {}
                for field_name, field_value in zip(field_names, field_values):
                    if field_name == "sip.Call-ID":
                        if time_stamp in org_file:
                            org_file[time_stamp].append([tag, field_value, src_addr, dst_addr])
                            org_sens_info[time_stamp].append([tag, mac, via, from_, to])
                        else:
                            org_file_temp = {
                                            time_stamp: [[tag, field_value, src_addr, dst_addr]]
                            }
                            org_sens_info_temp = {
                                                 time_stamp: [[tag, mac, via, from_, to]]
                            }
                            org_file.update(org_file_temp)
                            org_sens_info.update(org_sens_info_temp)

            if hasattr(packet2, 'sip') :
                """ Counting SIP packets and Collecting Unique Call-IDs in Original pcap file """
                sip_pkts2 += 1
                time_stamp2 = packet2.sniff_timestamp
                tag2 = packet2.sip.tag
                src_addr2 = packet2.ip.src
                dst_addr2 = packet2.ip.dst

                #print("Timestamp: {}   {}  Tag: {}   {}".format(packet.sniff_timestamp, packet2.sniff_timestamp, packet.sip.tag, packet2.sip.tag))
                field_names2 = packet2.sip._all_fields
                field_values2 = packet2.sip._all_fields.values()

                mac2 = packet2.eth.src
                via2 = packet2.sip.Via
                from_2 = packet2.sip.From 
                to2 = packet2.sip.To

                anon_file_temp = {}
                anon_info_temp = {}
                for field_name2, field_value2 in zip(field_names2, field_values2):
                    if field_name2 == "sip.Call-ID":
                        if time_stamp2 in anon_file:
                            anon_file[time_stamp2].append([tag2, field_value2, src_addr2, dst_addr2])
                            anon_info[time_stamp2].append([tag2, mac2, via2, from_2, to2])
                        else:
                            anon_file_temp = {
                                            time_stamp2: [[tag2, field_value2, src_addr2, dst_addr2]]
                                            }
                            anon_info_temp = {
                                                 time_stamp2: [[tag2, mac2, via2, from_2, to2]]
                            }
                            anon_file.update(anon_file_temp) 
                            anon_info.update(anon_info_temp)            
        except OSError:
            pass
        except asyncio.TimeoutError:
            pass
    #print(anon_file)
    print("SIP packets before Anonymization: {} \nSIP packets after Anonymization: {}\n".format(sip_pkts, sip_pkts2))
    if sip_pkts == sip_pkts2:
        check_fields()
        ip_mapping()
    else:
        print("There are {} missing SIP packets.".format(sip_pkts - sip_pkts2))
    
def check_fields():

    """ Checks if sensitive information is anonymized """

    print("Checking if sensitive information is anonymized...\n")
    mac_anonymized = True
    sensitive_info_anon = True
    p = 0
    for key in org_sens_info:
        if len(org_sens_info[key]) > 1:
            for i in range(len(org_sens_info[key])):
                if (key in anon_info) and (anon_info[key][i][0] == org_sens_info[key][i][0]):
                    if (org_sens_info[key][i][1] == anon_info[key][i][1]):
                        mac_anonymized = False
                    for j in range(2, 5):
                        if (org_sens_info[key][i][j] == anon_info[key][i][j]):
                            sensitive_info_anon = False
        
        if (key in anon_file) and (anon_file[key][0][0] == org_file[key][0][0]):
            if (org_sens_info[key][0][1] == anon_info[key][0][1]):
                mac_anonymized = False
            for k in range(2, 5):
                if (org_sens_info[key][0][k] == anon_info[key][0][k]):
                    sensitive_info_anon = False

    if mac_anonymized:
        print("MAC Addresses Anonymized.")
    else:
        print("MAC Addresses NOT Anonymized.")

    if sensitive_info_anon:
        print("Sensitive Information under Message Header Anonymized.\n")
    else:
        print("Sensitive Information under Message Header NOT Anonymized.\n")

def ip_mapping():

    """ Maps unique IP adresses before and after Anonymization """
    print("IP mapping...\n")
    #print(org_file)
    ip_credible = True
    for key in org_file:
        ip_map_temp = {}
        if len(org_file[key]) > 1:
            for i in range(len(org_file[key])):
                if (key in anon_file) and (anon_file[key][i][0] == org_file[key][i][0]):
                    if ((org_file[key][i][2] in ip_map) or (org_file[key][i][3] in ip_map)):
                        if (ip_map[org_file[key][i][2]] != anon_file[key][i][2]) or (ip_map[org_file[key][i][3]] != anon_file[key][i][3]):
                            ip_credible = False
                    else:
                        ip_map_temp = {org_file[key][i][2]: anon_file[key][i][2], org_file[key][i][3]: anon_file[key][i][3]}
                        ip_map.update(ip_map_temp)
        #print("{}   {}".format(org_file[key][0][0], anon_file[key][0][0]))
        if (key in anon_file) and (anon_file[key][0][0] == org_file[key][0][0]):
            if ((org_file[key][0][2] in ip_map) or (org_file[key][0][3] in ip_map)):
                if (ip_map[org_file[key][0][2]] != anon_file[key][0][2]) or (ip_map[org_file[key][0][3]] != anon_file[key][0][3]):
                    ip_credible = False
            else:
                ip_map_temp = {org_file[key][0][2]: anon_file[key][0][2], org_file[key][0][3]: anon_file[key][0][3]}
                ip_map.update(ip_map_temp)
            #print("{}   {}".format(org_file[key],anon_file[key]))
    if ip_credible:
        print("There are {} unique IP addresses.\n".format(len(ip_map)))
        print("|{:>20} | {:>20} |".format("Original IP", "Anon IP"))
        print("|{:>20} | {:>20} |".format("_"*20, "_"*20))
        for ip in ip_map:        
            print("|{:>20} | {:>20} |".format(ip, ip_map[ip]))
    else:
        print("IP Anonymization error!")
    
if __name__ == '__main__':
    pcap_file = sys.argv[1]
    pcap_file2 = sys.argv[2]
    cap = pyshark.FileCapture(pcap_file)
    cap2 = pyshark.FileCapture(pcap_file2)
    sip_pkts_and_integrity(cap, cap2)
    #ip_mapping(cap, cap2)
    cap.close()
    cap2.close()
   
