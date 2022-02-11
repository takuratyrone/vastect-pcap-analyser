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
fields_left_msg_hdr = {}
msg_hdr_fields = ['Tag', 'MAC Addr', 'Request-Line User', 'Request-Line Host', 'Via', 'From User', 'From Host', 'To User', 'To Host']

ip_map = {}
call_id_map = {}
org_msg_body = {}
anon_msg_body = {}
fields_left_msg_bdy = {}
msg_body_fields = ['Tag', 'SDP Owner Username', 'SDP Owner Address', 'SDP Connection Info']

def sip_pkts_and_integrity(capture, capture2):

    """ Counts and compares the number of SIP packets before and after 
        Anonymization and Collects field values for further analysis to test for integrity """

    print("Counting SIP packets...\n")
    sip_pkts = 0
    sip_pkts2 = 0
    global start 
    start = time.time()
    for packet, packet2 in itertools.zip_longest(capture, capture2):
        try:

            if hasattr(packet, 'sip') :
                """ Counting SIP packets and Collecting field data in Original file """
                sip_pkts += 1
                time_stamp = packet.sniff_timestamp
                tag = packet.sip.tag
                src_addr = packet.ip.src
                dst_addr = packet.ip.dst

                field_names = packet.sip._all_fields
                field_values = packet.sip._all_fields.values()
                call_id = packet['sip'].get_field_value('Call-ID')

                mac = packet.eth.src
                req_user = packet['sip'].get_field_value('r-uri.user')
                req_host = packet['sip'].get_field_value('r-uri.host')
                via = packet['sip'].get_field_value('Via.sent-by.address')
                from_user = packet['sip'].get_field_value('from.user')
                from_host = packet['sip'].get_field_value('from.host')
                to_user = packet['sip'].get_field_value('to.host')
                to_host = packet['sip'].get_field_value('to.host') 

                sdp_user = packet.sip.get_field_value("sdp.owner.username")
                sdp_addr = packet.sip.get_field_value("sdp.owner.address")
                sdp_conn = packet.sip.get_field_value("sdp.connection_info.address")

                org_file_temp = {}
                org_sens_info_temp = {}

                if time_stamp in org_file:
                    if ("@" in call_id) and ("@" in tag):
                        id_pos = call_id.split("@")
                        tag_pos = tag.split("@")
                        org_file[time_stamp].append([tag_pos[0], id_pos[0], src_addr, dst_addr])
                        org_sens_info[time_stamp].append([tag_pos[0], mac, req_user, req_host, via, from_user, from_host, to_user, to_host])
                            
                    elif ("@" in call_id):
                        id_pos = call_id.split("@")
                        org_file[time_stamp].append([tag, id_pos[0], src_addr, dst_addr])
                        org_sens_info[time_stamp].append([tag, mac, req_user, req_host, via, from_user, from_host, to_user, to_host])
                                
                    elif ("@" in tag):
                        tag_pos = tag.split("@")
                        org_file[time_stamp].append([tag_pos[0], call_id, src_addr, dst_addr])
                        org_sens_info[time_stamp].append([tag_pos[0], mac, req_user, req_host, via, from_user, from_host, to_user, to_host])
                                
                    else:
                        org_file[time_stamp].append([tag, call_id, src_addr, dst_addr])
                        org_sens_info[time_stamp].append([tag, mac, req_user, req_host, via, from_user, from_host, to_user, to_host])
                                
                else:
                    if ("@" in call_id) and ("@" in tag):
                        id_pos = call_id.split("@")
                        tag_pos = tag.split("@")
                        org_file.update({
                                    time_stamp: [[tag_pos[0], id_pos[0], src_addr, dst_addr]]
                        })
                        org_sens_info.update({
                                             time_stamp: [[tag_pos[0], mac, req_user, req_host, via, from_user, from_host, to_user, to_host]]
                        })
                                
                    elif ("@" in call_id):
                        id_pos = call_id.split("@")
                        org_file.update({
                                    time_stamp: [[tag, id_pos[0], src_addr, dst_addr]]
                        })
                        org_sens_info.update({
                                             time_stamp: [[tag, mac, req_user, req_host, via, from_user, from_host, to_user, to_host]]
                        })
                                
                    elif ("@" in tag):
                        tag_pos = tag.split("@")
                        org_file.update({
                                    time_stamp: [[tag_pos[0], call_id, src_addr, dst_addr]]
                        })
                        org_sens_info.update({
                                             time_stamp: [[tag_pos[0], mac, req_user, req_host, via, from_user, from_host, to_user, to_host]]
                        })
                                
                    else:
                        org_file.update({
                                        time_stamp: [[tag, call_id, src_addr, dst_addr]]
                        })
                        org_sens_info.update({
                                             time_stamp: [[tag, mac, req_user, req_host, via, from_user, from_host, to_user, to_host]]
                        })                  
                              
                if packet['sip'].get_field_value('msg_body'):
                    if time_stamp in org_msg_body:
                        if "@" in tag:
                            tag_pos = tag.split("@")
                            org_msg_body[time_stamp].append([tag_pos[0], sdp_user, sdp_addr, sdp_conn])
                        else:
                            org_msg_body[time_stamp].append([tag, sdp_user, sdp_addr, sdp_conn])
                    else:
                        if "@" in tag:
                            tag_pos = tag.split("@")
                            org_msg_body.update({
                                                time_stamp: [[tag_pos[0], sdp_user, sdp_addr, sdp_conn]]
                                })
                        else:
                            org_msg_body.update({
                                                time_stamp: [[tag, sdp_user, sdp_addr, sdp_conn]]
                                })                            

            if hasattr(packet2, 'sip') :
                """ Counting SIP packets and Collecting field data in Anonymized file """
                sip_pkts2 += 1
                time_stamp2 = packet2.sniff_timestamp
                tag2 = packet2.sip.tag
                src_addr2 = packet2.ip.src
                dst_addr2 = packet2.ip.dst

                field_names2 = packet2.sip._all_fields
                field_values2 = packet2.sip._all_fields.values()
                call_id2 = packet2['sip'].get_field_value('Call-ID')

                mac2 = packet2.eth.src
                req_user2 = packet2['sip'].get_field_value('r-uri.user')
                req_host2 = packet2['sip'].get_field_value('r-uri.host')
                via2 = packet2['sip'].get_field_value('Via.sent-by.address')
                from_user2 = packet2['sip'].get_field_value('from.user')
                from_host2 = packet2['sip'].get_field_value('from.host')
                to_user2 = packet2['sip'].get_field_value('to.host')
                to_host2 = packet2['sip'].get_field_value('to.host')
                #print(from_user2)

                sdp_user2 = packet2.sip.get_field_value("sdp.owner.username")
                sdp_addr2 = packet2.sip.get_field_value("sdp.owner.address")
                sdp_conn2 = packet2.sip.get_field_value("sdp.connection_info.address")
                #print(sdp_user2)

                anon_file_temp = {}
                anon_info_temp = {}
                #for field_name2, field_value2 in zip(field_names2, field_values2):
                #    if field_name2 == "sip.Call-ID":
                if time_stamp2 in anon_file:
                    if ("@" in call_id2) and ("@" in tag2):
                        id_pos2 = call_id2.split("@")
                        tag_pos2 = tag2.split("@")
                        anon_file[time_stamp2].append([tag_pos2[0], id_pos2[0], src_addr2, dst_addr2])
                        anon_info[time_stamp2].append([tag_pos2[0], mac2, req_user2, req_host2, via2, from_user2, from_host2, to_user2, to_host2])

                                
                    elif "@" in call_id2:
                        id_pos2 = call_id2.split("@")
                        anon_file[time_stamp2].append([tag2, id_pos2[0], src_addr2, dst_addr2])
                        anon_info[time_stamp2].append([tag2, mac2, req_user2, req_host2, via2, from_user2, from_host2, to_user2, to_host2])

                                
                    elif "@" in tag2:
                        tag_pos2 = tag2.split("@")
                        anon_file[time_stamp2].append([tag_pos2[0], call_id2, src_addr2, dst_addr2])
                        anon_info[time_stamp2].append([tag_pos2[0], mac2, req_user2, req_host2, via2, from_user2, from_host2, to_user2, to_host2])

                                
                    else:
                        anon_file[time_stamp2].append([tag2, call_id2, src_addr2, dst_addr2])
                        anon_info[time_stamp2].append([tag2, mac2, req_user2, req_host2, via2, from_user2, from_host2, to_user2, to_host2])

                                
                else:
                    if ("@" in call_id2) and ("@" in tag2):
                        id_pos2 = call_id2.split("@")
                        tag_pos2 = tag2.split("@")
                        anon_file.update({
                                        time_stamp2: [[tag_pos2[0], id_pos2[0], src_addr2, dst_addr2]]
                                        })
                        anon_info.update({
                                             time_stamp2: [[tag_pos2[0], mac2, req_user2, req_host2, via2, from_user2, from_host2, to_user2, to_host2]]
                        })
                            
                    elif ("@" in call_id2):
                        id_pos2 = call_id2.split("@")
                        anon_file.update({
                                        time_stamp2: [[tag2, id_pos2[0], src_addr2, dst_addr2]]
                                        })
                        anon_info.update({
                                             time_stamp2: [[tag2, mac2, req_user2, req_host2, via2, from_user2, from_host2, to_user2, to_host2]]
                        })
                                
                    elif ("@" in tag2):
                        tag_pos2 = tag2.split("@")
                        anon_file.update({
                                        time_stamp2: [[tag_pos2[0], call_id2, src_addr2, dst_addr2]]
                                        })
                        anon_info.update({
                                             time_stamp2: [[tag_pos2[0], mac2, req_user2, req_host2, via2, from_user2, from_host2, to_user2, to_host2]]
                        })
                                
                    else:
                        anon_file.update({
                                    time_stamp2: [[tag2, call_id2, src_addr2, dst_addr2]]
                                    })
                        anon_info.update({
                                             time_stamp2: [[tag2, mac2, req_user2, req_host2, via2, from_user2, from_host2, to_user2, to_host2]]
                        })

                if packet2['sip'].get_field_value('msg_body'):
                    if time_stamp2 in anon_msg_body:
                        if "@" in tag2:
                            tag_pos2 = tag2.split("@")
                            anon_msg_body[time_stamp2].append([tag_pos2[0], sdp_user2, sdp_addr2, sdp_conn2])
                        else:
                            anon_msg_body[time_stamp2].append([tag2, sdp_user2, sdp_addr2, sdp_conn2])
                    else:
                        if "@" in tag2:
                            tag_pos2 = tag2.split("@")
                            #print(sdp_user2)
                            anon_msg_body.update({
                                                time_stamp2: [[tag_pos2[0], sdp_user2, sdp_addr2, sdp_conn2]]
                                })
                        else:
                            #print(sdp_user2)
                            anon_msg_body.update({
                                                time_stamp2: [[tag2, sdp_user2, sdp_addr2, sdp_conn2]]
                                })
                                      
        except OSError:
            pass
        except asyncio.TimeoutError:
            pass
    #print(anon_file)
    print("SIP packets before Anonymization: {} \nSIP packets after Anonymization: {}\n".format(sip_pkts, sip_pkts2))
    
    # If no SIP packet loss, analysis continues
    if sip_pkts == sip_pkts2:
        check_fields()
        ip_mapping()
    else:
        print("There are {} missing SIP packets.".format(sip_pkts - sip_pkts2))
    
def check_fields():

    """ Checks if sensitive information is anonymized """

    print("Checking if sensitive information is anonymized...\n")
    mac_anonymized = True
    msg_hdr_anon = True
    msg_body_anon = True
    p = 0
    for key in org_sens_info:
        if len(org_sens_info[key]) > 1:
            for i in range(len(org_sens_info[key])):
                if (key in anon_info) and (anon_info[key][i][0] == org_sens_info[key][i][0]):
                    if (org_sens_info[key][i][1] == anon_info[key][i][1]):
                        mac_anonymized = False
                    for j in range(2, len(org_sens_info[key][i])):
                        if (org_sens_info[key][i][j] == anon_info[key][i][j]) and (org_sens_info[key][i][j] != None):
                            print("not Anonymized: {}".format(org_sens_info[key][i][j]))
                            msg_hdr_anon = False
                            fields_left_msg_hdr.update({j: ''})

        if (key in anon_info) and (anon_info[key][0][0] == org_sens_info[key][0][0]):
            if (org_sens_info[key][0][1] == anon_info[key][0][1]):
                mac_anonymized = False
            for k in range(2, len(org_sens_info[key][0])):
                if (org_sens_info[key][0][k] == anon_info[key][0][k]) and (org_sens_info[key][0][k] != None):
                    #print("not Anonymized: {} {}".format(org_sens_info[key][0][k], k))
                    msg_hdr_anon = False
                    fields_left_msg_hdr.update({k: org_sens_info[key][0][k]})

    for key in org_msg_body: 
        if len(org_msg_body[key]) > 1:
            for l in range(len(org_msg_body)):
                if (key in org_msg_body) and (org_msg_body[key][l][0] == anon_msg_body[key][l][0]):
                    for m in range(1, len(org_msg_body[key][l])):
                        if (org_msg_body[key][l][m] == anon_msg_body[key][l][m]) and (org_msg_body[key][l][m] != None):
                            msg_body_anon = False
                            fields_left_msg_bdy.update({m: org_msg_body[key][l][m]})

        if (key in org_msg_body) and (org_msg_body[key][0][0] == anon_msg_body[key][0][0]):
            for n in range(1, len(org_msg_body[key][0])):
                if (org_msg_body[key][0][n] == anon_msg_body[key][0][n]) and (org_msg_body[key][0][n] != None):
                    #print(n)
                    msg_body_anon = False
                    fields_left_msg_bdy.update({n: org_msg_body[key][0][n]})

    if mac_anonymized:
        print("MAC Addresses Anonymized.\n")
    else:
        print("MAC Addresses NOT Anonymized.\n")

    if msg_hdr_anon:
        print("Sensitive Information under Message Header Anonymized.\n")
    else:
        print("Sensitive Information under Message Header NOT Anonymized: ")
        for field in fields_left_msg_hdr:
            print("{}: {}".format(msg_hdr_fields[field], fields_left_msg_hdr[field]))
        print('\n')

    if msg_body_anon:
        print("Sensitive Information under Message Body Anonymized.\n")
    else:
        print("Sensitive Information under Message Body NOT Anonymized:")
        for field in fields_left_msg_bdy:
            print("{}: {}".format(msg_body_fields[field], fields_left_msg_bdy[field]))
        print("\n")

def ip_mapping():

    """ Maps unique IP adresses and Call-ID before and after Anonymization """
    print("Call-ID and IP mapping...\n")
    #print(org_file)
    ip_credible = True
    call_id_credible = True
    for key in org_file:
        ip_map_temp = {}
        call_id_map_temp = {}
        if len(org_file[key]) > 1:
            for i in range(len(org_file[key])):
                if (key in anon_file) and (anon_file[key][i][0] == org_file[key][i][0]):
                    if ((org_file[key][i][2] in ip_map) and (org_file[key][i][3] in ip_map)):
                        if (ip_map[org_file[key][i][2]] != anon_file[key][i][2]) or (ip_map[org_file[key][i][3]] != anon_file[key][i][3]):
                            ip_credible = False

                    elif ((org_file[key][i][2] in ip_map) and (org_file[key][i][3] not in ip_map)):
                        if (ip_map[org_file[key][i][2]] != anon_file[key][i][2]):
                            ip_credible = False
                        ip_map.update({org_file[key][i][3]: anon_file[key][i][3]})

                    elif ((org_file[key][i][2] not in ip_map) and (org_file[key][i][3] in ip_map)):
                        if (ip_map[org_file[key][i][3]] != anon_file[key][i][3]):
                            ip_credible = False
                        ip_map.update({org_file[key][i][2]: anon_file[key][i][2]})

                    else:
                        ip_map.update({org_file[key][i][2]: anon_file[key][i][2], org_file[key][i][3]: anon_file[key][i][3]})
                    #ip_map.update(ip_map_temp)

                    # CALL-ID MAPPING
                    if (org_file[key][i][1] in call_id_map):
                        if (call_id_map[org_file[key][i][1]] != anon_file[key][i][1]):
                            call_id_credible = False
                    else:
                        call_id_map_temp = {org_file[key][i][1]: anon_file[key][i][1]}
                        ip_map.update(call_id_map_temp)

        elif len(org_file[key]) == 1:
            if (key in anon_file) and (anon_file[key][0][0] == org_file[key][0][0]):
                # Checks if both src and dst IP are in ip_map and verifies if mapping is consistent
                if ((org_file[key][0][2] in ip_map) and (org_file[key][0][3] in ip_map)):
                    if (ip_map[org_file[key][0][2]] != anon_file[key][0][2]) or (ip_map[org_file[key][0][3]] != anon_file[key][0][3]):
                        ip_credible = False

                # Checks if src IP is in ip_map, verifies consistency and adds dst IP in ip_map_temp
                elif ((org_file[key][0][2] in ip_map) and (org_file[key][0][3] not in ip_map)):
                    if (ip_map[org_file[key][0][2]] != anon_file[key][0][2]):
                        ip_credible = False
                    ip_map.update({org_file[key][0][3]: anon_file[key][0][3]})

                # Checks if dst IP is in ip_map, verifies consistency and adds src IP in ip_map_temp
                elif ((org_file[key][0][2] not in ip_map) and (org_file[key][0][3] in ip_map)):
                    if (ip_map[org_file[key][0][3]] != anon_file[key][0][3]):
                        ip_credible = False
                    ip_map.update({org_file[key][0][2]: anon_file[key][0][2]})

                else:
                    ip_map.update({org_file[key][0][2]: anon_file[key][0][2], org_file[key][0][3]: anon_file[key][0][3]})

                # CALL-ID MAPPING
                if (org_file[key][0][1] in call_id_map):
                    if (call_id_map[org_file[key][0][1]] != anon_file[key][0][1]):
                        call_id_credible = False
                else:
                    call_id_map_temp = {org_file[key][0][1]: anon_file[key][0][1]}
                    call_id_map.update(call_id_map_temp)
        else:
            print("Timestamp: {} is empty!\n".format(key))

    if ip_credible:
        print("There are {} unique original IP addresses.".format(len(ip_map)))
        print("There are {} unique generated IP addresses.\n".format(len(set(ip_map.values()))))
        print("|{:>20} | {:>20} |".format("Original IP", "Anonymized IP"))
        print("|{:>20} | {:>20} |".format("_"*20, "_"*20))
        for ip in ip_map:        
            print("|{:>20} | {:>20} |".format(ip, ip_map[ip]))
    else:
        print("IP Anonymization error!")

    if call_id_credible:
        print("\nThere are {} unique Call-IDs.".format(len(call_id_map)))
        print("There are {} unique generated Call-IDs.\n".format(len(set(call_id_map.values()))))
        print("|{:>20} | {:>20} |".format("Original Call-ID", "Anonymized Call-ID"))
        print("|{:>20} | {:>20} |".format("_"*20, "_"*20))
        for ids in call_id_map:        
            print("|{:>20} | {:>20} |".format(ids, call_id_map[ids]))
    else:
        print("Call-ID Anonymization error!")

    
if __name__ == '__main__':
    pcap_file = sys.argv[1]
    pcap_file2 = sys.argv[2]
    cap = pyshark.FileCapture(pcap_file)
    cap2 = pyshark.FileCapture(pcap_file2)
    s = time.time()
    sip_pkts_and_integrity(cap, cap2)
    e = time.time()
    print("Runtime: {} seconds.".format(e-s))
    cap.close()
    cap2.close()
   
