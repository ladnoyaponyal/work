import pyshark
import csv

filename = str('SAT1.pcap')
cap = pyshark.FileCapture(filename, keep_packets=True)
k = 0
with open('try_convert.csv', 'w', newline='') as w_file:
    file_writer = csv.writer(w_file, delimiter=",", lineterminator='\r')
    file_writer.writerow(['number', 'time', 'time_delta', 'time_delta_disp', \
                          'time_relative', 'time_epoch', 'length', 'ip_src', 'ip_dst', \
                          'df', 'mf', 'rb', 'src_port', 'dst_port', 'ack', 'syn', 'fin', 'clas'])
    asd = 0

    for i in cap:
        cl = 0
        a = i.frame_info.time
        b = i.frame_info.time_delta
        c = i.frame_info.time_delta_displayed
        d = i.frame_info.time_relative
        e = i.frame_info.time_epoch
        f = i.frame_info.len
        if 'IP' in i:
            g = i.ip.src
            h = i.ip.dst
            z = i.ip.flags_df
            j = i.ip.flags_mf
            k = i.ip.flags_rb
        elif 'IPv6' in i:
            g = i.ipv6.src
            h = i.ipv6.dst
            z = -1
            j = -1
            k = -1
        else:
            g = 'none'
            h = 'none'
            z = -1
            j = -1
            k = -1
        if 'TCP' in i:
            sr1 = i.tcp.srcport
            sr2 = i.tcp.dstport
            ac = i.tcp.flags_ack
            sy = i.tcp.flags_syn
            fi = i.tcp.flags_fin
        else:
            sr1 = -1
            sr2 = -1
            ac = -1
            sy = -1
            fi = -1

        file_writer.writerow([asd, a, b, c, d, e, f, g, h, z, j, k, sr1, sr2, ac, sy, fi, cl])
        asd += 1
        if asd % 10000 == 0:
            print(asd)

sdfsadfsdfsdfsdf
