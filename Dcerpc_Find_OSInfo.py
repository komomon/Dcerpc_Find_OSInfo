#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author:Komomon
# @Time:2022/5/27 17:32

'''
完整版
通过DCERPC+NTLMSSP探测目标主机信息

usage
python3 Dcerpc_Find_OSInfo.py -i 192.168.31
python3 Dcerpc_Find_OSInfo.py -i ip.txt
python3 Dcerpc_Find_OSInfo.py -i 192.168.1.1-192.168.2.2


'''
域控原本IP
from base64 import b64encode
from argparse import ArgumentParser, FileType
from queue import Queue
from threading import Thread
import sys
import socket
import logging
import binascii, time

TIME_OUT = 3
RESULT_LIST = []
length = 0


def get_ip_list(ip) -> list:
    ip_list = []
    iptonum = lambda x: sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])
    numtoip = lambda x: '.'.join([str(int(x / (256 ** i)) % 256) for i in range(3, -1, -1)])
    if '-' in ip:
        ip_range = ip.split('-')
        ip_start = int(iptonum(ip_range[0]))
        ip_end = int(iptonum(ip_range[1]))
        ip_count = ip_end - ip_start
        if ip_count >= 0 and ip_count <= 65536:
            for ip_num in range(ip_start, ip_end + 1):
                ip_list.append(numtoip(ip_num))
        else:
            print('-i wrong format')

    elif '.txt' in ip:
        ip_config = open(ip, 'r')
        for ip in ip_config:
            ip_list.extend(get_ip_list(ip.strip()))
        ip_config.close()
    else:
        ip_split = ip.split('.')
        net = len(ip_split)
        if net == 2:
            for b in range(1, 255):
                for c in range(1, 255):
                    ip = "%s.%s.%d.%d" % (ip_split[0], ip_split[1], b, c)
                    ip_list.append(ip)
        elif net == 3:
            for c in range(1, 255):
                ip = "%s.%s.%s.%d" % (ip_split[0], ip_split[1], ip_split[2], c)
                ip_list.append(ip)
        elif net == 4:
            ip_list.append(ip)
        else:
            print("-i wrong format")

    return ip_list


def attribute_name(Target_Info_bytes):
    global length
    att_name_length = int.from_bytes(Target_Info_bytes[length + 2:length + 4], byteorder='little')
    att_name = Target_Info_bytes[length + 4:length + 4 + att_name_length].replace(b"\x00", b"").decode(
        encoding="unicode_escape")
    length = length + 4 + att_name_length
    return att_name


def send_packet(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(TIME_OUT)
        sock.connect((ip, 135))
        buffer_v1 = b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa\x03\x00\x00\x00\x33\x05\x71\x71\xba\xbe\x37\x49\x83\x19\xb5\xdb\xef\x9c\xcc\x36\x01\x00\x00\x00"
        sock.send(buffer_v1)
        packet1 = sock.recv(1024)
        digit = "x86"
        if b"\x33\x05\x71\x71\xBA\xBE\x37\x49\x83\x19\xB5\xDB\xEF\x9C\xCC\x36" in packet1:
            digit = "x64"
        return digit
    except Exception as e:
        # print(e)
        return -1
    finally:
        sock.close()


def get_osinfo(ip):
    global length
    osinfo = {
        "NetBIOS_domain_name": "",
        "DNS_domain_name": "",
        "DNS_computer_name": "",
        "DNS_tree_name": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(TIME_OUT)
        sock.connect((ip, 135))
        buffer_v2 = b"\x05\x00\x0b\x03\x10\x00\x00\x00\x78\x00\x28\x00\x03\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x01\x00\xa0\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00\x0a\x02\x00\x00\x00\x00\x00\x00\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x01\xb1\x1d\x00\x00\x00\x0f"
        sock.send(buffer_v2)
        packet2 = sock.recv(4096)
        digit = send_packet(ip)
        OS_Version_bytes = packet2[int('0xa0', 16) - 54 + 10:int('0xa0', 16) - 54 + 18]
        Major_Version = int.from_bytes(OS_Version_bytes[0:1], byteorder='little')
        Minor_Version = int.from_bytes(OS_Version_bytes[1:2], byteorder='little')
        Build_Number = int.from_bytes(OS_Version_bytes[2:4], byteorder='little')
        NTLM_Current_Reversion = int.from_bytes(OS_Version_bytes[7:8], byteorder='little')
        OS_Verison = "Windows Version {0}.{1} Build {2} {3}".format(Major_Version, Minor_Version, Build_Number, digit)

        Target_Info_Length_bytes = packet2[int('0xa0', 16) - 54 + 2:int('0xa0', 16) - 54 + 4]
        Target_Info_Length = int.from_bytes(Target_Info_Length_bytes, byteorder='little')
        Target_Info_bytes = packet2[-Target_Info_Length:-4]  # 最后四个0x00000000
        print("[*] " + ip)
        print("\t[->]", "OS_Verison :", OS_Verison)
        for k in osinfo.keys():
            osinfo[k] = attribute_name(Target_Info_bytes)
            print("\t[->]", k, ":", osinfo[k])
        length = 0
        osinfo["OS_Verison"] = OS_Verison
        result = {ip: osinfo}
        return result
    except Exception as e:
        return -1
    finally:
        sock.close()


def worker(q):
    while True:
        try:
            data = q.get()
            result = get_osinfo(data)
            if result != -1:
                RESULT_LIST.append(result)
        except Exception as e:
            sys.stderr.write(str(e))
        finally:
            q.task_done()


def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--ip', help=u'IP Address', required=True)
    parser.add_argument('-t', '--threads', help=u'threads', default=20, type=int)
    parser.add_argument('-o', '--output', help=u'Output result', default='log.txt', type=FileType('a+'))

    args = parser.parse_args()
    if args.ip is None:
        print("Some Wrong.")
    q = Queue(args.threads)

    for _ in range(args.threads):
        t = Thread(target=worker, args=(q,))
        t.daemon = True
        t.start()

    ip_list = get_ip_list(args.ip)
    for i in ip_list:
        q.put(i)
    q.join()
    for osinfo_dict in RESULT_LIST:
        for ip in osinfo_dict.keys():
            args.output.write("[*] " + ip + "\n")
            for k, v in osinfo_dict[ip].items():
                args.output.write("\t[->] " + k + ":" + v + "\n")
        # print(osinfo_dict)


if __name__ == '__main__':
    main()
