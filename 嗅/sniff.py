from scapy.all import *
import pymysql
import joblib
import ws
import traceback


class Net:
    ethernet_dst = ''
    ethernet_src = ''
    ethernet_type = ''
    ip_version = ''
    ip_ihl = ''
    ip_tos = ''
    ip_len = ''
    ip_id = ''
    ip_flags = ''
    ip_frag = ''
    ip_ttl = ''
    ip_proto = ''
    ip_chksum = ''
    ip_src = ''
    ip_dst = ''
    tcp_sport = ''
    tcp_dport = ''
    tcp_seq = ''
    tcp_ack = ''
    tcp_dataofs = ''
    tcp_reserved = ''
    tcp_flags = ''
    tcp_window = ''
    tcp_chksum = ''
    tcp_urgptr = ''
    tcp_options = ''
    udp_sport = ''
    udp_dport = ''
    udp_len = ''
    udp_chksum = ''
    raw_load = ''


# 连接数据库
SERVER_IP = '39.97.107.13'
db = pymysql.connect(host=SERVER_IP, user='industry', password='tjut2020', database='industry')
cursor = db.cursor()


# 定义回调函数，嗅探一次返回执行一次
def pack_callback(pack):
    net = Net()
    # pack.show()
    try:
        if pack['Ethernet'].payload:
            net.ethernet_dst = pack['Ethernet'].dst
            net.ethernet_src = pack['Ethernet'].src
            net.ethernet_type = pack['Ethernet'].type
    except Exception as e:
        pass

    try:
        if pack['IP'].payload:
            net.ip_version = pack['IP'].version
            net.ip_ihl = pack['IP'].ihl
            net.ip_tos = pack['IP'].tos
            net.ip_len = pack['IP'].len
            net.ip_id = pack['IP'].id
            net.ip_flags = pack['IP'].flags
            net.ip_frag = pack['IP'].frag
            net.ip_ttl = pack['IP'].ttl
            net.ip_proto = pack['IP'].proto
            net.ip_chksum = pack['IP'].chksum
            net.ip_src = pack['IP'].src
            net.ip_dst = pack['IP'].dst
    except Exception as e:
        pass

    try:
        if pack['TCP'].payload:
            net.tcp_sport = pack['TCP'].sport
            net.tcp_dport = pack['TCP'].dport
            net.tcp_seq = pack['TCP'].seq
            net.tcp_ack = pack['TCP'].ack
            net.tcp_dataofs = pack['TCP'].dataofs
            net.tcp_reserved = pack['TCP'].reserved
            net.tcp_flags = pack['TCP'].flags
            net.tcp_window = pack['TCP'].window
            net.tcp_chksum = pack['TCP'].chksum
            net.tcp_urgptr = pack['TCP'].urgptr
            net.tcp_options = pack['TCP'].options
    except Exception as e:
        pass

    try:
        if pack['UDP'].payload:
            net.udp_sport = pack['UDP'].sport
            net.udp_dport = pack['UDP'].dport
            net.udp_len = pack['UDP'].len
            net.udp_chksum = pack['UDP'].chksum
    except Exception as e:
        pass

    try:
        net.raw_load = pack['Raw'].load
    except Exception as e:
        pass

    save_db(net)

    # 获取数据
    data_list = [random.randint(40, 638),
                 random.randint(46, 8900),
                 random.randint(1, 30),
                 random.randint(0, 4.220000e+08),
                 random.randint(0, 847621692),
                 random.randint(1, 30),
                 random.randint(111, 117),
                 random.randint(1422326703, 2710576871),
                 random.uniform(0, 1),
                 random.randint(1, 29)]

    predict(data_list)


# 模拟预测
def predict(data):
    """
    模型导入与预测
    :param data: a list length:10
    :return: int 0~9
    """
    data = [data]
    if os.path.exists('./model/10_test.pkl'):
        # 模型导入
        gbm = joblib.load('./model/10_test.pkl')
        result = gbm.predict(data)  # result:[N]  array([0], dtype=int64)
        re_list = [str(result[0]), data[0]]
        ws.send(str(re_list))
        print(result[0])
        return result[0]
    else:
        print("【ERROR】模型加载失败")


# 存储到数据库
def save_db(net):
    sql = f'''INSERT INTO net(ethernet_dst,ethernet_src,ethernet_type,ip_version,ip_ihl,ip_tos,ip_len,ip_id,
        ip_flags,ip_frag,ip_ttl,ip_proto,ip_chksum,ip_src,ip_dst,tcp_sport,tcp_dport,tcp_seq,tcp_ack,tcp_dataofs,
        tcp_reserved,tcp_flags,tcp_window,tcp_chksum,tcp_urgptr,tcp_options,udp_sport,udp_dport,udp_len,udp_chksum,
        raw_load) VALUES ('{net.ethernet_dst}','{net.ethernet_src}','{net.ethernet_type}','{net.ip_version}',
        '{net.ip_ihl}','{net.ip_tos}','{net.ip_len}','{net.ip_id}','{net.ip_flags}','{net.ip_frag}','{net.ip_ttl}',
        '{net.ip_proto}','{net.ip_chksum}','{net.ip_src}','{net.ip_dst}','{net.tcp_sport}','{net.tcp_dport}',
        '{net.tcp_seq}','{net.tcp_ack}','{net.tcp_dataofs}','{net.tcp_reserved}','{net.tcp_flags}','{net.tcp_window}',
        '{net.tcp_chksum}','{net.tcp_urgptr}','{net.tcp_options}','{net.udp_sport}','{net.udp_dport}','{net.udp_len}',
        '{net.udp_chksum}',"{net.raw_load}")'''

    try:
        cursor.execute(sql)
        db.commit()
    except:
        db.rollback()  # 错误回滚
    finally:
        print('【INFO】执行一次存储')


show_interfaces()  # 展示"iface"参数
dpkt = sniff(iface="Broadcom 802.11ac Network Adapter", prn=pack_callback, count=0)
