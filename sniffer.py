import time
import csv
import pickle

import sklearn
import pandas as pd
import scapy.all as scapy


class Sniffer():

    def __init__(self, adapter, parent=None):
        self.adapter = adapter
        self.exiting = False
        self.mac = ""
        self.badmac = ''
        self.border = 0.75
        self.buffer = {}
        self.filename = 'data.csv'
        self.fieldnames = ['proto','ports', 'portmin', 'portmax', 'delay', 'count', 'length', 'suspicious']
        self.model = pickle.load(open('model', "rb"))
        try:
            with open(self.filename, 'r') as csvfile:
                print('file already exists!')
        except:
            with open(self.filename, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
                writer.writeheader()

    def __del__(self):
        self.exiting = True

    def run(self):
        try:
            scapy.sniff(iface=self.adapter, store=False, prn=self.pktProcess, lfilter=self.isNotOutgoing)
        except Exception as e:
            print(f"FAILED! Error: {e}")

    def pktProcess(self, pkt):
        data = self.pkt_info(pkt)
        if not data: return
        pred = self.predictor(data)
        print(f"{pkt['Ether'].src} is {'bad ' if pred else 'good'} (data={data})")
        #self.collector(pkt['Ether'].src, data) 
    
    def collector(self, src, data, show = False):
        if src == self.badmac:
            data['suspicious'] = 1
        else:
            data['suspicious'] = 0
        if show: print(data)
        with open(self.filename, 'a', newline='') as csvfile:
           writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
           writer.writerow(data)

    def predictor(self, data):
        df = pd.DataFrame(columns=self.fieldnames[:-1])
        df.loc[0] = list(data.values())
        return self.model.predict(df)[0]

    def get_proto(self, proto):
        match proto:
                case 6:  # TCP
                    return 1
                case 17: # UDP
                    return 2
                case 1:  # ICMP
                    return 3
                case 58: # ICMP
                    return 3
                case _:  # OTHER
                    return 0

    def pkt_info(self, pkt):
        if 'Ether' not in pkt: return
        if 'DNS' not in pkt and 'ARP' not in pkt: 
            if pkt['Ether'].type != 2048: return False
            ip = pkt['IP'].src
            curtime = time.time()
            if ip not in self.buffer:
                self.buffer[ip] = {}
            proto = self.get_proto(pkt['IP'].proto)
            sproto = str(proto)
            if sproto not in self.buffer[ip]:
                self.new_proto(ip, sproto, curtime)
            if curtime-self.buffer[ip][sproto]['start']<=5:
                try:
                    port = pkt[2].dport
                    self.buffer[ip][sproto]['pkt']['ports'] += port
                    min = self.buffer[ip][sproto]['pkt']['portmin'] 
                    max = self.buffer[ip][sproto]['pkt']['portmax']
                    if port < min: self.buffer[ip][sproto]['pkt']['portmin'] = port
                    if port > max: self.buffer[ip][sproto]['pkt']['portmax'] = port
                except:
                    self.buffer[ip][sproto]['pkt']['ports'] += 0
                self.buffer[ip][sproto]['pkt']['delay'] += curtime - self.buffer[ip][sproto]['last']
                self.buffer[ip][sproto]['last'] = curtime
                self.buffer[ip][sproto]['pkt']['count'] += 1
                self.buffer[ip][sproto]['pkt']['length'] += len(list(pkt)[-1])
                return False
            else:
                a = self.buffer[ip].pop(sproto, False)['pkt']
                return self.get_avg(proto, a)

    def get_avg(self, proto, data):
        res = {
            'proto': proto,
            'portmin': data['portmin'],
            'portmax': data['portmax'],
            'ports': data['ports']/data['count'],
            'delay': data['delay']/data['count'],
            'count': data['count'],
            'length': data['length']/data['count']
        }
        return res

    def new_proto(self, ip, proto, time):
        self.buffer[ip][proto] = {'start': time, 'last': time, 
                                'pkt': {
                                    'ports': 0,
                                    'portmin':65535,
                                    'portmax': 0,
                                    'delay': 0,
                                    'count': 0,
                                    'length': 0
                                }
                        }

    def isNotOutgoing(self, pkt):
        if 'Ether' in pkt:
            return pkt['Ether'].src != self.mac


if __name__ == "__main__":
    snf = Sniffer('')
    snf.run()
    
