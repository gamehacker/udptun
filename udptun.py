#!/usr/bin/python
#coding: utf8
'''
    UDP Tunnel VPN
    Xiaoxia (xiaoxia@xiaoxia.org)
    First version: 2012-2-21
    Updated: 2014-6-3 P2P network packet exchange
    Updated: 2015-6-2 for mac
'''

import os, sys
import hashlib
import getopt
import fcntl
import time
import struct
import socket, select
import traceback
import signal
import ctypes
import binascii
import cPickle as pickle
import re

SHARED_PASSWORD = hashlib.sha1("feiwu").digest()
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001 | 0x1000 #TUN + NO_PI

BUFFER_SIZE = 8192
MODE = 0
DEBUG = 0
PORT = 0
IFACE_IP = "10.0.0.1"
IFACE_PEER = "10.0.0.2"
MTU = 1400
TIMEOUT = 60*10 # seconds
RT_INTERVAL = 30 # seconds
ipstr2int = lambda x: struct.unpack('!I', socket.inet_aton(x))[0]

class Server():
    def create_tun(self):
        """For every client, we create a P2P interface for it."""
        try:
            tun_fd = os.open("/dev/net/tun", os.O_RDWR)
        except:
            tun_fd = os.open("/dev/tun", os.O_RDWR)
        if tun_fd < 0:
            raise Exception('Failed to create tun device')
        ifs = fcntl.ioctl(tun_fd, TUNSETIFF, struct.pack("16sH", "tun%d", IFF_TUN))
        tname = ifs[:16].strip("\x00")
        return {'tun_fd': tun_fd, 'tun_name': tname}
    
    def config_tun(self, c):
        """Set up IP address and P2P address"""
        print "Configuring interface %s with ip %s" % (c['tun_name'], c['tun_ip'])
        os.system("ifconfig %s %s dstaddr %s mtu %s up" % (c['tun_name'], c['tun_ip'], c['tun_peer'], MTU))

    def get_client_by_addr(self, addr):
        for c in self.sessions:
            if c['addr'] == addr:
                return c
        return None

    def get_client_by_tun(self, tun):
        for c in self.sessions:
            if c['tun_fd'] == tun:
                return c
        return None

    def get_client_by_intip(self, ip):
        for c in self.sessions:
            if c['tun_peer'] == ip:
                return c
        return None
        
    def do_login(self, data, addr):
        """Deal with client logins, use share key."""
        if data.startswith('AUTH'):
            d = pickle.loads(data[4:])
            # Check password
            if d['password'] != SHARED_PASSWORD:
                d = {
                    'ret': 1,
                    'msg': 'Incorrent password.'
                }
                self.udpfd.sendto('AUTH' + pickle.dumps(d), addr)
                return
            # Find existing session 
            found = False
            for c in self.sessions:
                if c['tun_peer'] == d['tun_ip'] and c['tun_ip'] == d['tun_peer']:
                    c['addr'] = addr
                    found = True
                    break
            if not found:
                # Create new client session
                c = {
                    'addr': addr,
                    'tun_peer': d['tun_ip'],
                    'tun_ip': d['tun_peer'],
                    'active_time': time.time(),
                }
                t = self.create_tun()
                c.update(t)
                self.config_tun(c)
                self.sessions.append(c)
                print '[%s] Created new tun %s, %s -> %s for %s' % (time.ctime(), c['tun_name'], c['tun_ip'], c['tun_peer'], c['addr'])
            else:
                print '[%s] Keep alive tun %s, %s -> %s for %s' % (time.ctime(), c['tun_name'], c['tun_ip'], c['tun_peer'], c['addr'])
            d = {
                'ret': 0,
            }
            self.udpfd.sendto('AUTH'+ pickle.dumps(d), addr)
            print 'send ok to', addr
        else:
            self.udpfd.sendto('AUTH', addr)

    def sync_routes(self):
        """ Send dynamic routing table to every client for P2P package excahnge.
            This only works for clients behide Full-Cone NAT at the moment. Should be improved.
        """
        table = []
        for c in self.sessions:
            r = {'network': c['tun_peer'], 'mask': 32, 'gw': c['tun_peer'], 'addr': c['addr'], 'active_time': int(c['active_time'])}
            table.append(r)
        data = os.popen('ip route show|grep zebra').read()
        for ip,mask,gw in re.findall(r'([\d\.]+)/(\d+) via ([\d\.]+)', data):
            c = self.get_client_by_intip(gw)
            r = {'network': ip, 'mask': int(mask), 'gw': gw, 'addr': c['addr'], 'active_time': int(c['active_time'])}
            table.append(r)
        data = 'RTBL' + pickle.dumps(table)
        for c in self.sessions:
            try:
                self.udpfd.sendto(data, c['addr'])
            except: pass

    def run(self):
        """ Server packets loop """
        global PORT
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.bind(("", PORT))
        self.sessions = []
        self.rt_sync_time = 0

        print 'Server listen at port', PORT
        while True:
            now = int(time.time())
            fds = [x['tun_fd'] for x in self.sessions]
            fds.append(self.udpfd)
            rset = select.select(fds, [], [], 1)[0]
            for r in rset:
                if r == self.udpfd:
                    if DEBUG: os.write(1, "<")
                    data, addr = self.udpfd.recvfrom(BUFFER_SIZE)
                    c = self.get_client_by_addr(addr)
                    if data.startswith('AUTH') or not c:
                        self.do_login(data, addr)
                    else:
                        c['active_time'] = now
                        os.write(c['tun_fd'], data)
                else:
                    c = self.get_client_by_tun(r)
                    if DEBUG: os.write(1, ">")
                    data = os.read(r, BUFFER_SIZE)
                    try:
                        self.udpfd.sendto(data, c['addr'])
                    except: pass
            if now % RT_INTERVAL == 0 and now != self.rt_sync_time:
                self.sync_routes()
                self.rt_sync_time = now

class Client():
    def create_tun(self):
        """ Every client needs a tun interface """
        if sys.platform == 'darwin':
            for i in xrange(10):
                try:
                    tname = 'tun%s' % i
                    tun_fd = os.open('/dev/%s' % tname, os.O_RDWR)
                    break
                except:
                    continue
        else:
            try:
                tun_fd = os.open("/dev/net/tun", os.O_RDWR)
            except:
                tun_fd = os.open("/dev/tun", os.O_RDWR)
            ifs = fcntl.ioctl(tun_fd, TUNSETIFF, struct.pack("16sH", "t%d", IFF_TUN))
            tname = ifs[:16].strip("\x00")

        return {'tun_fd': tun_fd, 'tun_name': tname}
    
    def config_tun(self, c):
        """ Set up local ip and peer ip """
        print "Configuring interface %s with ip %s" % (c['tun_name'], c['tun_ip'])
        os.system("ifconfig %s %s/32 %s mtu %s up" % (c['tun_name'], c['tun_ip'], c['tun_peer'], MTU))

    def do_login(self, data):
        """ Check login results """
        try:
            d = pickle.loads(data[4:])
        except:
            d = {'ret': 1}
        if d['ret'] == 0:
            self.logged = True
            print "Logged in server succefully!"
        else:
            self.logged = False
            print "Logged failed:", d.get('msg')

    def update_routes(self, data):
        """ Update routing table (peer list) for P2P packet exchange """
        try:
            table = pickle.loads(data[4:])
        except:
            traceback.print_exc()
            return
        rt = []
        for x in table:
            mask = 0xffffffff & (0xffffffff << (32-x['mask']))
            network = ipstr2int(x['network'])
            addr = x['addr']
            rt.append((network, mask, addr))
        rt.append((0, 0, (IP, PORT)))
        self.rt_table = rt

    def get_router_by_dst(self, dst):
        for n, m, addr in self.rt_table:
            if dst & m == n:
                return addr
        print 'No route address for', dst
        return self.addr
 
    def run(self):
        """ Client network loop """
        global PORT
        c = self.create_tun()
        c['tun_ip'] = IFACE_IP
        c['tun_peer'] = IFACE_PEER
        self.config_tun(c)
        self.tunfd = c['tun_fd']
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.bind(("", 0))
        self.logged = False
        self.log_time = 0
        self.active_time = 0
        self.addr = (IP, PORT)
        self.rt_table = [(0, 0, (IP, PORT))]
        print '[%s] Created client %s, %s -> %s for %s' % (time.ctime(), c['tun_name'], c['tun_ip'], c['tun_peer'], self.addr)

        while True:
            now = time.time()
            if now - self.active_time > 60: #If no packets within 60 secs, Force relogin, NAT problem, Just keepalive
                self.active_time = now
                self.logged = False
            if not self.logged and time.time() - self.log_time > 2.:
                d = {
                    'password': SHARED_PASSWORD,
                    'tun_ip': IFACE_IP,
                    'tun_peer': IFACE_PEER,
                }
                data = pickle.dumps(d)
                self.udpfd.sendto('AUTH' + data, self.addr)
                self.log_time = now
                print "[%s] Do login ..." % (time.ctime(), )

            rset = select.select([self.udpfd, self.tunfd], [], [], 1)[0]
            for r in rset:
                if r == self.tunfd:
                    if DEBUG: os.write(1, ">")
                    data = os.read(self.tunfd, BUFFER_SIZE)
                    dst = struct.unpack('!I', data[20:24])[0]
                    addr = self.get_router_by_dst(dst)
                    self.udpfd.sendto(data, addr)
                elif r == self.udpfd:
                    if DEBUG: os.write(1, "<")
                    data, src = self.udpfd.recvfrom(BUFFER_SIZE)
                    if data.startswith("AUTH"):
                        self.do_login(data)
                    elif data.startswith('RTBL'):
                        self.update_routes(data)
                    else:
                        os.write(self.tunfd, data)
                        self.active_time = now

def usage(status = 0):
    print "Usage: %s [-s port|-c serverip] [-hd] [-l localip]" % (sys.argv[0])
    sys.exit(status)

def on_exit(no, info):
    raise Exception("TERM signal caught!")

if __name__=="__main__":
    opts = getopt.getopt(sys.argv[1:],"s:c:l:p:hd")
    for opt,optarg in opts[0]:
        if opt == "-h":
            usage()
        elif opt == "-d":
            DEBUG += 1
        elif opt == "-s":
            MODE = 1
            PORT = int(optarg)
        elif opt == "-c":
            MODE = 2
            IP, PORT = optarg.split(",")
            IP = socket.gethostbyname(IP)
            PORT = int(PORT)
        elif opt == "-l":
            IFACE_IP = optarg
        elif opt == "-p":
            IFACE_PEER = optarg
    
    if MODE == 0 or PORT == 0:
        usage(1)
    
    signal.signal(signal.SIGTERM, on_exit)
    if MODE == 1:
        tun = Server()
    else:
        tun = Client()
    try:
        tun.run()
    except KeyboardInterrupt:
        pass
    except:
        print traceback.format_exc()
    finally:
        # Cleanup something.
        pass


