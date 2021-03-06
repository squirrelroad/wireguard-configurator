#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Licensed under the GNU General Public License Version 3 (GNU GPL v3),
    available at: https://www.gnu.org/licenses/gpl-3.0.txt
"""
import json
import os
import re
import subprocess
import sys
import traceback
from enum import Enum
import ipaddress
import copy
import os.path
import random
import logging
import jsonpickle
from pprint import pformat
import argparse
import hashlib

class Utilities:
    """ Useful utilities

    This class contains a number of utility tools.
    """

    @staticmethod
    def execute(command, input_value=''):
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        output = process.communicate(input=input_value)[0]
        return output.decode().replace('\n', '')

class WireGuard:
    """ WireGuard utility controller

    This class handles the interactions with the wg binary,
    including:

    - genkey
    - pubkey
    - genpsk
    """

    def __init__(self):
        pass

    def genkey(self):
        """ Generate WG private key

        Generate a new wireguard private key via
        wg command.
        """
        return Utilities.execute(['wg', 'genkey'])

    def pubkey(self, public_key):
        """ Convert WG private key into public key

        Uses wg pubkey command to convert the wg private
        key into a public key.
        """
        return Utilities.execute(['wg', 'pubkey'], input_value=public_key.encode('utf-8'))

    def genpsk(self):
        """ Generate a random base64 psk
        """
        return Utilities.execute(['wg', 'genpsk'])

class PeerType(Enum):
    CLIENT = "client"
    SERVER = "server"
    DYNAMIC = "dynamic"

class Peer:
    alias = ''
    description = ''
    private_key = ''
    peertype = PeerType(PeerType.CLIENT)
    public_address = ''
    keep_alive = ''
    preshared_key = ''

    def __getstate__(self):
        state = self.__dict__.copy()
        if 'peertype' in state:
            state['peertype'] = self.peertype._value_
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        if 'peertype' in state:
            self.peertype = PeerType(state['peertype'])
        

class ProfileManager(object):
    prefix = ""
    LISTEN_PORT = 51820
    ip6interface = ipaddress.IPv6Interface("fd42:42:42::0/64")
    ip4interface = ipaddress.IPv4Interface('192.168.195.0/32')
    peers = []
    preshared = []


def dump():
    jsonpm = json.loads(jsonpickle.encode(pm))
    return (json.dumps(jsonpm, indent=2))
            
def find_hash(key1, key2):
    combine = ""
    if (key1 < key2):
        combine = key1 + key2
    else:
        combine = key2 + key1
    hash = hashlib.blake2b( combine.encode()).digest()
    return hash[0]


def fill_parameters():
    """
    PRIVATE_SUBNET_V4 - private IPv4 subnet configuration 10.8.0.0/24 by default
    PRIVATE_SUBNET_V6 - private IPv6 subnet configuration fd42:42:42::0/64 by default
    SERVER_PORT - public port for wireguard server, default is 51820
    """

    #sweep all peers for ip address
    pool = [
        pm.ip4interface+1,
        pm.ip4interface+2,
        pm.ip4interface+4,
        pm.ip4interface+8,
        pm.ip4interface+16,
        pm.ip4interface+32,
        pm.ip4interface+64,
        pm.ip4interface+128
    ]
    logging.debug(pformat(pool))
    serverip = pool.copy()
    ipsix = pm.ip6interface +1
    clientip = pm.ip4interface +1

    for peer in pm.peers:
        if peer.peertype == PeerType.SERVER:
            pm.master = peer
            break

    for peer in pm.peers:
        if peer.peertype != PeerType.CLIENT:
            if peer.address == '':
                peer.address = str(pool.pop(0))
            if peer.listen_port == '':
                peer.listen_port = str(pm.LISTEN_PORT)

    for peer in pm.peers:
        if peer.peertype == PeerType.CLIENT:
            if peer.address == '':
                while (clientip in serverip):
                    clientip = clientip+1
                peer.address = str(clientip)
                clientip = clientip+1

    for peer in pm.peers:
        if peer.address6 == '':
            peer.address6 = str(ipsix)
            ipsix = ipsix +1
    
    keys = set()
    for peer in pm.peers:
        if peer.private_key in keys:
            raise
        else:
            keys.add(peer)
            
            
def generate_configs_alt(output_path):
    logging.debug("generate_configs_alt")

    # servers
    for peer in pm.peers:
        if peer.peertype == PeerType.CLIENT:
            continue
        filename = f'{output_path}/{peer.alias}.conf'
        logging.info(f'Generating configuration file for {filename}')
        with open(filename, 'w') as config:
            # Write Interface configuration
            config.write('[Interface]\n')
            if peer.alias:
                config.write(f'# Alias: {peer.alias}\n')
            config.write(f'PrivateKey = {peer.private_key}\n')
            address = peer.address
            if peer.address6 != '':
                address = f'{address},{peer.address6}'
            config.write(f'Address = {address}\n')
            config.write(f'ListenPort = {peer.listen_port}\n')
            config.write(f'PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; iptables -A INPUT -s 192.168.195.0/24 -p udp -m udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT; ip6tables -A INPUT -s fd42:42:42::0/64 -p udp -m udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT\n')
            config.write(f'PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; iptables -D INPUT -s 192.168.195.0/24 -p udp -m udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT; iptables -D INPUT -s fd42:42:42::0/64 -p udp -m udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT\n')
            config.write(f'SaveConfig = false\n')

            for p in pm.peers:
                if p.address == peer.address:
                    continue

                config.write('\n[Peer]\n')
                print(p.private_key)
                if p.alias:
                    config.write(f'# Alias: {p.alias}\n')
                config.write(f'PublicKey = {wg.pubkey(p.private_key)}\n')
                address = p.address
                if p.address6 != '':
                    address = f'{address},{p.address6}'
                if (p.address == pm.master.address):
                    config.write(f'Endpoint = {p.public_address}:{p.listen_port}\n')
                    config.write('PersistentKeepalive = 25\n')
                    config.write(f'AllowedIPs = {pm.ip4interface},{pm.ip6interface}\n')
                else:
                    config.write(f'AllowedIPs = {address}\n')

                ipreshared = find_hash(peer.private_key, p.private_key) % len(pm.preshared)
                logging.debug(ipreshared)
                preshared = pm.preshared[ipreshared]
                config.write(f'PresharedKey = {preshared}\n')

    # clients
    logging.debug("generate_configs_alt")
    for peer in pm.peers:
        if peer.peertype == PeerType.SERVER:
            continue
        for p in pm.peers:
            if p.address == peer.address: #self,ignore
                continue
            if p.peertype == PeerType.CLIENT:
                continue
            filename = f'{output_path}/{pm.prefix}-{p.alias}-{peer.alias}.conf';
            logging.info(f'Generating configuration file for {filename}')
            with open(filename, 'w') as config:
                config.write('[Interface]\n')
                if peer.alias:
                    config.write(f'# Alias: {peer.alias}\n')
                config.write(f'PrivateKey = {peer.private_key}\n')
                config.write(f'# PublicKey = {wg.pubkey(peer.private_key)}\n')
                address = peer.address
                if peer.address6 != '':
                    address = f'{address},{peer.address6}'
                config.write(f'Address = {address}\n')
                listen_port = str(random.randrange(50000,59999))
                if peer.listen_port != '':
                    listen_port = peer.listen_port;
                config.write(f'ListenPort = {listen_port}\n')
                addr4 = ipaddress.IPv4Interface(p.address)
                addr6 = ipaddress.IPv6Interface(p.address6)
                config.write(f'DNS = {addr4.ip},{addr6.ip}\n')
                config.write(f'MTU = 1280')
                
                config.write('\n[Peer]\n')
                print(p.private_key)
                if p.alias:
                    config.write(f'# Alias: {p.alias}\n')
                config.write(f'PublicKey = {wg.pubkey(p.private_key)}\n')
                if p.peertype == PeerType.DYNAMIC:
                    config.write(f'AllowedIPs = {pm.ip4interface},{pm.ip6interface}\n')
                if p.peertype == PeerType.CLIENT:
                    config.write(f'AllowedIPs = 0.0.0.0/0,::/0\n')
                config.write(f'Endpoint = {p.public_address}:{p.listen_port}\n')
                if p.keep_alive:
                    config.write('PersistentKeepalive = 25\n')

                ipreshared = find_hash(peer.private_key, p.private_key) % len(pm.preshared)
                logging.debug(ipreshared)
                preshared = pm.preshared[ipreshared]
                config.write(f'PresharedKey = {preshared}\n')


def main():
    """ WireGuard Mesh Configurator main function

    This function controls the main flow of this program.
    """

    global wg, pm

    parser = argparse.ArgumentParser()
    parser.add_argument('--old', nargs='?', type=str, metavar='oldprofile.json')
    parser.add_argument('profile', nargs='?', metavar='profile.json', type=str)
    parser.add_argument('--makepreshared', action='store_true')
    parser.add_argument('--generate', metavar="directory", type=str)

    args = parser.parse_args()
    logging.info(args.profile)
    logging.info(args.old)

    if (args.old is not None) and (os.path.isfile(args.old)):
        pm.json_load_profile(args.old)

    if (args.profile is not None) and (os.path.isfile(args.profile)):
        logging.debug("loading jsonpickle")
        pm = jsonpickle.decode(open(args.profile).read())
        logging.debug("loading jsonpickle done")

    if (args.makepreshared == True):
        pm.preshared = []
        for i in range(128):
            pm.preshared.append(wg.genpsk())

    logging.debug("jsonpickle3")

    if (args.generate is not None):
        fill_parameters()
        jsonpm = json.loads(jsonpickle.encode(pm))
        print(json.dumps(jsonpm, indent=2))
        generate_configs_alt(args.generate)
    else:
        jsonpm = json.loads(jsonpickle.encode(pm))
        print(json.dumps(jsonpm, indent=2))



if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)

    # Create global object for WireGuard handler
    wg = WireGuard()

    # Create global object for profile manager
    pm = ProfileManager()

    # Launch main function
    main()
