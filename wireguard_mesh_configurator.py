#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Licensed under the GNU General Public License Version 3 (GNU GPL v3),
    available at: https://www.gnu.org/licenses/gpl-3.0.txt
"""
from avalon_framework import Avalon
import json
import os
import pickle
import re
import readline
import subprocess
import sys
import traceback
from enum import Enum
import ipaddress
import copy
import os.path
import random

prefix = 'deerarise'
LISTEN_PORT = 51820

VERSION = '1.2.0'
COMMANDS = [
    'Interactive',
    'ShowPeers',
    'JSONLoadProfile',
    'JSONSaveProfile',
    'NewProfile',
    'AddPeer',
    'DeletePeer',
    'GenerateConfigs',
    'Exit',
    'Quit',
]


class Utilities:
    """ Useful utilities

    This class contains a number of utility tools.
    """

    @staticmethod
    def execute(command, input_value=''):
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        output = process.communicate(input=input_value)[0]
        return output.decode().replace('\n', '')


class ShellCompleter(object):
    """ A Cisco-IOS-like shell completer

    This is a Cisco-IOS-like shell completer, that is not
    case-sensitive. If the command typed is not ambiguous,
    then execute the only command that matches. User does
    not have to enter the entire command.
    """

    def __init__(self, options):
        self.options = sorted(options)

    def complete(self, text, state):
        if state == 0:
            if text:
                self.matches = [s for s in self.options if s and s.lower().startswith(text.lower())]
            else:
                self.matches = self.options[:]
        try:
            return self.matches[state]
        except IndexError:
            return None

class PeerType(str, Enum):
    SERVER = "server"
    DYNAMIC = "dynamic"
    CLIENT = "client"

class Peer:
    """ Peer class

    Each object of this class represents a peer in
    the wireguard mesh network.
    """

    def __init__(self):
        self.address = ''
        self.address6 = ''
        self.public_address = ''
        self.listen_port = ''
        self.private_key = ''
        self.keep_alive = ''
        self.preshared_key = ''
        self.alias = ''
        self.description = ''
        self.peertype = PeerType(PeerType.CLIENT)

    def load(self, p):
        if 'address' in p:
            self.address = p['address']

        if 'public_address' in p:
            self.public_address = p['public_address']

        if 'listen_port' in p:
            self.listen_port = p['listen_port']

        if 'private_key' in p:
            self.private_key = p['private_key']

        if 'keep_alive' in p:
            self.keep_alive=p['keep_alive']

        if 'alias' in p:
            self.alias=p['alias']

        if 'peertype' in p:
            try:
                self.peertype = PeerType(p['peertype'])
            except:
                pass


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


class ProfileManager(object):
    """ Profile manager

    Each instance of this class represents a profile,
    which is a complete topology of a mesh / c/s network.
    """

    def __init__(self):
        """ Initialize peers list
        """
        self.peers = []

    def json_load_profile(self, profile_path):
        """ Load profile to JSON file

        Dumps each peer's __dict__ to JSON file.
        """
        self.peers = []
        Avalon.debug_info(f'Loading profile from: {profile_path}')
        with open(profile_path, 'rb') as profile:
            loaded_profiles = json.load(profile)
            profile.close()
        
        for p in loaded_profiles['peers']:
            peer = Peer()
            peer.load(p)
            if peer.private_key =='':
                peer.private_key = wg.genkey()
            pm.peers.append(peer)

    def json_dump(self):
        peers_dict = {}
        peers_dict['peers'] = []

        for peer in pm.peers:
            peers_dict['peers'].append(peer.__dict__)

        print(json.dumps(peers_dict, indent=2))

    def json_save_profile(self, profile_path):
        """ Save current profile to a JSON file
        """

        # If profile already exists (file or link), ask the user if
        # we should overwrite it.
        if os.path.isfile(profile_path) or os.path.islink(profile_path):
            if not Avalon.ask('File already exists. Overwrite?', True):
                Avalon.warning('Aborted saving profile')
                return 1

        # Abort if profile_path points to a directory
        if os.path.isdir(profile_path):
            Avalon.warning('Destination path is a directory')
            Avalon.warning('Aborted saving profile')
            return 1

        # Finally, write the profile into the destination file
        Avalon.debug_info(f'Writing profile to: {profile_path}')

        peers_dict = {}
        peers_dict['peers'] = []

        for peer in pm.peers:
            peers_dict['peers'].append(peer.__dict__)

        with open(profile_path, 'w') as profile:
            json.dump(peers_dict, profile, indent=4)
            profile.close()

    def new_profile(self):
        """ Create new profile and flush the peers list
        """

        # Warn the user before flushing configurations
        Avalon.warning('This will flush the currently loaded profile!')
        if len(self.peers) != 0:
            if not Avalon.ask('Continue?', False):
                return

        # Reset self.peers and start enrolling new peer data
        self.peers = []


def print_welcome():
    """ Print program name and legal information
    """
    print(f'WireGuard Mesh Configurator')


def print_peer_config(peer):
    """ Print the configuration of a specific peer

    Input takes one Peer object.
    """
    if peer.alias:
        Avalon.info(f'{peer.alias} information summary:')
    else:
        Avalon.info(f'{peer.address} information summary:')
    if peer.description:
        print(f'Description: {peer.description}')
    if peer.address:
        print(f'Address: {peer.address}')
    if peer.public_address:
        print(f'Public Address: {peer.public_address}')
    if peer.listen_port:
        print(f'Listen Port: {peer.listen_port}')
    print(f'Private Key: {peer.private_key}')
    if peer.keep_alive:
        print(f'Keep Alive: {peer.keep_alive}')
    # print(f'Preshared Key: {peer.preshared_key}')


def add_peer():
    """ Enroll a new peer

    Gets all the information needed to generate a
    new Peer class object.
    """

    peer = Peer()
    # Get peer tunnel address
    while True:
        peer.address = Avalon.gets('Address (leave empty if client only) [IP/CIDR]: ')
        if re.match('^(?:\d{1,3}\.){3}\d{1,3}/{1}(?:\d\d?)?$', address) is None:
            Avalon.error('Invalid address entered')
            Avalon.error('Please use CIDR notation (e.g. 10.0.0.0/8)')
            continue
        break

    # Get peer public IP address
    while True:
        peer.public_address = Avalon.gets('Public address (leave empty if client only) [IP|FQDN]: ')

        # Check if public_address is valid IP or FQDN
        valid_address = False
        if re.match('^(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?$', public_address) is not None:
            valid_address = True
        if re.match('(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', public_address) is not None:
            valid_address = True

        if not valid_address and public_address != '':  # field not required
            Avalon.error('Invalid public address address entered')
            Avalon.error('Please enter an IP address or FQDN')
            continue
        break

    # Get peer listening port
    peer.listen_port = Avalon.gets('Listen port (leave empty for client) [1-65535]: ')

    # Get peer private key
    peer.private_key = Avalon.gets('Private key (leave empty for auto generation): ')
    if private_key == '':
        private_key = wg.genkey()

    # Ask if this peer needs to be actively connected
    # if peer is behind NAT and needs to be accessed actively
    # PersistentKeepalive must be turned on (!= 0)
    peer.keep_alive = Avalon.ask('Keep alive?', False)

    """
    preshared_key = False
    if Avalon.ask('Use a preshared key?', True):
        preshared_key = Avalon.gets('Preshared Key (leave empty for auto generation): ')
        if preshared_key == '':
            preshared_key = wg.genpsk()
    peer = Peer(address, private_key, keep_alive, listen_port, preshared_key)
    """

    # Get peer alias
    peer.alias = Avalon.gets('Alias (optional): ')

    # Get peer description
    peer.description = Avalon.gets('Description (optional): ')

    # Create peer and append peer into the peers list
    pm.peers.append(peer)
    print_peer_config(peer)


def delete_peer(address):
    """ Delete a peer

    Delete a specific peer from the peer list.
    """
    for peer in pm.peers:
        if peer.address == address:
            pm.peers.remove(peer)

def fill_parameters():
    """
    PRIVATE_SUBNET_V4 - private IPv4 subnet configuration 10.8.0.0/24 by default
    PRIVATE_SUBNET_V6 - private IPv6 subnet configuration fd42:42:42::0/64 by default
    SERVER_PORT - public port for wireguard server, default is 51820
    """

    #sweep all peers for ip address
    pool = [
        ipaddress.IPv4Interface('192.168.195.1/32'),
        ipaddress.IPv4Interface('192.168.195.2/32'),
        ipaddress.IPv4Interface('192.168.195.4/32'),
        ipaddress.IPv4Interface('192.168.195.8/32'),
        ipaddress.IPv4Interface('192.168.195.16/32'),
        ipaddress.IPv4Interface('192.168.195.32/32'),
        ipaddress.IPv4Interface('192.168.195.64/32'),
        ipaddress.IPv4Interface('192.168.195.128/32')
    ]
    serverip = copy.deepcopy(pool)
    ipsix = ipaddress.IPv6Interface("fd42:42:42::0/64")+1
    clientip = ipaddress.IPv4Interface('192.168.195.1/32')

    for peer in pm.peers:
        if peer.peertype != PeerType.CLIENT:
            if peer.address == '':
                peer.address = str(pool.pop(0))
            if peer.listen_port == '':
                peer.listen_port = str(LISTEN_PORT)

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
            
def generate_configs_alt(output_path):

    Avalon.info("generate_configs_alt")

    preshared_pair = {}

    # servers
    for peer in pm.peers:
        if peer.peertype == PeerType.CLIENT:
            continue
        filename = f'{output_path}/{peer.alias}.conf'
        Avalon.debug_info(f'Generating configuration file for {filename}')
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
                config.write(f'AllowedIPs = {address}\n')
                # if p.public_address != '':
                #     config.write(f'Endpoint = {p.public_address}:{p.listen_port}\n')
                # if peer.keep_alive:
                #     config.write('PersistentKeepalive = 25\n')
                preshared = wg.genpsk()
                preshared_pair[(p.address, peer.address)] = preshared
                config.write(f'PresharedKey = {preshared}\n')

    # clients
    Avalon.info("generate_configs_alt")
    for peer in pm.peers:
        if peer.peertype == PeerType.SERVER:
            continue
        for p in pm.peers:
            if p.address == peer.address:
                continue
            if p.peertype == PeerType.CLIENT:
                continue
            filename = f'{output_path}/{prefix}-{p.alias}-{peer.alias}.conf';
            Avalon.debug_info(f'Generating configuration file for {filename}')
            with open(filename, 'w') as config:
                config.write('[Interface]\n')
                if peer.alias:
                    config.write(f'# Alias: {peer.alias}\n')
                config.write(f'PrivateKey = {peer.private_key}\n')
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
                config.write(f'AllowedIPs = 0.0.0.0/0,::/0\n')
                config.write(f'Endpoint = {p.public_address}:{p.listen_port}\n')
                if peer.keep_alive:
                    config.write('PersistentKeepalive = 25\n')
                preshared = preshared_pair[(peer.address, p.address)]
                config.write(f'PresharedKey = {preshared}\n')


def print_help():
    """ Print help messages
    """
    help_lines = [
        f'\n{Avalon.FM.BD}Commands are not case-sensitive{Avalon.FM.RST}',
        'Interactive  // launch interactive shell',
    ]
    for line in help_lines:
        print(line)

def auto(argv):
    savedata = argv[1]
    pm.json_load_profile(savedata)
    fill_parameters()
    pm.json_dump()


def command_interpreter(commands):
    """ WGC shell command interpreter

    This function interprets commands from CLI or
    the interactive shell, and passes the parameters
    to the corresponding functions.
    """
    try:
        # Try to guess what the user is saying
        possibilities = [s for s in COMMANDS if s.lower().startswith(commands[1])]
        if len(possibilities) == 1:
            commands[1] = possibilities[0]

        if commands[1].replace(' ', '') == '':
            result = 0
        elif commands[1].lower() == 'help':
            print_help()
            result = 0
        elif commands[1].lower() == 'showpeers':
            for peer in pm.peers:
                print_peer_config(peer)
            result = 0
        elif commands[1].lower() == 'jsonloadprofile':
            result = pm.json_load_profile(commands[2])
        elif commands[1].lower() == 'jsonsaveprofile':
            result = pm.json_save_profile(commands[2])
        elif commands[1].lower() == 'newprofile':
            result = pm.new_profile()
        elif commands[1].lower() == 'addpeer':
            result = add_peer()
        elif commands[1].lower() == 'deletepeer':
            result = delete_peer(commands[2])
        elif commands[1].lower() == 'generateconfigs':
            result = generate_configs_alt(commands[2])
        elif commands[1].lower() == 'exit' or commands[1].lower() == 'quit':
            Avalon.warning('Exiting')
            exit(0)
        elif len(possibilities) > 0:
            Avalon.warning(f'Ambiguous command \"{commands[1]}\"')
            print('Use \"Help\" command to list available commands')
            result = 1
        else:
            Avalon.error('Invalid command')
            print('Use \"Help\" command to list available commands')
            result = 1
        return result
    except IndexError:
        Avalon.error('Invalid arguments')
        print('Use \"Help\" command to list available commands')
        result = 0



def main():
    """ WireGuard Mesh Configurator main function

    This function controls the main flow of this program.
    """

    try:
        if sys.argv[1].lower() == 'help':
            print_help()
            exit(0)
    except IndexError:
        pass

    # Begin command interpreting
    try:
        startinteractive = False
        if sys.argv[1].lower() == 'interactive' or sys.argv[1].lower() == 'int':
            startinteractive = True
        elif os.path.isfile(sys.argv[1]):
            auto(sys.argv)
            startinteractive = True

        if startinteractive == True:
            print_welcome()
            # Set command completer
            completer = ShellCompleter(COMMANDS)
            readline.set_completer(completer.complete)
            readline.parse_and_bind('tab: complete')
            # Launch interactive trojan shell
            prompt = f'{Avalon.FM.BD}[WGC]> {Avalon.FM.RST}'
            while True:
                command_interpreter([''] + input(prompt).split(' '))
        else:
            # Return to shell with command return value
            exit(command_interpreter(sys.argv[0:]))

    except IndexError:
        Avalon.warning('No commands specified')
        print_help()
        exit(0)
    except (KeyboardInterrupt, EOFError):
        Avalon.warning('Exiting')
        exit(0)
    except Exception:
        Avalon.error('Exception caught')
        traceback.print_exc()
        exit(1)


if __name__ == '__main__':
    # Create global object for WireGuard handler
    wg = WireGuard()

    # Create global object for profile manager
    pm = ProfileManager()

    # Launch main function
    main()
