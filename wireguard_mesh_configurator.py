#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: Wireguard Mesh Configurator
Dev: K4YT3X
Date Created: October 10, 2018
Last Modified: October 17, 2018

Licensed under the GNU General Public License Version 3 (GNU GPL v3),
    available at: https://www.gnu.org/licenses/gpl-3.0.txt
(C) 2018 K4YT3X
"""
from avalon_framework import Avalon
import os
import pickle
import re
import readline
import subprocess
import sys
import traceback

VERSION = '1.1.5'
COMMANDS = [
    'Interactive',
    'ShowPeers',
    'LoadProfile',
    'SaveProfile',
    'NewProfile',
    'AddPeers',
    'GenerateConfigs',
    'Exit',
    'Quit',
]


class Utilities:
    """ Useful utilities

    This class contains a number of utility tools.
    """

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


class Peer:
    """ Peer class

    Each object of this class represents a peer in
    the wireguard mesh network.
    """

    def __init__(self, address, public_address, listen_port, private_key, keep_alive, preshared_key=False):
        self.address = address
        self.public_address = public_address
        self.listen_port = listen_port
        self.private_key = private_key
        self.keep_alive = keep_alive
        self.preshared_key = preshared_key


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

    def load_profile(self, profile_path):
        """ Load profile from a file

        Open the pickle file, deserialize the content and
        load it back into the profile manager.
        """
        Avalon.dbgInfo('Loading profile from: {}'.format(profile_path))
        with open(profile_path, 'rb') as profile:
            pm.peers = pickle.load(profile)
            profile.close()

    def save_profile(self, profile_path):
        """ Save current profile to a file

        Serializes the current profile with pickle
        and dumps it into a file.
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
        Avalon.dbgInfo('Writing profile to: {}'.format(profile_path))
        with open(profile_path, 'wb') as profile:
            pickle.dump(pm.peers, profile)
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
        get_peers_settings()

    def add_peers(self):
        """ Add new peers into the profile
        """
        get_peers_settings()


def print_welcome():
    """ Print program name and legal information
    """
    print('WireGuard Mesh Configurator {}'.format(VERSION))
    print('(C) 2018 K4YT3X')
    print('Licensed under GNU GPL v3')


def print_peer_config(peer):
    """ Print the configuration of a specific peer

    Input takes one Peer object.
    """
    Avalon.info('Peer {} information summary:'.format(peer.address))
    if peer.address:
        print('Address: {}'.format(peer.address))
    if peer.public_address:
        print('Public Address: {}'.format(peer.public_address))
    if peer.listen_port:
        print('Listen Port: {}'.format(peer.listen_port))
    print('Private Key: {}'.format(peer.private_key))
    if peer.keep_alive:
        print('Keep Alive: {}'.format(peer.keep_alive))
    # print('Preshared Key: {}'.format(peer.preshared_key))


def enroll_peer():
    """ Enroll a new peer

    Gets all the information needed to generate a
    new Peer class object.
    """

    # Get peer tunnel address
    while True:
        address = Avalon.gets('Address (leave empty if client only): ')
        result = re.match('^(?:\d{1,3}\.){3}\d{1,3}/{1}(?:\d\d?)?$', address)
        if result is None:
            Avalon.error('Invalid address entered')
            Avalon.error('Please use CIDR notation (e.g. 10.0.0.0/8)')
            continue
        break

    # Get peer public IP address
    while True:
        public_address = Avalon.gets('Public address (leave empty if client only): ')
        result = re.match('^(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?$', public_address)
        if result is None and public_address != '':  # field not required
            Avalon.error('Invalid IP address entered')
            continue
        break

    # Get peer listening port
    listen_port = Avalon.gets('Listen port (leave empty for client): ')

    # Get peer private key
    private_key = Avalon.gets('Private key (leave empty for auto generation): ')
    if private_key == '':
        private_key = wg.genkey()

    # Ask if this peer needs to be actively connected
    # if peer is behind NAT and needs to be accessed actively
    # PersistentKeepalive must be turned on (!= 0)
    keep_alive = Avalon.ask('Keep alive?', False)

    """
    preshared_key = False
    if Avalon.ask('Use a preshared key?', True):
        preshared_key = Avalon.gets('Preshared Key (leave empty for auto generation): ')
        if preshared_key == '':
            preshared_key = wg.genpsk()
    peer = Peer(address, private_key, keep_alive, listen_port, preshared_key)
    """
    peer = Peer(address, public_address, listen_port, private_key, keep_alive)
    pm.peers.append(peer)
    print_peer_config(peer)


def generate_configs(output_path):
    """ Generate configuration file for every peer

    This function reads the PEERS list, generates a
    configuration file for every peer, and export into
    the CONFIG_OUTPUT directory.
    """
    if len(pm.peers) == 0:
        Avalon.warning('No peers configured, exiting')
        exit(0)
    if len(pm.peers) == 1:
        Avalon.warning('Only one peer configured')

    Avalon.info('Generating configuration files')

    # Abort is destination is a file / link
    if os.path.isfile(output_path) or os.path.islink(output_path):
        Avalon.warning('Destination path is a file / link')
        Avalon.warning('Aborting configuration generation')
        return 1

    # Ask if user wants to create the output directory if it doesn't exist
    if not os.path.isdir(output_path):
        if Avalon.ask('Output directory doesn\'t exist. Create output directory?', True):
            os.mkdir(output_path)
        else:
            Avalon.warning('Aborting configuration generation')
            return 1

    # Iterate through all peers and generate configuration for each peer
    for peer in pm.peers:
        Avalon.dbgInfo('Generating configuration file for {}'.format(peer.address))
        with open('{}/{}.conf'.format(output_path, peer.address.split('/')[0]), 'w') as config:

            # Write Interface configuration
            config.write('[Interface]\n')
            config.write('PrivateKey = {}\n'.format(peer.private_key))
            if peer.address != '':
                config.write('Address = {}\n'.format(peer.address))
            if peer.listen_port != '':
                config.write('ListenPort = {}\n'.format(peer.listen_port))

            # Write peers' information
            for p in pm.peers:
                if p.address == peer.address:
                    # Skip if peer is self
                    continue
                config.write('\n[Peer]\n')
                print(p.private_key)
                config.write('PublicKey = {}\n'.format(wg.pubkey(p.private_key)))
                config.write('AllowedIPs = {}\n'.format(p.address))
                if p.public_address != '':
                    config.write('Endpoint = {}:{}\n'.format(p.public_address, p.listen_port))
                if peer.keep_alive:
                    config.write('PersistentKeepalive = 25\n')
                if p.preshared_key:
                    config.write('PresharedKey = {}\n'.format(p.preshared_key))


def get_peers_settings():
    """ Get all peers' settings

    Keep enrolling peers until the user aborts.
    """
    enroll_peer()
    while Avalon.ask('Add new peer?', True):
        enroll_peer()


def print_help():
    """ Print help messages
    """
    help_lines = [
        '\n{}Commands are not case-sensitive{}'.format(Avalon.FM.BD, Avalon.FM.RST),
        'Interactive  // launch interactive shell',
        'ShowPeers  // show all peer information',
        'LoadProfile [profile path]  // load profile from profile_path',
        'SaveProfile [profile path]  // save profile to profile_path',
        'NewProfile  // create new profile',
        'AddPeers  // add new peers into the current profile',
        'GenerateConfigs [output directory]  // generate configuration files',
        'Exit',
        'Quit',
        '',
    ]
    for line in help_lines:
        print(line)


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
        elif commands[1].lower() == 'loadprofile':
            result = pm.load_profile(commands[2])
        elif commands[1].lower() == 'saveprofile':
            result = pm.save_profile(commands[2])
        elif commands[1].lower() == 'newprofile':
            result = pm.new_profile()
        elif commands[1].lower() == 'addpeers':
            result = pm.add_peers()
        elif commands[1].lower() == 'generateconfigs':
            result = generate_configs(commands[2])
        elif commands[1].lower() == 'exit' or commands[1].lower() == 'quit':
            Avalon.warning('Exiting')
            exit(0)
        elif len(possibilities) > 0:
            Avalon.warning('Ambiguous command \"{}\"'.format(commands[1]))
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
        if sys.argv[1].lower() == 'interactive' or sys.argv[1].lower() == 'int':
            print_welcome()
            # Set command completer
            completer = ShellCompleter(COMMANDS)
            readline.set_completer(completer.complete)
            readline.parse_and_bind('tab: complete')
            # Launch interactive trojan shell
            prompt = '{}[WGC]> {}'.format(Avalon.FM.BD, Avalon.FM.RST)
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
