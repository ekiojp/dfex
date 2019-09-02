# DFEX

## DNS File EXfiltration

Data exfiltration is a common technique used for post-exploitation, DNS is one of the most common protocols through firewalls.
We take the opportunity to build a unique protocol for transferring files across the network.

Existing tools have some limitations and NG Firewalls are getting a bit "smarter", we have been obliged to explore new combinations of tactics to bypass these.
Using the good old fashion "HIPS" (Hidden In Plain Sigh) tricks to push files out

----

## Installation

### Client
```
apt-get install -y virtualenv python3 python3-pip git
git clone https://github.com/secdev/scapy
cd scapy
sudo python setup.py install && cd .. && sudo rm -rf scapy
```

```
virtualenv -p python3 dfex-client
cd dfex-client
source ./bin/activate
```

```
git clone https://github.com/ekiojp/dfex
cd dfex
pip3 -r requirements_client.txt install
```

### Server
```
apt-get install -y virtualenv python3 python3-pip git
git clone https://github.com/secdev/scapy
cd scapy
sudo python setup.py install && cd .. && sudo rm -rf scapy
```

```
virtualenv -p python3 dfex-server
cd dfex-server
source ./bin/activate
```

```
git clone https://github.com/ekiojp/dfex
cd dfex
pip3 -r requirements_server.txt install
```

----

## Usage

[Client](https://github.com/ekiojp/dfex/wiki/DFEX-Client)

[Server](https://github.com/ekiojp/dfex/wiki/DFEX-Server)

----

# Presentations

### Video
[HITB GSEC (Aug 2019)](https://youtu.be/tm2dyKGVNko?t=7493)
### Slides
[HITB GSEC (Aug 2019)](https://speakerdeck.com/ekio_jp/dfex-dns-file-exfiltration)
[HITB GSEC (Aug 2019)](https://gsec.hitb.org/materials/sg2019/D2%20COMMSEC%20-%20DFEX%20%e2%80%93%20DNS%20File%20EXfiltration%20-%20Emilio%20Couto.pdf)

----

# ToDo

- [ ] DDFEX - Distributed DNS File Exfiltration
- [ ] Make the code nicer

----

# Disclaimer

The tool is provided for educational, research or testing purposes.<br>
Using this tool against network/systems without prior permission is illegal.<br>
The author is not liable for any damages from misuse of this tool, techniques or code.

----

# Author

Emilio / [@ekio_jp](https://twitter.com/ekio_jp)

----

# Licence

Please see [LICENSE](https://github.com/ekiojp/dfex/blob/master/LICENSE).
