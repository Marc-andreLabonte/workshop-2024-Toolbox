
## Clone with submodules

git clone --recurse-submodules 

git submodule update --init --recursive

## Installation

### As root:

* apt install docker.io
* add your user to docker group (or invoke docker with sudo)

#### If docker would require a proxy on your computer:

```bash
mkdir /etc/systemd/system/docker.service.d/
cp http-proxy.conf /etc/systemd/system/docker.service.d/
systemctl daemon-reload
systemctl restart docker
```


### As user:

* Download Ghidra or similar tool
    - [https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.2_build/ghidra_11.0.2_PUBLIC_20240326.zip](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.2_build/ghidra_11.0.2_PUBLIC_20240326.zip)
