# SENG Netfilter Extension

## Overview
This project is a proof of concept to integrate the per-application policy enforcement of [SENG](https://github.com/sengsgx/sengsgx) directly into Netfilter/Xtables and iptables.
The integration allows to define a single Enclave subnetwork (rather than app-specific ones) and directly define per-application policies using a set of new SENG iptables rule specifiers.
In contrast to vanilla SENG, the extension is specifically tailored for Netfilter/iptables and therefore not compatible with other firewalls.

The repository is structured in the following way:
* `demo-app/` -- contains a demo application for communication with the SENG Netfilter module
* `include/` -- shared header files including the user-space API header (`seng_netfilter_api.h`)
* `iptables-extension` -- the SENG iptables extension library for adding SENG rule specifiers
* `seng-module` -- the SENG Netfilter/Xtables (Linux) kernel module
* `user-library` -- the user-space library for communcation with the netfilter module (used by the SENG Server)

## Documentation
The documentation consists of three parts: this README file, the Doxygen API documentation and the SENG research paper.
The Doxygen documentation requires the doxygen packet to be installed (`sudo apt install doxygen`) and can be accessed in the following way:
```
mkdir docs
cd docs
cmake ..
make seng_docs

# open html/index.html
```

### Research Project and USENIX Paper
This repository belongs to the [SENG research project](https://github.com/sengsgx/sengsgx) by Fabian Schwarz and Christian Rossow from the CISPA Helmholtz Center for Information Security.
The corresponding [research paper](https://publications.cispa.saarland/3119/1/seng-sec20.pdf) `"SENG, the SGX-Enforcing Network Gateway: Authorizing Communication from Shielded Clients"` will be published as part of the 29th USENIX Security Symposium (USENIX Security 20).
If you use SENG or the SENG Netfilter Extension in a project, please cite the paper using one of the formats provided by the export function of the [publication database](https://publications.cispa.saarland/3119/) or use the following bibtex entry:

```
@inproceedings{SENG2020,
    author = {Fabian Schwarz and Christian Rossow},
    title = {{SENG, the SGX-Enforcing Network Gateway: Authorizing Communication from Shielded Clients}},
    booktitle = {29th {USENIX} Security Symposium ({USENIX} Security 20)},
    year = {2020},
    address = {Boston, MA},
    publisher = {{USENIX} Association},
    month = aug,
    url = {https://publications.cispa.saarland/3119/}
}
```
We thank our student assistant Leon Trampert for his support on the prototype implementation of the SENG Netfilter Extension.

## How it works
The extension consists of three main components: (i) an iptables extension library (`libxt_seng.so`), (ii) a SENG netfilter module (`seng.ko`), and (iii) a user-space library for communication with the netfilter module (`libsengnetfilter.so`).
The iptables extension library (i) registers against iptables to provide new SENG rule specifiers for per-application policies.
The SENG netfilter module (ii) registers against the Netfilter subsystem and is responsible for handling the matching of network traffic against the new SENG rule specifiers.
The [SENG Server](https://github.com/sengsgx/sengsgx/tree/master/seng_server) uses the user-space library (iii) to inform the SENG module about newly registered or unregistered Enclave IPs and their associated metadata (incl. measurement, host IP and app category).
The SENG module stores the information in an internal hash table and uses it to resolve source/destination Enclave IPs to the respective metadata for performing the application-specific rule matching.
The communication between the user-space SENG-netfilter library and the SENG module is realised via a generic netlink channel.
The SENG-netfilter library deletes all conntrack entries associated with connections from/to an unregistered Enclave IP to prevent exploitation of stale entries on IP re-assignments.

## Building the SENG Netfilter Extension
### Dependencies
* SENG iptables Extension:
   ```
   sudo apt install libxtables-dev
   ```
* SENG Netfilter module and user-space library:
   ```
   sudo apt install libnl-genl-3-dev
   ```
   Note: dependencies for building a Linux kernel module (e.g., kernel header files) are also required.

### Compilation
1. SENG iptables Extension:
   ```
   cd iptables-extension
   make
   ```

2. SENG Netfilter/Xtables Module:
   ```
   cd seng-module
   make
   ```
   Notes:
   * tested under Ubuntu 16.04 / 18.04 / 20.04 LTS and Debian 10
   * tested with Linux kernel 4.15 / 4.19 / 5.0 / 5.4

3. There are 2 options to build the SENG-Netfilter user-space Library: separately or as part of the SENG Server [build process](https://github.com/sengsgx/sengsgx/tree/master/seng_server/README.md#build).
   * Separate Build:
      ```
      cd user-library
      mkdir build
      cd build
      cmake ..
      make
      ```
   * Combined Build: The compilation and integration of the SENG-Netfilter library is now part of the SENG Server build process.

4. Demo Application:
   ```
   cd demo-app
   mkdir build
   cd build
   cmake ..
   make
   ```

## Usage

### Preparation
1. Insert the SENG Netfilter module:
   ```
   cd seng-module
   sudo insmod seng.ko
   ```
2. Symlink the iptables extension to the xtables folder, s.t. iptables can find it:
   ```
   # on Ubuntu 16.04 LTS
   sudo ln -s $(pwd)/iptables-extension/libxt_seng.so /lib/xtables/

   # on Ubuntu 18.04 / 20.04 LTS and Debian 10
   sudo ln -s $(pwd)/iptables-extension/libxt_seng.so /usr/lib/x86_64-linux-gnu/xtables/
   ```

### How to use
Use `sudo iptables -m seng --help` to see the SENG rule specifiers for creating per-application policies based on the source/destination application, the resp. source/destination app category and/or the resp. untrusted host IP(s).
See the [SENG Server README](https://github.com/sengsgx/sengsgx/edit/master/seng_server/README.md) for instructions on how to run the SENG Server.
You have to run the server with the `-n` and `-d <database>` options to enable communication with the SENG Netfilter module.

### Sample iptables Rules
```
# Allow all demo Enclaves with given Measurement (mrenclave) to send to tcp/8391
sudo iptables -A INPUT -i tunFA --source 192.168.28.0/24 -p tcp --destination-port 8391 -m seng --src-app d9237809ab399aa541e42ad54146a2a1bde310dd7dc9fccc1e964dacf4c5c3b0 -j ACCEPT

# Block Enclave traffic from external hosts (traffic not from internal subnet)
sudo iptables -A INPUT -i tunFA --source 192.168.28.0/24 -m seng ! --src-host 10.0.0.0/8 -j DROP

# Allow trusted Browser enclaves to communicate to port 443
sudo iptables -A INPUT -i tunFA --source 192.168.28.0/24 -p tcp --destination-port 443 -m seng --src-cat Browser -j ACCEPT

# Allow communication from the Gateway to NGINX Enclaves
sudo iptables -A OUTPUT -o tunFA --destination 192.168.28.0/24 -p tcp --destination-port 4711 -m seng --dst-app d5876e37d31ad62d4eafd36997820b18fdea7b104a0e2d3f81873230be2af792 -j ACCEPT
```

### Cleanup
1. remove all SENG iptables rules via the respective `sudo iptables -D [...]` commands
2. flush the module database via `./seng_app -f`, or if used with the SENG Server, shut down the Server to cause a `flush_module()` call
3. remove module: `sudo rmmod seng`


## Component Details

### SENG iptables Extension Library
The SENG extension library registers against iptables and provides new rule specifiers via the seng module (`-m seng`).
All functionality is documented in `libxt_seng.c`.

Use `sudo iptables -m seng --help` for usage infos.

### SENG Netfilter/Xtables Module
The module consists of 3 parts to handle different things.

#### Matching
The matching functionality happens in `seng_mt()` in `xt_seng.c`. The function receives a packet to be matched and a rule.
Then the enclave metadata behind the source and destination IP addresses of the packet are looked up in the hash table.
The metadata (e.g., app measurement) is then matched against the rule specification.

#### Database
The database functionality is mainly hidden and documented in `xt_seng_metadb.h`.
These functions are used to add or delete items in the internal module database.

#### Netlink Channel
The netlink channel is used to receive enclave IP-to-metadata mappings from the user-space.
See the following section for details on the netlink communcation channel.

### SENG Netfilter user-space Library
The SENG Netfilter library provides a communication channel to the SENG module via a generic netlink channel.
The communcation channel allows to inform the SENG module about changes in the set of active Enclave IPs (register/unregister) and their associated metadata (e.g., app measurement, host IP).
In addition, a message type for flushing all entries in the SENG module database is provided.
The [SENG Server](https://github.com/sengsgx/sengsgx/tree/master/seng_server) uses the library to inform the SENG module whenever a new Enclave IP has been assigned or an existing Enclave has been shut down.
The SENG Server sends the Enclave IP together with the Enclave metadata (from the SENG Database) to the SENG module for the rule enforcement, including information about the shielded application (mrenclave), the app category, and the untrusted host IP on which the Enclave is running.

The user API of the library is documented in `seng_netfilter_api.h`.
The specific usage of the generic netlink socket is documented in `xt_seng_genl.h`.
See `seng_nl_recv_msg()` in `xt_seng_genl.c` for further details on the kernel-side of the commmunication channel.

### Demo Application
A demo app is provided (`app/`) which serves as a small working example of using the SENG-Netfilter API.
Use `./seng_app -h` for usage infos.
