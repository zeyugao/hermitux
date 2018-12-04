# HermiTux: a unikernel binary-compatible with Linux applications

For general information about HermiTux's design principles and implementation, please read the [paper](https://www.ssrg.ece.vt.edu/papers/vee2019.pdf). There are also various
[documents](https://github.com/ssrg-vt/hermitux/wiki/Documents) related to HermiTux listed in the
wiki.

The instruction that follows are for x86-64. We have basic support for an ARM64 embedded
board, more information in the [Wiki](https://github.com/ssrg-vt/hermitux/wiki/Aarch64-support).

We also have a [Slack channel](https://join.slack.com/t/hermitux/shared_invite/enQtOTM0MTE2MjgwNzM2LTRjZTMyMzYwOWU3MDFkNjJiZTA5ZmY2NDJhOGI5NDU3MjZjZjI1MWNlMGZiZGE2OTc5MzQxN2UyNmRhYWRlYmM) for HermiTux.

## Quick start
The easiest way to try HermiTux is with Docker:
```
docker pull olivierpierre/hermitux
docker run --privileged -it olivierpierre/hermitux
```
Then you can directly try to [run an application](https://github.com/ssrg-vt/hermitux#run-an-application).

## Prerequisites
<<<<<<< HEAD
  - Recommended system: Ubuntu 20.04/Debian 10 (GlibC support is not assured
  on other distributions)
    - See [here](https://github.com/ssrg-vt/hermitux/wiki/Old-Linux-distributions-requirements)
    for additional instructions regarding older distributions Ubuntu 18.04/16.04 or Debian 10/9 
  - Debian/Ubuntu packages:
```
sudo apt update
sudo apt install git build-essential cmake nasm apt-transport-https wget \
	libgmp-dev bsdmainutils libseccomp-dev libelf-dev
```

  - HermitCore	toolchain installed in `/opt/hermit`:
```
for dep in binutils-hermit_2.30.51-1_amd64.deb gcc-hermit_6.3.0-1_amd64.deb \
        libhermit_0.2.10_all.deb  newlib-hermit_2.4.0-1_amd64.deb; do \
    wget https://github.com/ssrg-vt/hermitux/releases/download/v1.0/$dep && \
    sudo dpkg -i $dep && \
    rm $dep;
done
```

## Build
=======
  - Recommended system: Debian 9 (GlibC support is not assured on newer 
    distributions)
  - `build-essential` debian package, plus [HermitCore prerequisites](https://github.com/RWTH-OS/HermitCore#requirements)
  - [HermitCore toolchain](https://github.com/RWTH-OS/HermitCore#hermitcore-cross-toolchain) installed in /opt/hermit (the one coming from the
  debian repositories mentionned in HermitCore GitHub repositories works fine, you might need to install the `apt-transport-https` debian package before downloading the toolchain packages)
    - You may also need to install a recent version of libmpfr to use the hermit toolchain on debian 9:https://www.mpfr.org/mpfr-current/
  - For fortran test application, you will need the `gfortran` debian package
  - Clang/LLVM to test this compiler, we recommend the following version to also test the obfuscation options: https://github.com/obfuscator-llvm/obfuscator

TODO here: put prerequisites for syscall rewriting and identification (cmake
with curl support)
>>>>>>> merge master

1. Clone the repository and retrieve the submodules
```bash
git clone https://github.com/ssrg-vt/hermitux
cd hermitux
git submodule init && git submodule update
```

2. Compile everything as follows:

```bash
make
```

<<<<<<< HEAD
## Run an application

Test an example application, for example NPB IS:
=======
2. Test an example application, for example NPB IS:
>>>>>>> merge master
```bash
cd apps/npb/is
# let's compile it as a static binary:
gcc *.c -o is -static
# let's launch it with HermiTux:
sudo HERMIT_ISLE=uhyve HERMIT_TUX=1 ../../../hermitux-kernel/prefix/bin/proxy \
	../../../hermitux-kernel/prefix/x86_64-hermit/extra/tests/hermitux is

# Now let's try with a dynamically linked program:
gcc *.c -o is-dyn
# We can run it by having hermitux execute the dynamic linux loader:
sudo HERMIT_ISLE=uhyve HERMIT_TUX=1 \
	../../../hermitux-kernel/prefix/bin/proxy \
	../../../hermitux-kernel/prefix/x86_64-hermit/extra/tests/hermitux \
	/lib64/ld-linux-x86-64.so.2 ./is-dyn
```

<<<<<<< HEAD
For more documentation about multiple topics, please see the wiki:
[https://github.com/ssrg-vt/hermitux/wiki](https://github.com/ssrg-vt/hermitux/wiki)

HermiTux logo made by [Mr Zozu](https://mrzozu.fr/).
=======
## Template Makefile
TODO describe here

## `hermit-run`
TODO describe here

## Networking

In order to enable network for the unikernel you need to create a _tap_
interface. Moreover, to get access to the unikernel from outside the host, you
need to bridge that interface with the physical interface of the host.

To that aim, use the following commands:

```bash
# Create the bridge br0
sudo ip link add br0 type bridge

# Add the physical interface to the bridge (change the physical interface
# name enp0s31f6 to the correct one on your machine)
sudo ip link set enp0s31f6 master br0

# At that point you will loose internet connection on the host, to get it back:
sudo dhclient br0

# Create the tap interface
sudo ip tuntap add tap100 mode tap

# Set the ip addr for the tap interface on your LAN (it will be the ip address
# of the unikernel, here I use 192.168.1.4
sudo ip addr add 192.168.1.4 broadcast 192.168.1.255 dev tap100

# Enable proxy ARP for the tap interface
sudo bash -c 'echo 1 > /proc/sys/net/ipv4/conf/tap100/proxy_arp'

# Enable the tap interface
sudo ip link set dev tap100 up

# Add it to the bridge
sudo ip link set tap100 master br0

# Next you can launch the unikernel, you need to correctly set the
# network-related environment variables:
HERMIT_NETIF=tap100 HERMIT_IP=192.168.1.4 HERMIT_GATEWAY=192.168.1.1

```

## Features

- Debugging: TODO describe here
- Profiling: TODO describe here
- secure container: TODO describe here
- Checkpoint/restart: TODO describe here
- ASLR: see apps/loader-pie

>>>>>>> merge master
