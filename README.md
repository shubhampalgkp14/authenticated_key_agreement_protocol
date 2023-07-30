# authenticated_key_agreement_protocol
Provably Secure and Lightweight Identity-Based Two-Party Authenticated Key Agreement Protocol for IIoT Environments.


# Project Title

With the significant development of the Internet,
Internet of Things (IoT) has become an emerging technology in
many industries. To support security and privacy in the Industrial
IoT environment, a user may interact with another user on the
Internet to share confidential information, which requires an authenticated
communication channel. To meet this demand, developed an identity-based two-party authenticated
key agreement (ID-2PAKA) protocol that allows two users to
communicate securely and share sensitive data across IoT-enabled
regions. 


## Documentation

[Documentation](https://crypto.stanford.edu/pbc/)
The PBC (Pairing-Based Cryptography) library is a free C library (released under the GNU Lesser General Public License) built on the GMP library that performs the mathematical operations underlying pairing-based cryptosystems.


## Installation

The PBC library needs the GMP library (https://gmplib.org/).
This build system has been tested and works on Linux and Mac OS X with a fink installation.
$ ./configure
$ make
$ make install
On Windows, the configure command requires a couple of options:
$ ./configure -disable-static -enable-shared
By default the library is installed in /usr/local/lib. On some systems, this may not be in the library
path. One way to fix this is to edit /etc/ld.so.conf and run ldconfig.


For speed and simplicity, I use simple.make during development. Naturally it is less portable.
$ make -f simple.make

Run pbc/pbc and type:
g := rnd(G1);
g;

h := rnd(G2);
h;

pairing(g,h);
    
