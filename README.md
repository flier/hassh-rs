# hassh - A SSH fingerprinting library written in Rust

[![License: BSD 3-Clause License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![crates.io](https://img.shields.io/crates/v/hassh.svg)](https://crates.io/crates/hassh)
[![Build Status](https://travis-ci.org/flier/hassh-rs.svg?branch=master)](https://travis-ci.org/jabedude/hassh-rs)
[![Documentation](https://docs.rs/hassh/badge.svg)](https://docs.rs/hassh/)

This crate enables a consumer to fingerprint the [Key Exchange](https://tools.ietf.org/html/rfc4253#section-6.5) portion of a SSH handshake. It can hash SSH handshakes over IPv4 and IPv6. It heavily depends on the [ssh-parser](https://github.com/rusticata/ssh-parser) project from [Rusticata](https://github.com/rusticata).

"HASSH" is a network fingerprinting standard which can be used to identify specific Client and Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint.

See the original [HASSH](https://github.com/salesforce/hassh) project for more information.

## Example

Example of fingerprinting a packet capture file:

```rust
use hassh::pcap;

for hassh in pcap::open("test.pcap")? {
    println!("{:x}", hassh.client_hash());
}
```

Example of fingerprinting a live capture:

```rust
use hassh::live;

for hassh in live::capture("en0")? {
    println!("{:x}", hassh.server_hash());
}
```

See the [hassh](examples/hassh.rs) example for more information.

```bash
$ cargo run --example hassh -- -i en0

[+] Client SSH_MSG_KEXINIT detected
    [ 192.168.1.8:57278 -> 192.168.1.31:22 ]
        [-] Identification String: SSH-2.0-OpenSSH_8.1
        [-] hassh: ec7378c1a92f5a8dde7e8b7a1ddf33d1
        [-] hassh Algorithms: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com,zlib

[+] Server SSH_MSG_KEXINIT detected
    [ 192.168.1.31:22 -> 192.168.1.8:57278 ]
        [-] Identification String: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
        [-] hasshServer: 3ccd1778a76049721c71ad7d2bf62bbc
        [-] hasshServer Algorithms: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com
```

## Reference

* [RFC4253 - The Secure Shell (SSH) Transport Layer Protocol](https://tools.ietf.org/html/rfc4253)
* ["HASSH" - a Profiling Method for SSH Clients and Servers](https://github.com/salesforce/hassh)

## Credits:
hassh and hasshServer were conceived and developed by [Ben Reardon](mailto:breardon@salesforce.com) ([@benreardon](https://twitter.com/@benreardon)) within the Detection Cloud Team at Salesforce, with inspiration and contributions from [Adel Karimi](mailto:akarimishiraz@salesforce.com) (@0x4d31) and the [JA3 crew](https://github.com/salesforce/ja3/)  crew:[John B. Althouse](mailto:jalthouse@salesforce.com)  , [Jeff Atkinson](mailto:jatkinson@salesforce.com) and [Josh Atkins](mailto:j.atkins@salesforce.com)
