# mfv
mfv - Merkle Tree File Integrity Verifier. Proof that you securely   
published a web page, in combination with opentimestamps.org   

## For Administrators (Server Side)

As an administrator, deploy the integrity verification system  
by placing four critical files in your .well-known/mfv/ directory:  

1) merkle_metadata.json (generated via ' $ mfv hash /path/to/your/webroot)
--domain example.org' containing the Merkle tree structure and file hashes, and   

2) a signed timestamp document (e.g., merkle_metadata.json.ots) and  
your DNS record as dns.txt.ots  by uploading merkle_metadata.json and
dns.txt to opentimestamps.org. These files must remain accessible at:

https://yourdomain.org/.well-known/mfv/merkle_metadata.json     
https://yourdomain.org/.well-known/mfv/merkle_metadata.ots.  
https://yourdomain.org/.well-known/mfv/dns.txt      
https://yourdomain.org/.well-known/mfv/dns.txt.ots.  
 
Regularly update these four files after legitimate content changes  
using   mfv hash followed by creating a new timestamp.  

The DNS TXT record (_merkle.yourdomain.org IN TXT "merkle-root=YOUR_ROOT_HASH")  
is highly recommended as it provides additional verification convenience.

Example:

_merkle.example.org IN TXT "merkle-root=9f327e3d7c3c2d1a4b5c6d7e8f9a0b1c2d3e4f5a6"

3) If you use [yubicrypt](https://github.com/Ch1ffr3punk/yubicrypt) as a modern replacement for OpenPGP you may appreciate that   mfv supports the .well-known/yubicrypt/ directory where you can store yubicrypt
encryption certificates along with their respective .ots files.  

## For End Users (Verification Side)

To perform complete integrity verification, download the four files from the   
server's .well-known/mfv/ directory with the --download parameter.    

First, verify the timestamp at opentimestamps.org to confirm the data  
hasn't been backdated. Then use mfvc https://example.org to verify all  
current files match the hashes in the timestamp-validated metadata. 

This dual verification (cryptographic timestamps + Merkle tree) provides  
forensic-grade proof that website content hasn't been altered since the  
documented timestamp, creating an immutable audit trail suitable for legal  
or compliance requirements.

## A session output of the mfvc CLI client:
```
C:\Users\xxxxxxxxxx\Desktop>mfvc oc2mx.net --dns --yubicrypt --download --save
======================================================================
DOWNLOADING PROOF FILES (Mode: normal)
======================================================================
Server URL: https://oc2mx.net

Trying: https://oc2mx.net/.well-known/mfv/merkle_metadata.json ... ✓
Trying: https://oc2mx.net/.well-known/mfv/merkle_metadata.json.ots ... ✓
Trying: https://oc2mx.net/.well-known/mfv/dns.txt ... ✓
Trying: https://oc2mx.net/.well-known/mfv/dns.txt.ots ... ✓
----------------------------------------------------------------------
Proof Files Summary:
  Mode:             normal
  Files downloaded: 4
  Total size:       4.5 KiB
  Downloaded files:
    • merkle_metadata.json
    • merkle_metadata.json.ots
    • dns.txt
    • dns.txt.ots

======================================================================
DOWNLOADING yubicrypt CERTIFICATES
======================================================================
Downloading yubicrypt: .well-known/yubicrypt/ch1ffr3punk.crt ... ✓
Downloading yubicrypt: .well-known/yubicrypt/ch1ffr3punk.crt.ots ... ✓

yubicrypt Download Summary:
  Files downloaded: 2
  Total size:       1.8 KiB
  Downloaded files:
    • .well-known/yubicrypt/ch1ffr3punk.crt
    • .well-known/yubicrypt/ch1ffr3punk.crt.ots

  yubicrypt files downloaded: 2

======================================================================
CONTINUING WITH VERIFICATION (--dns/--save specified)
======================================================================
Starting STRICT verification of: https://oc2mx.net (Mode: normal)
URL Domain: oc2mx.net
STRICT MODE: No domain migration allowed
SECURITY NOTE: Only .well-known/yubicrypt/ is verified from .well-known/
               All other .well-known/ contents are excluded for security
----------------------------------------------------------------------
Querying DNS for Merkle hash...
DNS hash found: 6f8c047a4cfd27a6e927dee653f99eb304a4d3cf

Fetching metadata from server...
Metadata found.          Created: 2026-04-03 18:40:10 UTC (Unix ET: 1775241610)
Original file count:     13 (included)
Metadata domain:         oc2mx.net
Excluded files:          4

Collecting current files from server...

======================================================================
yubicrypt CERTIFICATE VERIFICATION
======================================================================
1 yubicrypt certificate(s) found with respective .ots file(s)

RIPEMD-160 hashes:
  1. bf828af51027ea9c740adba0406ab93d5c42fc95 (.well-known/yubicrypt/ch1ffr3punk.crt)
======================================================================
Calculating hashes and Merkle root...

Performing STRICT hash verification...
======================================================================
VERIFICATION SUCCESSFUL
======================================================================
Server URL:        https://oc2mx.net
Verification Date: 2026-04-04 08:55:10 UTC (Unix ET: 1775292910)
URL Domain:        oc2mx.net
Metadata Domain:   oc2mx.net
Excluded Files:    4

STATUS: All files unchanged and domain binding correct.
NOTE: 4 files excluded from verification (including most .well-known/)

DOMAIN VERIFICATION (STRICT MODE):
----------------------------------------------------------------------
  URL Domain:             oc2mx.net
  Metadata Domain:        oc2mx.net
  Domain Match:           Perfect

HASH VERIFICATION:
----------------------------------------------------------------------
  Original Root Hash:     6f8c047a4cfd27a6e927dee653f99eb304a4d3cf
  Calculated Merkle Root: 8ef4fda05034359846b1c0a712de05fe21e44d1d
  Calculated Final Hash:  6f8c047a4cfd27a6e927dee653f99eb304a4d3cf (with domain: oc2mx.net)
  Root Hash Match:        true
  Metadata Created:       2026-04-03 18:40:10 UTC (Unix ET: 1775241610)
  Original File Count:    13 (included)
  Current File Count:     13 (included)
  Excluded Paths:         4 (not verified)
  Original Total Size:    25.8 KiB
  Current Total Size:     25.8 KiB

DNS VERIFICATION:
----------------------------------------------------------------------
  DNS Hash:               6f8c047a4cfd27a6e927dee653f99eb304a4d3cf
  DNS Source:             dns
  DNS Query Time:         2026-04-04 08:55:10 UTC (Unix ET: 1775292910)
  DNS Hash Valid:         true
  DNS Hash Match:         true

UNCHANGED FILES: 13 files
======================================================================
  FINAL VERDICT: VERIFICATION SUCCESSFUL
  All files are intact and domain binding is correct.
  yubicrypt certificates are included in the integrity check.
======================================================================

Detailed verification report saved to: verification_oc2mx_net_20260404_085510.json

C:\Users\xxxxxxxxxx\Desktop>

```
## opentimestamps.org proof:
```
ch1ffr3punk.crt.ots 584 B
Stamped SHA256 hash: ef0519befb13e24074c1ed6ef9881e63cb8386a94fc98c97b74de9b1b9b89cea

ch1ffr3punk.crt 1.3 kB
SHA256: ef0519befb13e24074c1ed6ef9881e63cb8386a94fc98c97b74de9b1b9b89cea

SUCCESS!

merkle_metadata.json.ots 700 B
Stamped SHA256 hash: 1701c24d0d84581a811f50d21188e327ca6000eab948d0af976f8d7645770610

merkle_metadata.json 3.2 kB
SHA256: 1701c24d0d84581a811f50d21188e327ca6000eab948d0af976f8d7645770610

SUCCESS!

Bitcoin block 943540 attests existence as of 2026-04-03 CET

dns.txt.ots 595 B
Stamped SHA256 hash: cb1d69ccc812f269401cb1a441bc6901b0aa2e0ed1a358c179783fb2a52fd26d

dns.txt 81 B
SHA256: cb1d69ccc812f269401cb1a441bc6901b0aa2e0ed1a358c179783fb2a52fd26d

SUCCESS!

Bitcoin block 943540 attests existence as of 2026-04-03 CET
```

If you like mfv consider a small donation in crypto currencies
or buy me a coffee.  
```  
BTC: bc1qkluy2kj8ay64jjsk0wrfynp8gvjwet9926rdel
Nym: n1f0r6zzu5hgh4rprk2v2gqcyr0f5fr84zv69d3x 
XMR: 45TJx8ZHngM4GuNfYxRw7R7vRyFgfMVp862JqycMrPmyfTfJAYcQGEzT27wL1z5RG1b5XfRPJk97KeZr1svK8qES2z1uZrS  
```
<a href="https://www.buymeacoffee.com/Ch1ffr3punk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-yellow.png" alt="Buy Me A Coffee" height="41" width="174"></a>

Merkle Tree File Integrity Verifier is dedicated to Alice and Bob.
