# mfv
mfv - Merkle Tree File Integrity Verifier. Proof that you securely   
published a web page, in combination with opentimestamps.org   

## For Administrators (Server Side)

As an administrator, deploy the integrity verification system  
by placing four critical files in your .well-known/mfv/ directory:  

1) merkle_metadata.json (generated via mfv hash /path/to/your/webroot) --domain example.org   
containing the Merkle tree structure and file hashes, and  

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
C:\Users\xxxxxxxxxxxx\Desktop>mfvc oc2mx.net --dns
Starting remote verification of: https://oc2mx.net
Domain for DNS lookup: oc2mx.net
----------------------------------------------------------------------
Querying DNS for Merkle hash...
DNS hash found: 0d84c30c710d662d76b7c80269378df10702aa1d

Fetching metadata from server...
Metadata found. Created: 2025-12-04 19:46:34 UTC (Unix: 1764877594)
Original file count: 8 (included)
Excluded files: 2 (e.g., .well-known/acme-challenge/test.txt, .well-known/test.txt)

Collecting current files from server...
Calculating hashes and Merkle root...
======================================================================
REMOTE MERKLE TREE VERIFICATION RESULT
======================================================================
Server URL:       https://oc2mx.net
Verification Date: 2025-12-04 21:39:22 UTC (Unix: 1764884362)
Domain:           oc2mx.net
Excluded Files:   2 (e.g., .well-known/, .git/)

STATUS: Folder is UNCHANGED. All included files are identical.
NOTE: 2 files were excluded from verification (.well-known/, .git/, etc.)

COMPARISON RESULTS:
----------------------------------------------------------------------
  Original Root Hash:    0d84c30c710d662d76b7c80269378df10702aa1d
  Calculated Root Hash:  0d84c30c710d662d76b7c80269378df10702aa1d
  Root Hash Match:       true
  Metadata Created:      2025-12-04 19:46:34 UTC (Unix: 1764877594)
  Original File Count:   8 (included)
  Current File Count:    8 (included)
  Excluded Paths:        2 (not verified)
    - .well-known/acme-challenge/test.txt
    - .well-known/test.txt
  Original Total Size:   22.1 KiB (included files)
  Current Total Size:    22.1 KiB (included files)

DNS VERIFICATION:
----------------------------------------------------------------------
  DNS Hash:             0d84c30c710d662d76b7c80269378df10702aa1d
  DNS Source:           dns
  DNS Query Time:       2025-12-04 21:39:22 UTC (Unix: 1764884362)
  DNS Hash Valid:       true
  DNS Hash Match:       true

UNCHANGED FILES: 8 files (included)
  - ae.html
  - index.html
  - index.html.bak
  - me.ico
  - nt.html
  - oc.html
  - redball.gif
  - about.html
======================================================================
```
## opentimestamps.org proof:
```
merkle_metadata.json.ots 479 B
Stamped SHA256 hash: c7e2a9b7c17e1466e53734c8f5089657bebaf7082e73c995b2ab1cf2f0b0c925

merkle_metadata.json 2.0 kB
SHA256: c7e2a9b7c17e1466e53734c8f5089657bebaf7082e73c995b2ab1cf2f0b0c925

SUCCESS!

Bitcoin block 926445 attests existence as of 2025-12-04 CET

dns.txt.ots 514 B
Stamped SHA256 hash: a115060e1295b1eb5592487ad74db801b7737610c263b4e271217b82b8bd7b27

dns.txt 81 B
SHA256: a115060e1295b1eb5592487ad74db801b7737610c263b4e271217b82b8bd7b27

SUCCESS!

Bitcoin block 926445 attests existence as of 2025-12-04 CET
```

If you like mfv consider a small donation in crypto currencies
or buy me a coffee.  
```  
BTC: bc1qhgek8p5qcwz7r6502y8tvenkpsw9w5yafhatxk 
Nym: n1yql04xjhmlhfkjsk8x8g7fynm27xzvnk23wfys  
XMR: 45TJx8ZHngM4GuNfYxRw7R7vRyFgfMVp862JqycMrPmyfTfJAYcQGEzT27wL1z5RG1b5XfRPJk97KeZr1svK8qES2z1uZrS
```
<a href="https://www.buymeacoffee.com/Ch1ffr3punk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-yellow.png" alt="Buy Me A Coffee" height="41" width="174"></a>

Merkle Tree File Integrity Verifier is dedicated to Alice and Bob.
