# OTA Uptane automated tests

Test branches:
* Client - aktualizr: https://github.com/advancedtelematic/aktualizr, commit ‘fc9c5f5‘
* Server - ota-community-edition (monolith version): https://github.com/uptane/ota-community-edition, branch: ‘v2‘, commit ‘3d60bb9‘

The following OTA Uptane test cases are implemented:
1. Installation of a regular update
2. Server-side verification of the client certificate
   - no client certificate
   - fabricated cert
3. Certificate pinning (client-side verification of server certificates)
4. Different software update for existing version
5. Rollback update 
6. Malicious update through MitM
   - endless data update
   - tampered update
7. TLS downgrade
   - drop packet (TLS handshake packet)
   - modified packet
   - malformed packet


