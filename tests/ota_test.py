'''
#################################################################
######### Filename: ota_test.py 

######### Author: Amelia Andronescu

######### Date: 18/06/2024

######### Description:
Automated test cases for OTA Uptane reference implementation
#################################################################
'''
import pytest

from mitmproxy_util import *
from ota_util import *

PACKAGE_DIFFERENT_SIZE = "test_update_different_size"

class TestAddon:
  def response(self, flow):
    if f"/repo/targets/{PACKAGE_DIFFERENT_SIZE}" in flow.request.pretty_url:
      flow.response.content = b"invalid"

@pytest.fixture
def ota_device():
  device = gen_device()
  with MitmProxyWrapper(client_cert=cert_path(device), addons=[TestAddon()]):
    yield device
  clear_devices()

@pytest.fixture
def ota_device_without_cert():
  device = gen_device()
  with MitmProxyWrapper(client_cert=None):
    yield device
  clear_devices()

'''
#################################################################
######### Test case 
######### Name: Server-side verification of the client certificate

######### Author: Amelia Andronescu

######### Date: 18/06/2024

######### Description:
Test if the server accepts connections from 
an unauthenticated client (no client certificate is sent to the server)
#################################################################
'''
def test_mitm_no_client_cert(ota_device_without_cert):
  data = run_aktualizr(ota_device_without_cert)

  assert b"400 No required SSL certificate was sent" in data


'''
#################################################################
######### Test case
######### Name: Certificate pinning (client-side verification of server certificates)

######### Author: Amelia Andronescu

######### Date: 18/06/2024

######### Description
Test if certificate pinning is in place
Certificate pinning is a method of association a host to their expected X509 cert
#################################################################
'''
def test_mitm_with_client_cert(ota_device):
  data = run_aktualizr(ota_device)

  assert b"Certificate verify failed: self-signed certificate in certificate chain" not in data
  assert b"No new updates found" in data


'''
#################################################################
######### Test case
######### Name: Server-side verification of the client certificate

######### Author: Amelia Andronescu

######### Date: 18/06/2024

######### Description
Test if a fabricated certificate could mislead the
server into authenticating the client.

######### Steps
1. Generate a fake, self-signed client certificate using the Common Name (CN) 
and issuer details from the legitimate certificate.
2. Attempt to use the fabricated certificate to authenticate 
with the server
#################################################################
'''
def test_mitm_with_fake_cert():
  device = gen_device()
  cert_path = gen_fake_cert(device)

  with MitmProxyWrapper(client_cert=cert_path):
    data = run_aktualizr(device)

  clear_devices()
  assert b"400 The SSL certificate error" in data


'''
#################################################################
######### Test case
######### Name: Installation of a Regular update 

######### Author: Amelia Andronescu

######### Date: 18/06/2024

######### Description:
Check the successful installation of a regular update 
#################################################################
'''
def test_regular_update(ota_device):
  data = gen_and_run_update(ota_device)
  assert b"Installing package was successful" in data

'''
#################################################################
######### Test case
######### Name: Different software update for existing version 

######### Author: Amelia Andronescu

######### Date: 18/06/2024

######### Description:
- Test status for the attempt of installation a software update package 
which has the same version number as an existing package but contains different contents
- Check capability of launching other updates if installation fails
#################################################################
'''
def test_update_same_version_different_content(ota_device):
  package_name = "test_update_same_version_different_content"

  initial_update = gen_and_run_update(ota_device, package_name=package_name, package_version="1.0.0")
  assert b"Installing package was successful" in initial_update

  new_update = gen_and_run_update(ota_device, package_name=package_name, package_version="1.0.0")
  assert b"Inconsistency between Director metadata and available ECUs: Director Target filename matches currently installed version, but content differs." in new_update

'''
#################################################################
######### Test case
######### Name: Rollback update 

######### Author: Amelia Andronescu

######### Date: 18/06/2024

######### Description:
Test if the system accepts to reinstall an older software version

######### Steps:
  1. Create package 0.0.2: Initially, a package versioned 0.0.2 was created.
  2. Launch update for package 0.0.2: this version was installed on a mock device.
  3. Create package 0.0.3: Afterwards, a newer version, package 0.0.3 was created.
  4. Launch update for package 0.0.3: this newer version was installed successfully.
  5. Relaunch update for package 0.0.2: Finally, an attempt was made to reinstall the
  older package 0.0.2, while the device had the newer 0.0.3 version.

#################################################################
'''
def test_update_rollback(ota_device):
  initial_update = gen_and_run_update(ota_device, package_name="test_update_rollback", package_version="0.0.2")
  assert b"Installing package was successful" in initial_update

  new_update = gen_and_run_update(ota_device, package_name="test_update_rollback", package_version="0.0.3")
  assert b"Installing package was successful" in new_update

  rollback_update = gen_and_run_update(ota_device, package_name="test_update_rollback", package_version="0.0.2")
  assert b"Installing package was successful" in rollback_update

'''
#################################################################
######### Test case
######### Name: Malicious update through MitM 

######### Author: Amelia Andronescu

######### Date: 18/06/2024

######### Description:
Test if a malicious update can be installed in the case of a man-in-the-middle attack. 
There are 2 scenarios tested:

- tampered update: The package content is altered in such a way 
  that its size differs from the original size.

- endless data update: An intercepted package is replaced with a significantly larger file (1GB
in size) to test the system stability for large updates.

######### Steps:

#################################################################
'''
def test_update_different_size(ota_device):
  update = gen_update(ota_device, package_name=PACKAGE_DIFFERENT_SIZE)

  data = run_aktualizr(ota_device)

  assert b"Error downloading image: The target\'s calculated hash did not match the hash in the metadata." in data
  