'''
#################################################################
######### Filename: ota_util.py 

######### Author: Amelia Andronescu

######### Date: 18/06/2024

######### Description:
Helper functions for automating miscellaneous tasks needed in OTA framework e.g
- registration of mock device
- clearing mock device
- generate update package
- install update 
- generate fake certificates
#################################################################
'''

import logging
import os
import subprocess

OTA_PATH = "/root/Documents/ota-community-edition"
OTA_DEVICES_PATH = f"{OTA_PATH}/ota-ce-gen/devices"
TARGETS_PATH = "/tmp/targets.toml"

def clear_devices():
  devices = os.listdir(OTA_DEVICES_PATH)
  for device_id in devices:
    if "ca." in device_id:
      continue

    logging.warning(f"Clearing device {device_id}")
    subprocess.check_output(["rm", "-rf", f"{OTA_DEVICES_PATH}/{device_id}"])

def cert_path(device_id):
  os.system(f"cd {OTA_DEVICES_PATH}/{device_id}; cat client.pem pkey.pem ca.pem > chain.pem")

  return f"{OTA_DEVICES_PATH}/{device_id}/chain.pem"

def gen_fake_cert(device_id):
  os.system(f"openssl ecparam -name prime256v1 -genkey -noout -out /tmp/fakekey.pem")
  os.system(f"openssl req -new -key /tmp/fakekey.pem -out /tmp/fakecsr.pem -subj \"/CN={device_id}\"")
  os.system(f"openssl x509 -req -days 365 -in /tmp/fakecsr.pem -signkey /tmp/fakekey.pem -out /tmp/fakecert.pem")
  os.system(f"cat /tmp/fakekey.pem /tmp/fakecert.pem > /tmp/fakecert2.pem")

  return "/tmp/fakecert2.pem"

def gen_device():
  out = subprocess.check_output(f"{OTA_PATH}/scripts/gen-device.sh", stderr=subprocess.DEVNULL)
  device_id = out.split(b"\n")[-1].decode("utf-8").strip('"')
  logging.warning(f"Generated device: {device_id}")

  # subprocess.check_output(["bash", "-c", f"sed -i 's/ota-ce-device/{device_id}/g' {OTA_DEVICES_PATH}/{device_id}/config.toml"])
  run_aktualizr(device_id)
  return device_id

def gen_and_run_update(device_id, package_name="mypkg", package_version="0.0.2", package_path="/tmp/randfile", package_size="100"):
  gen_update(device_id, package_name, package_version, package_path, package_size)
  return run_aktualizr(device_id)

def run_aktualizr(device_id):
  device_path = f"{OTA_DEVICES_PATH}/{device_id}"
  return subprocess.check_output(['bash', '-c', f'cd {device_path}; aktualizr --run-mode=once --config=config.toml 2>&1'])

def gen_update(device_id, package_name="mypkg", package_version="0.0.2", package_path="/tmp/randfile", package_size="100"):
  subprocess.check_output(['bash', '-c', f'dd if=/dev/urandom of={package_path} bs=1 count={package_size}'])

  subprocess.check_output([
    'bash',
    '-c',
    f'ota package add -n {package_name} -v {package_version} --path {package_path} --binary --hardware ota-ce-device'
  ])

  hsh = subprocess.check_output(["bash", "-c", f"sha256sum {package_path}"]).decode().split(" ")[0]

  tpl = f"""
[ota-ce-device.to]
name = "{package_name}"
version = "{package_version}"
length = {package_size}
hash = "{hsh}"
method = "sha256"
target_format = "binary"
generate_diff = true
"""

  with open(TARGETS_PATH, "w") as g:
      g.write(tpl)

  update_data = subprocess.check_output(["bash", "-c", f"ota update create -t {TARGETS_PATH}"])
  update_id = update_data.decode().strip('"')

  launch_cmd = f"ota update launch --update \"{update_id}\" --device \"{device_id}\""

  return subprocess.check_output(["bash", "-c", launch_cmd])

def installation_successful(output):
  return "Device has been successfully installed" in output.decode()
