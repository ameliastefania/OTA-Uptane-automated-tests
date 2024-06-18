'''
#################################################################
######### Filename: mitmproxy_util.py 

######### Author: Amelia Andronescu

######### Date: 18/06/2024

######### Description:
A ‘MitmProxyWrapper‘ class instantiates mitmproxy and sets it as a global proxy for the
context that runs it, to help manipulate or observe network traffic 
as necessary for specific tests.
#################################################################
'''

import asyncio
import logging
import os
import random
import threading
import time
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

class MitmProxyWrapper(threading.Thread):
  def __init__(self, *, addons=[], listen_host='localhost', listen_port=None, client_cert=None):
    super().__init__()
    self.listen_host = listen_host
    self.listen_port = listen_port if listen_port is not None else random.randint(10000, 65535)
    self.addons = addons
    self.client_cert = client_cert
    self._event_loop = asyncio.new_event_loop()

  def run(self):
    logging.warning(f"mitmproxy started on {self.listen_host}:{self.listen_port}")
    asyncio.set_event_loop(self._event_loop)
    asyncio.run(self.async_run())

  def __enter__(self):
    self.start()
    os.environ["http_proxy"] = f"http://{self.listen_host}:{self.listen_port}"
    os.environ["https_proxy"] = f"http://{self.listen_host}:{self.listen_port}"
    time.sleep(0.2)
    return self

  def __exit__(self, *_):
    logging.warning("Shutting down mitmproxy...")
    asyncio.run(self.async_shutdown())
    self._event_loop.stop()
    del os.environ["http_proxy"]
    del os.environ["https_proxy"]
    self.join()
    logging.warning("mitmproxy has been shut down.")

  async def async_run(self):
    self.dm = DumpMaster(
    Options(
      listen_host=self.listen_host,
      listen_port=self.listen_port,
      http2=True,
      client_certs=self.client_cert if self.client_cert else None,
      ssl_insecure=True,
    ),
    with_termlog=False,
    with_dumper=False,
    )
    self.dm.addons.add(*self.addons)

    await self.dm.run()

  async def async_shutdown(self):
    if self.dm:
      self.dm.shutdown()