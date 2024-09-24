"""rpyc IDA server"""

from __future__ import print_function

from rpyc.utils.server import OneShotServer
from rpyc.core import SlaveService
import concurrent

def serve_threaded(hostname="localhost", port=4455):
    """This will run a rpyc server in IDA, so a custom script client will be
    able to access IDA api.
    WARNING: IDA will be locked until the client script terminates.
    """

    print('Running server')
    server = OneShotServer(SlaveService, hostname=hostname,
                           port=port, reuse_addr=True, ipv6=False,
                           authenticator=None,
                           auto_register=False)
    server.logger.quiet = False

    return server.start()

def main():
    print("Start thread running")
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    pool.submit(serve_threaded)
    pool.shutdown(wait=True)
    print("Main thread continuing to run")

def worker():
    print("Worker thread running")

def PLUGIN_ENTRY_SORDA():
    try:
        serve_threaded()
    except:
        print("WARNING: setup_RPyc_Server script - NO serve_threaded from PLUGIN_ENTRY_SORDA!")
        pass

if __name__ == "__main__":

    try:
       main()
    except:
       print("WARNING: setup_RPyc_Server script - no main()")
       pass

    try:
       serve_threaded()
    except:
       print("WARNING: setup_RPyc_Server script - no serve_threaded()")
       pass

    try:
       import pydevd
       pydevd.settrace(host='localhost', port=51234, stdoutToServer=True, stderrToServer=True)
    except:
       print("exception caught and not handled!")
       pass

try:
   pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
 
   pool.submit(worker)
   pool.submit(worker)
 
   pool.shutdown(wait=True)
except:
   print("WARNING: setup_RPyc_Server script - starting code threw exception!")
   pass

print("Main thread continuing to run")
