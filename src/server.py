"""
-------------------------------------------------------------------------------

    Written by Thomas Munzer (tmunzer@juniper.net)
    Github repository: https://github.com/tmunzer/websocket_nac/

    This script is licensed under the MIT License.

-------------------------------------------------------------------------------
Python script to send RADIUS Accounting and/or Syslog messages based on Mist
client stats.
This script is opening a Websocket with the Mist Cloud and subscribe to the
client stats channel. This is allowing the Mist Cloud to stream the data in
real time.

-------
Current limitations:
This script can currently only subscribe for a single Mist Site Websocket.


-------
Requirements:
mistapi: https://pypi.org/project/mistapi/
websocket-client==0.44.0
pyrad

-------
Usage:
This script can be run as is (without parameters), or with the options below.
If no options are defined, or if options are missing, the missing options will
be asked by the script or the default values will be used.

It is recomended to use an environment file to store the required information
to request the Mist Cloud (see https://pypi.org/project/mistapi/ for more
information about the available parameters).

-------
Script Parameters:
-h, --help                  display this help

--ppsk_sync_org             Enable Mist Org PPSK synchronisation. 
                            Used to set the client username with the PPSK name
--ppsk_sync_sites           Enable Mist Sites PPSK synchronisation. 
                            Used to set the client username with the PPSK name
--ppsk_sync_interval=       Interval between PPSK synchronisations,
                            in secondes
                            default is 3600

--radius_server=            RADIUS Server IP Address where to send the Accounting
                            messages to
                            Setting this parameter is enabling RADIUS Accounting
--radius_port=              RADIUS Server Port where to send the Accounting
                            messages to
                            Default is 1813
--radius_secret=            RADIUS shared secret
                            default is "secret"

--syslog_server=            SYSLOG Server IP Address where to send the Accounting
                            messages to
                            Setting this parameter is enabling SYSLOG Accounting
--syslog_port=              RADIUS Server Port where to send the Accounting
                            SYSLOG to
                            Default is 514

--interim_acct_interval=    Interval between each ACCT INTERIM Message, in
                            seconds. 0 to disable ACCT INTERIM Messages.
                            Default is 60

--client_timeout=           Duration before marking a client as disconnected if Mist
                            is no more sending update, in seconds.
                            Once a client is marked as disconnected, an ACCT Stop 
                            message will be sent and the client data will be removed
                            minimum: 120
                            maximum: 3600
                            default: 120

-l, --log_file=             define the filepath/filename where to write the logs
                            default is "./script.log"
-e, --env=                  define the env file to use (see mistapi env file documentation
                            here: https://pypi.org/project/mistapi/)
                            default is "~/.mist_env"

-------
Examples:
python3 ./acct_server.py
python3 ./acct_server.py  --ppsk_sync_org --syslog_server=10.3.20.16
"""

import os
import sys
import json
import getopt
import threading
import logging.handlers
from time import sleep
from dotenv import load_dotenv
import websocket  # websocket-client==0.44.0
from mist_orchestrator import MistOrcherstator
from mist_client import MistClient
from mist_acct_syslog import SyslogAcct
from mist_acct_radius import RadiusAcct

ENV_FILE = "~/.mist_env"
# Can be save in the env file
MIST_HOST = "api.mist.com"
MIST_APITOKEN = ""
MIST_ORG_ID = ""
MIST_SITE_ID = ""
# PPSK SYNC
PPSK_SYNC_ORG = False
PPSK_SYNC_SITES = False
PPSK_SYNC_INTERVAL = 3600

# RADIUS Server connection parameters
RADIUS_ENABLED = False
RADIUS_SERVER = "127.0.0.1"
RADIUS_PORT = 1813
RADIUS_SECRET = b"secret"
# SYSLOG Server connection parameters
SYSLOG_ENABLED = False
SYSLOG_SERVER = "127.0.0.1"
SYSLOG_PORT = 514
# SYSLOG Update parameters
INTERIM_ACCT_INTERVAL = 60  # 0 to disable
CLIENT_TIMEOUT = 120  # minimum: 120, maximum: 3600, default: 120


###############################################################################
## WEBSOCEKET
class MistSocket:
    def __init__(self) -> None:
        self.mist_orchestrator = MistOrcherstator(INTERIM_ACCT_INTERVAL, CLIENT_TIMEOUT)
        self.syslog_acct = SyslogAcct(SYSLOG_ENABLED, SYSLOG_SERVER, SYSLOG_PORT)
        self.radius_acct = RadiusAcct(RADIUS_ENABLED, RADIUS_SERVER, RADIUS_PORT, RADIUS_SECRET)
        
        mist_host, mist_apitoken, self.mist_org_id, self.mist_site_id = _load_env(
        ENV_FILE, MIST_HOST, MIST_APITOKEN, MIST_ORG_ID, MIST_SITE_ID
        )
        mist_apitoken = mist_apitoken.split(",")[0]
        # host for websocket is api-ws.mist.com, so replacing "api." or "manage."
        # with "api-ws." if not the right host
        if mist_host.startswith("api."):
            mist_ws_host = mist_host.replace("api.", "api-ws.")
        elif MIST_HOST.startswith("manage."):
            mist_ws_host = mist_host.replace("manage.", "api-ws.")
        print(f"MIST_HOST     : {mist_host}")
        print(f"MIST_WS_HOST  : {mist_ws_host}")
        print(f"MIST_APITOKEN : {mist_apitoken[:6]}...{mist_apitoken[-6:]}")
        print(f"MIST_ORG_ID   : {self.mist_org_id}")
        print(f"MIST_SITE_ID  : {self.mist_site_id}")

        self.mist_orchestrator.set_psk_sync(
            mist_host,
            mist_apitoken,
            self.mist_org_id,
            PPSK_SYNC_ORG,
            PPSK_SYNC_SITES,
            PPSK_SYNC_INTERVAL
        )
        # Create and Start the Websocket in a Thread
        self.ws = websocket.WebSocketApp(
                    f"wss://{mist_ws_host}/api-ws/v1/stream",
                    header={"Authorization": f"Token {mist_apitoken}"},
                    on_message = lambda ws,msg: self.on_message(ws, msg),
                    on_error   = lambda ws,msg: self.on_error(ws, msg),
                    on_close   = lambda ws:     self.on_close(ws),
                    on_open    = lambda ws:     self.on_open(ws)
        )
        self.wst = threading.Thread(target=self.ws.run_forever)
        self.wst.daemon = True

        while True:
            self.start_ws()
        
    def start_ws(self, conn_timeout:int=5):
        """
        start the websocket, wait for the connection to establish, and start the infinite
        loop to process the update functions
        """
        self.wst.start()
        sleep(1)
        while not self.ws.sock.connected and conn_timeout:
            conn_timeout -= 1
            sleep(1)

        # Start the loop to check client udpates/timeouts
        while self.ws.sock.connected:
            sleep(1)
            interim_data = self.mist_orchestrator.chron()
            for entry in interim_data.get("stop", []):
                self._acct_stop(entry)
            for entry in interim_data.get("update",[]):
                self._acct_update(entry)


    def _acct_start(self, client:MistClient):
        self.syslog_acct.start(client)
        self.radius_acct.start(client)
        client.update_last_sent()

    def _acct_stop(self, client:MistClient):
        self.syslog_acct.stop(client)
        self.radius_acct.stop(client)
        self.mist_orchestrator.delete_client(client.mac)

    def _acct_update(self, client:MistClient):
        self.syslog_acct.update(client)
        self.radius_acct.update(client)
        client.update_last_sent()

    def on_message(self, ws: websocket.WebSocketApp, message):
        """
        process the data comming from Mist
        if data os JSON and contains "mac":
        - if mac is not known: send Acct-Start
        - if mac is known and Client Connection Info didn't change: update Client data
        - else: send Acct-Stop
        """
        try:
            message_json = json.loads(message)
            if message_json.get("data"):
                client_data = json.loads(message_json.get("data", {}))
                client_mac = client_data.get("mac")
                if client_mac:
                    known_client: MistClient = self.mist_orchestrator.copy_client(client_mac)
                    if not known_client.mac:
                        client: MistClient = self.mist_orchestrator.new_client(client_mac, client_data)
                        self._acct_start(client)
                    else:
                        client: MistClient = self.mist_orchestrator.update_client(client_mac, known_client, client_data)
                        # if last_sent is reset, means the entry has been removed/recreated because critical
                        # client information changed and accounting must be restarted
                        if client.last_sent == 0:
                            self._acct_stop(known_client)
                            self._acct_start(client)
            else:
                print(message_json)
        except Exception as e:
            SCRIPT_LOGGER.error("Exception occurred", exc_info=True)


    def on_error(self, ws: websocket.WebSocketApp, error):
        print("onerror")
        print(error)


    def on_close(self, ws: websocket.WebSocketApp):
        print("onclose")


    def on_open(self, ws: websocket.WebSocketApp):
        print("onopen")
        ws.send(json.dumps({"subscribe": f"/sites/{self.mist_site_id}/stats/clients"}))


###############################################################################
## ENV
def _load_env(
    env_file: str,
    mist_host: str,
    mist_apitoken: str,
    mist_org_id: str,
    mist_site_id: str,
):
    if env_file.startswith("~/"):
        env_file = os.path.join(os.path.expanduser("~"), env_file.replace("~/", ""))
    load_dotenv(dotenv_path=env_file, override=True)
    if os.getenv("MIST_HOST"):
        mist_host = os.getenv("MIST_HOST")
    if os.getenv("MIST_APITOKEN"):
        mist_apitoken = os.getenv("MIST_APITOKEN")
    if os.getenv("MIST_ORG_ID"):
        mist_org_id = os.getenv("MIST_ORG_ID")
    if os.getenv("MIST_SITE_ID"):
        mist_site_id = os.getenv("MIST_SITE_ID")
    return mist_host, mist_apitoken, mist_org_id, mist_site_id

###############################################################################
# USAGE
def usage(error_message:str=None):
    print("""
-------------------------------------------------------------------------------

    Written by Thomas Munzer (tmunzer@juniper.net)
    Github repository: https://github.com/tmunzer/Mist_library/

    This script is licensed under the MIT License.

-------------------------------------------------------------------------------
Python script to send RADIUS Accounting and/or Syslog messages based on Mist
client stats.
This script is opening a Websocket with the Mist Cloud and subscribe to the
client stats channel. This is allowing the Mist Cloud to stream the data in
real time.

-------
Current limitations:
This script can currently only subscribe for a single Mist Site Websocket.


-------
Requirements:
mistapi: https://pypi.org/project/mistapi/
websocket-client==0.44.0
pyrad

-------
Usage:
This script can be run as is (without parameters), or with the options below.
If no options are defined, or if options are missing, the missing options will
be asked by the script or the default values will be used.

It is recomended to use an environment file to store the required information
to request the Mist Cloud (see https://pypi.org/project/mistapi/ for more
information about the available parameters).

-------
Script Parameters:
-h, --help                  display this help

--ppsk_sync_org             Enable Mist Org PPSK synchronisation. 
                            Used to set the client username with the PPSK name
--ppsk_sync_sites           Enable Mist Sites PPSK synchronisation. 
                            Used to set the client username with the PPSK name
--ppsk_sync_interval=       Interval between PPSK synchronisations,
                            in secondes
                            default is 3600

--radius_server=            RADIUS Server IP Address where to send the Accounting
                            messages to
                            Setting this parameter is enabling RADIUS Accounting
--radius_port=              RADIUS Server Port where to send the Accounting
                            messages to
                            Default is 1813
--radius_secret=            RADIUS shared secret
                            default is "secret"

--syslog_server=            SYSLOG Server IP Address where to send the Accounting
                            messages to
                            Setting this parameter is enabling SYSLOG Accounting
--syslog_port=              RADIUS Server Port where to send the Accounting
                            SYSLOG to
                            Default is 514

--interim_acct_interval=    Interval between each ACCT INTERIM Message, in
                            seconds. 0 to disable ACCT INTERIM Messages.
                            Default is 60

--client_timeout=           Duration before marking a client as disconnected if Mist
                            is no more sending update, in seconds.
                            Once a client is marked as disconnected, an ACCT Stop 
                            message will be sent and the client data will be removed
                            minimum: 120
                            maximum: 3600
                            default: 120

-l, --log_file=             define the filepath/filename where to write the logs
                            default is "./script.log"
-e, --env=                  define the env file to use (see mistapi env file documentation
                            here: https://pypi.org/project/mistapi/)
                            default is "~/.mist_env"

-------
Examples:
python3 ./acct_server.py
python3 ./acct_server.py  --ppsk_sync_org --syslog_server=10.3.20.16

          """)
    if error_message:
        print(f"ERROR: {error_message}")
###############################################################################
# ENTRY POINT
if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "he:l:",
            [
                "help",
                "env=",
                "log_file=",
                "ppsk_sync_org",
                "ppsk_sync_sites",
                "ppsk_sync_interval=",
                "radius_server=",
                "radius_port=",
                "radius_secret=",
                "syslog_server=",
                "syslog_port=",
                "interim_acct_interval=",
                "client_timeout=",
            ],
        )
    except getopt.GetoptError as err:
        usage(err)

    for o, a in opts:
        if o in ["-h", "--help"]:
            usage()
        elif o in ["-e", "--env"]:
            ENV_FILE = a
        elif o in ["-l", "--log_file"]:
            LOG_FILE = a
        elif o == "--ppsk_sync_org":
            PPSK_SYNC_ORG = True
        elif o == "--ppsk_sync_sites":
            PPSK_SYNC_SITES = True
        elif o == "--ppsk_sync_interval":
            PPSK_SYNC_INTERVAL = a
        elif o == "--radius_server":
            RADIUS_SERVER = a
            RADIUS_ENABLED = True
        elif o == "--radius_port":
            RADIUS_PORT = a
        elif o == "--radius_secret":
            RADIUS_SECRET = a
        elif o == "--syslog_server":
            SYSLOG_SERVER = a
            SYSLOG_ENABLED = True
        elif o == "--syslog_port":
            SYSLOG_PORT = a
        elif o == "--interim_acct_interval":
            INTERIM_ACCT_INTERVAL = a
        elif o == "--client_timeout":
            CLIENT_TIMEOUT = a
        else:
            assert False, "unhandled option"

    #### LOGS ####
    LOG_FILE = "./syslog.log"
    SCRIPT_LOGGER = logging.getLogger(__name__)
    SCRIPT_LOGGER.setLevel(logging.DEBUG)
    if LOG_FILE:
        logging.basicConfig(filename=LOG_FILE, filemode="w")
    else:
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

    mist_socket = MistSocket()