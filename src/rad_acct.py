import os
import sys
import json
import socket
import threading
from time import sleep
from dotenv import load_dotenv
from datetime import datetime
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import Packet

import websocket  # websocket-client==0.44.0


ENV_FILE = "~/.mist_env"
# Can be save in the env file
MIST_HOST = "api.mist.com"
MIST_APITOKEN = ''
MIST_ORG_ID = ''
MIST_SITE_ID = ''
# RADIUS Server connection parameters
SERVER = "127.0.0.1"
SECRET = b"secret"
PORT = 1813
# RADIUS Update parameters
INTERIM_ACCT_INTERVAL = 60
CLIENT_TIMEOUT = 120

"""
Attribute Name	        Type	RFC	Description
*User-Name	            1	RFC 2865	The User-Name attribute is forwarded in the Accounting-Request and indicates the name of the user.
NAS-IP-Address	        4	RFC 2865	The NAS-IP-Address attribute is forwarded in the Accounting-Request and indicates the IP Address of the Access Point.
*Framed-IP-Address	    8	RFC 2865	The Framed-IP-Address attribute is forwarded in the Accounting-Request packets and indicates current or last-known 
                                        IP address of the wireless client. It is only sent when Interim Accounting is enabled on the WLAN.
                                        Note: during the first client connection, when client has not yet obtained an IP address, Framed-IP-Address AVP will 
                                        be missing in the first Accounting-Start packet. However, as soon as the AP learns client IP address, it will send
                                        asynchronous (outside of normal Interim-Accounting update interval) Accounting Interim-Update message with 
                                        Framed-IP-Address information.
Class	                25	RFC 2865	The Class attribute is optionally forwarded in the Access-Accept and should be sent unmodified by the client to the
                                        accounting server as part of the Accounting-Request packet if accounting is enabled. Mist Access Points support sending
                                        multiple Class attributes for each client.
*Called-Station-Id	    30	RFC 2865	The Called-Station-Id attribute is forwarded in the Accounting-Request and indicates the BSSID and ESSID that the user
                                        is associated with. The Access Point will forward the attribute value using the following formatting: XX-XX-XX-XX-XX-XX:ESSID.
*Calling-Station-Id	    31	RFC 2865	The Calling-Station-Id attribute is forwarded in the Accounting-Request and indicates the MAC address of the user. The
                                        Access Point will forward the attribute value using the following formatting: XX-XX-XX-XX-XX-XX.
NAS-Identifier	        32	RFC 2865	The NAS-Identifier attribute is forwarded in the Accounting-Request and indicates the user defined identifier configured
                                        under WLAN settings.
*Acct-Status-Type        40	RFC 2866	The Acct-Status-Type attribute is forwarded in the Accounting-Request and indicates whether the Accounting-Request marks
                                        the status of the accounting update. Supported values include Start, Stop and Interim-Update.
Acct-Delay-Time         41	RFC 2866	The Acct-Delay-Time attribute is forwarded in the Accounting-Request and indicates how many seconds the Access Point has
                                        been trying to send the accounting record for. This value is subtracted from the time of arrival on the server to find the
                                        approximate time of the event generating this Accounting-Request.
*Acct-Input-Octets	    42	RFC 2866	The Acct-Input-Octets attribute is forwarded in the Accounting-Request and indicates how many octets have been received from
                                        the user over the course of the connection. This attribute may only be present in Accounting-Request records where the
                                        Acct-Status-Type is set to Stop.
*Acct-Output-Octets	    43	RFC 2866	The Acct-Output-Octets attribute is forwarded in the Accounting-Request and indicates how many octets have been forwarded to
                                        the user over the course of the connection. This attribute may only be present in Accounting-Request records where the 
                                        Acct-Status-Type is set to Stop.
*Acct-Session-Id	    44	RFC 2866	The Acct-Session-Id attribute is forwarded in the Accounting-Request and provides a unique identifier to make it easy to 
                                        match start, stop and interim records in an accounting log file.
*Acct-Authentic	        45	RFC 2866	The Account-Authentic attribute is forwarded in the Accounting-Request and indicates how the user was authenticated. When
                                        RADIUS accounting is enabled the Access Point will set this value to RADIUS.
*Acct-Session-Time	    46	RFC 2866	The Acct-Session-Time attribute is forwarded in the Accounting-Request and indicates how many seconds the user has received
                                        service for. This attribute may only be present in Accounting-Request records where the Acct-Status-Type is set to Stop.
*Acct-Input-Packets	    47	RFC 2866	The Acct-Input-Packets attribute is forwarded in the Accounting-Request and indicates how many packets have been received
                                        from the user over the course of the connection. This attribute may only be present in Accounting-Request records where the
                                        Acct-Status-Type is set to Stop.
*Acct-Output-Packets	48	RFC 2866	The Acct-Output-Packets attribute is forwarded in the Accounting-Request and indicates how many packets have been forwarded
                                        to the user over the course of the connection. This attribute may only be present in Accounting-Request records where the
                                        Acct-Status-Type is set to Stop.
Acct-Terminate-Cause	49	RFC 2866	The Acct-Terminate-Cause attribute is forwarded in the Accounting-Request and indicates how the session was terminated. This
                                        attribute may only be present in Accounting-Request records where the Acct-Status-Type is set to Stop.
*Event-Timestamp	    55	RFC 2869	The Event-Timestamp attribute is forwarded in the Accounting-Request and indicates the time that the accounting event occurred
                                        on the Access Point.
**NAS-Port-Type	        61	RFC 2865	The NAS-Port-Type attribute is forwarded in the Accounting-Request and indicates the type of physical connection for the user.
                                        This attribute value is always set to Wireless-802.11 by the Mist Access Point.

"""

class RadClient:
    """
    class to process and store dot1x client information
    it also generates the Acct Packets to be send
    """
    def __init__(self) -> None:
        self.username = None
        self.nas_ip_address = None
        self.framed_ip_address = None
        self.class_attr = None
        self.called_station_id = None
        self.calling_station_id = None
        self.nas_identifier = None
        self.acct_status_type = None
        self.acct_delay_time = 0
        self.acct_input_octets = 0
        self.acct_output_octets = 0
        self.acct_session_id = None
        self.acct_authentic = None
        self.acct_session_time = 0
        self.acct_input_packets = 0
        self.acct_output_packets = 0
        self.nas_port_type = None
        self.session_start = 0
        self.last_seen = 0
        self.last_sent = 0

    def check_session(self, client_data:dict):
        return self.called_station_id == f"{client_data.get('bssid')}:{client_data.get('ssid')}"

    def check_update_required(self):
        ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])
        return self.last_sent + INTERIM_ACCT_INTERVAL <= ts
    
    def check_disconnect(self):
        ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])
        return self.last_seen + CLIENT_TIMEOUT <= ts

    def update_client_data(self, client_data:dict):
        ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])

        if client_data.get("username"):
            self.username = client_data["username"]
        else:
            self.username = client_data["mac"]
        self.nas_ip_address = None
        self.framed_ip_address = client_data.get("ip")
        self.class_attr = None
        self.called_station_id = f"{client_data.get('bssid')}:{client_data.get('ssid')}"
        self.calling_station_id = client_data["mac"]
        self.nas_identifier = None
        self.acct_status_type = None
        self.acct_delay_time = 0
        self.acct_input_octets = client_data.get("rx_pkts")
        self.acct_output_octets = client_data.get("tx_pkts")
        # the Acct-Session-Id generation is not strong enough, this must be replaced
        # (e.g., if the service restarts, the client assoc_time will stay the same so 
        # the session id will not change, and the service will send a new acct-start 
        # with a session id already known by the RADIUS Server)
        self.acct_session_id = str(client_data.get("assoc_time"))[2:]
        self.acct_authentic = "RADIUS"
        self.acct_session_time = 0
        self.acct_input_packets = client_data.get("rx_bytes")
        self.acct_output_packets = client_data.get("tx_bytes")
        self.nas_port_type = "Wireless-802.11"
        self.session_start = client_data.get("assoc_time")
        self.last_seen = ts
        self.last_sent = 0
    
    def update_last_sent(self):
        self.last_sent = int(str(datetime.timestamp(datetime.now())).split(".")[0])

    def _common_rad_acct_data(self, pyrad_client:Client) -> Packet:
        ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])

        rad_acct = pyrad_client.CreateAcctPacket()
        rad_acct["User-Name"]= self.username
        rad_acct["Acct-Session-Id"]= self.acct_session_id
        rad_acct["Event-Timestamp"]= ts
        if self.nas_ip_address: rad_acct["NAS-IP-Address"]= self.nas_ip_address
        if self.framed_ip_address: rad_acct["Framed-IP-Address"]= self.framed_ip_address
        if self.called_station_id: rad_acct["Called-Station-Id"]= self.called_station_id
        if self.calling_station_id: rad_acct["Calling-Station-Id"]= self.calling_station_id
        if self.nas_identifier: rad_acct["NAS-Identifier"]= self.nas_identifier
        if self.acct_delay_time: rad_acct["Acct-Delay-Time"]= self.acct_delay_time
        if self.acct_authentic: rad_acct["Acct-Authentic"]= self.acct_authentic
        if self.nas_port_type: rad_acct["NAS-Port-Type"]= self.nas_port_type
        return rad_acct

    def start(self, pyrad_client:Client) -> Packet:
        rad_acct = self._common_rad_acct_data(pyrad_client)
        rad_acct["Acct-Status-Type"]= "Start"
        return rad_acct

    def update(self, pyrad_client:Client) -> Packet:
        rad_acct = self._common_rad_acct_data(pyrad_client)
        rad_acct["Acct-Status-Type"]= "Interim-Update"
        return rad_acct

    def stop(self, pyrad_client:Client, terminate_cause:str=None) -> Packet:
        ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])
        rad_acct = self._common_rad_acct_data(pyrad_client)
        rad_acct["Acct-Status-Type"]= "Stop"
        if  0 <= self.acct_input_octets <= 4294967295: rad_acct["Acct-Input-Octets"]= self.acct_input_octets
        if  0 <= self.acct_output_octets <= 4294967295: rad_acct["Acct-Output-Octets"]= self.acct_output_octets
        if  0 <= self.acct_input_packets <= 4294967295: rad_acct["Acct-Input-Packets"]= self.acct_input_packets
        if  0 <= self.acct_output_packets <= 4294967295: rad_acct["Acct-Output-Packets"]= self.acct_output_packets
        rad_acct["Acct-Session-Time"]= ts - self.session_start
        if terminate_cause:
            rad_acct["Acct-Terminate-Cause"]= terminate_cause
        return rad_acct

class RadAcct:
    """
    class to manage and process RADIUS data:
    - in-memory storage of the list of dot1x clients (data commning from websocket)
    - send the RADIUS Acct packet based on the client data stored in-memory
    - generate the Acct-Stop and Interim-Update based on the client data stored in-memory
    """

    def __init__(self) -> None:
        self.clients = {}
        self.pyrad_client = Client(server=SERVER, secret=SECRET, acctport=PORT, dict=Dictionary("dictionary"))

    def _start(self, client_mac: str,client_data:dict):
        """
        generates and store the Client to be stored in memory
        generates the Acct-Start packet
        send the Acct-Start packet
        update the Client "last_sent" entry
        """
        client = RadClient()
        client.update_client_data(client_data)
        acct_packet = client.start(self.pyrad_client)
        self._send_packet(acct_packet)
        self.clients[client_mac] = client
        self.clients[client_mac].update_last_sent()

    def _update(self, client_mac:str, client_data:dict):
        """
        updates the Client data with data comming from Mist
        udpates         
        Interim-Update will be sent we required by interim_update function
        """
        client = self.clients[client_mac]
        client.update_client_data(client_data)

    def _stop(self, client_mac:str):
        """
        generates the Acct-Stop packet
        send the Acct-Stop packet
        delete the Client from the in-memroy storage
        """
        client = self.clients[client_mac]
        acct_packet = client.stop(self.pyrad_client, "Port-Unneeded")
        self._send_packet(acct_packet)
        del self.clients[client_mac]

    def _send_packet(self, rad_acct:Packet):
        try:
            self.pyrad_client.SendPacket(rad_acct)
        except Client.Timeout:
            print("RADIUS server does not reply")
            sys.exit(1)
        except socket.error as error:
            print("Network error: " + error)
            sys.exit(1)
        except Exception as e:
            print("Exception occurred", exc_info=True)

    def new_message(self, message:str):
        """
        process the data comming from Mist
        if data os JSON and contains "mac":
        - if mac is not known: send Acct-Start
        - if mac is known and Called-Station-Id didn't change: update Client data
        - else: send Acct-Stop
        """
        try:
            message_json = json.loads(message)
            if message_json.get("data"):
                client_data = json.loads(message_json.get("data", {}))
                client_mac = client_data.get("mac")                
                if client_mac:
                    if not self.clients.get(client_mac):
                        print(f"Mist Update - {client_mac} not in client list. Processing Acct Start")
                        self._start(client_mac, client_data)
                    elif self.clients[client_mac].check_session(client_data):
                        print(f"Mist Update - {client_mac} in client list and Called-Station-Id didn't change. Processing Acct Interim-Update")
                        self._update(client_mac, client_data)
                    else:
                        print(f"Mist Update - {client_mac} in client list and Called-Station-Id changed. Processing Acct Stop/Start")
                        self._stop(client_mac)
                        self._start(client_mac, client_data)
            else:
                print(message_json)
        except:
            print(message)

    def interim_update(self):
        """
        this function must be run every X sec to check parse the Client list and
        - if Client is not seen anymore (based on CLIENT_TIMEOUT and client's last_seen values): send Acct-Stop and delete the Client from the list
        - if the last Interim-Update is outdated (based on the ITERIM_ACCT_INTERVAL and client's last_sent values): send the Interim-Update and update Client last_sent value
        """
        for client_mac in list(self.clients):
            client = self.clients[client_mac]
            if client.check_disconnect():
                print(f"RUNTIME Update - last update for {client_mac} is more than {CLIENT_TIMEOUT}s ago. Sending Acct-Stop and cleaning client data")
                acct_packet = client.stop(self.pyrad_client, "Idle-Timeout")
                self._send_packet(acct_packet)
                del self.clients[client_mac]
            elif client.check_update_required():
                print(f"RUNTIME Update - last interim update for {client_mac} was sent more than {INTERIM_ACCT_INTERVAL}s ago. Sending Interim-Update")
                acct_packet = client.update(self.pyrad_client)
                self._send_packet(acct_packet)
                self.clients[client_mac].update_last_sent()


def on_message(ws:websocket.WebSocketApp, message):
    RAD_ACCT.new_message(message)


def on_error(ws:websocket.WebSocketApp, error):
    print('onerror')
    print(error)


def on_close(ws:websocket.WebSocketApp, close_status_code:str, close_msg:str):
    print('onclose')
    print(close_status_code)
    print(close_msg)


def on_open(ws:websocket.WebSocketApp):
    print('onopen')
    ws.send(json.dumps({'subscribe': f'/sites/{MIST_SITE_ID}/stats/clients'}))

def _load_env(env_file:str, mist_host:str, mist_apitoken:str, mist_org_id:str, mist_site_id:str):
    if env_file.startswith("~/"):
        env_file = os.path.join(
            os.path.expanduser("~"), env_file.replace("~/", "")
        )
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


if __name__ == "__main__":
    MIST_HOST, MIST_APITOKEN, MIST_ORG_ID, MIST_SITE_ID = _load_env(ENV_FILE, MIST_HOST, MIST_APITOKEN, MIST_ORG_ID, MIST_SITE_ID)
    MIST_APITOKEN = MIST_APITOKEN.split(",")[0]
    # host for websocket is api-ws.mist.com, so replacing "api." or "manage." with "api-ws." if not the right host
    if MIST_HOST.startswith("api."):
        MIST_HOST = MIST_HOST.replace("api.", "api-ws.")
    elif MIST_HOST.startswith("manage."):
        MIST_HOST = MIST_HOST.replace("manage.", "api-ws.")
    print(f"MIST_HOST     : {MIST_HOST}")
    print(f"MIST_APITOKEN : {MIST_APITOKEN[:6]}...{MIST_APITOKEN[-6:]}")
    print(f"MIST_ORG_ID   : {MIST_ORG_ID}")
    print(f"MIST_SITE_ID  : {MIST_SITE_ID}")

    RAD_ACCT = RadAcct()
    # Create and Start the Websocket in a Thread
    WS = websocket.WebSocketApp(f"wss://{MIST_HOST}/api-ws/v1/stream",
                                header={'Authorization': f'Token {MIST_APITOKEN}'},
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close,
                                on_open=on_open)
    wst = threading.Thread(target=WS.run_forever())
    wst.daemon = True
    wst.start()

    # Start the loop to check client udpates/timeouts
    while True:
        sleep(1)
        RAD_ACCT.interim_update()
