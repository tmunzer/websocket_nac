import json
import os
from datetime import datetime
from dotenv import load_dotenv
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import socket
import sys
import pyrad.packet

import websocket  # websocket-client==0.44.0

MSG_RECEIVED = 0

ENV_FILE = "~/.mist_env"
MIST_HOST = "api.mist.com"
MIST_APITOKEN = ''
MIST_ORG_ID = ''
MIST_SITE_ID = ''

CLIENT_LIST = {}
SERVER = "10.3.20.12"
SECRET = b"secret"
SRV = Client(server=SERVER, secret=SECRET, acctport=1813, dict=Dictionary("dictionary"))

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

def _send_packet(rad_acct):
    try:
        SRV.SendPacket(rad_acct)
    except Client.Timeout:
        print("RADIUS server does not reply")
        sys.exit(1)
    except socket.error as error:
        print("Network error: " + error[1])
        sys.exit(1)
    except Exception as e:
        print("Exception occurred", exc_info=True)


def _send_start(client_list:dict, client_mac:str, client_data:dict):
        ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])

        client_list[client_mac] = {
            "Called-Station-Id": f"{client_data.get('bssid')}:{client_data.get('ssid')}",
            "Acct-Session-Id": str(client_data.get("assoc_time"))[2:], # the Acct-Session-Id generation is not strong enough, this must be replaced
        }

        rad_acct = SRV.CreateAcctPacket()
        rad_acct["Acct-Status-Type"]= "Start"
        if client_data.get("username"):
            rad_acct["User-Name"]= client_data.get("username")
        else:
            rad_acct["User-Name"]= client_mac
        #rad_acct["NAS-IP-Address"]= None
        rad_acct["Framed-IP-Address"]= client_data.get("ip")
        rad_acct["Called-Station-Id"]= client_list[client_mac]["Called-Station-Id"]
        rad_acct["Calling-Station-Id"]= client_mac
        #rad_acct["NAS-Identifier"]= None
        #rad_acct["Acct-Delay-Time"]= None
        rad_acct["Acct-Session-Id"]= client_list[client_mac]["Acct-Session-Id"]
        rad_acct["Acct-Authentic"]= "RADIUS"
        rad_acct["Event-Timestamp"]= ts
        rad_acct["NAS-Port-Type"]= "Wireless-802.11"
        _send_packet(rad_acct)

def _send_update(client_list:dict, client_mac:str, client_data:dict):
        ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])

        rad_acct = SRV.CreateAcctPacket()
        rad_acct["Acct-Status-Type"]= "Interim-Update"
        if client_data.get("username"):
            rad_acct["User-Name"]= client_data.get("username")
        else:
            rad_acct["User-Name"]= client_mac
        #rad_acct["NAS-IP-Address"]= None
        rad_acct["Framed-IP-Address"]= client_data.get("ip")
        rad_acct["Called-Station-Id"]= client_list[client_mac]["Called-Station-Id"]
        rad_acct["Calling-Station-Id"]= client_mac
        #rad_acct["NAS-Identifier"]= None
        #rad_acct["Acct-Delay-Time"]= None
        rad_acct["Acct-Session-Id"]= client_list[client_mac]["Acct-Session-Id"]
        rad_acct["Acct-Authentic"]= "RADIUS"
        rad_acct["Event-Timestamp"]= ts
        rad_acct["NAS-Port-Type"]= "Wireless-802.11"
        _send_packet(rad_acct)

def _send_stop(client_list:dict, client_mac:str, client_data:dict):
        ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])

        rad_acct = SRV.CreateAcctPacket()
        rad_acct["Acct-Status-Type"]= "Stop"
        if client_data.get("username"):
            rad_acct["User-Name"]= client_data.get("username")
        else:
            rad_acct["User-Name"]= client_mac
        #rad_acct["NAS-IP-Address"]= None
        rad_acct["Framed-IP-Address"]= client_data.get("ip")
        rad_acct["Called-Station-Id"]= client_list[client_mac]["Called-Station-Id"]
        rad_acct["Calling-Station-Id"]= client_mac
        #rad_acct["NAS-Identifier"]= None
        #rad_acct["Acct-Delay-Time"]= None
        rad_acct["Acct-Session-Id"]= client_list[client_mac]["Acct-Session-Id"]
        rad_acct["Acct-Authentic"]= "RADIUS"
        rad_acct["Event-Timestamp"]= ts
        rad_acct["NAS-Port-Type"]= "Wireless-802.11"
        rad_acct["Acct-Input-Octets"]= client_data.get("rx_pkts")
        rad_acct["Acct-Output-Octets"]= client_data.get("tx_pkts")
        rad_acct["Acct-Input-Packets"]= client_data.get("rx_bytes")
        rad_acct["Acct-Output-Packets"]= client_data.get("tx_bytes")
        rad_acct["Acct-Session-Time"]= ts - client_data.get("assoc_time")
        rad_acct["Acct-Terminate-Cause"]= None

        del client_list[client_mac]
        _send_packet(rad_acct)


def on_message(ws:websocket.WebSocketApp, message):
    global CLIENT_LIST
    # print(f' new message - {datetime.now()} '.center(80, "-"))
    try:
        message_json = json.loads(message)
        if message_json.get("data"):
            client_data = json.loads(message_json.get("data", {}))
            #print(f"event: {message_json.get('event')}")
            #print(f"channel: {message_json.get('channel')}")

            client_mac = client_data.get("mac")
            called_station_id = f"{client_data.get('bssid')}:{client_data.get('ssid')}"
            if client_mac:
                if not CLIENT_LIST.get(client_mac):
                    print(f"{client_mac} not in client list. Processing Acct Start")
                    _send_start(CLIENT_LIST, client_mac, client_data)             
                elif CLIENT_LIST[client_mac]["Called-Station-Id"] == called_station_id:
                    print(f"{client_mac} in client list and Called-Station-Id didn't change. Processing Acct Interim-Update")
                    _send_update(CLIENT_LIST, client_mac, client_data)
                else:
                    print(f"{client_mac} in client list and Called-Station-Id changed. Processing Acct Stop/Start")
                    _send_stop(CLIENT_LIST, client_mac, client_data)
                    _send_start(CLIENT_LIST, client_mac, client_data)
        else:
            print(message_json)
    except:
        print(message)


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
    ws = websocket.WebSocketApp(f"wss://{MIST_HOST}/api-ws/v1/stream",
                                header={'Authorization': f'Token {MIST_APITOKEN}'},
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close)
    ws.on_open = on_open
    ws.run_forever()
