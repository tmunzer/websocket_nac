"""
-------------------------------------------------------------------------------

    Written by Thomas Munzer (tmunzer@juniper.net)
    Github repository: https://github.com/tmunzer/websocket_nac/

    This script is licensed under the MIT License.

-------------------------------------------------------------------------------
"""
import sys
import logging
import socket
from datetime import datetime
from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad.packet import Packet
from mist_orchestrator import MistClient

SCRIPT_LOGGER = logging.getLogger(__name__)
SCRIPT_LOGGER.setLevel(logging.DEBUG)

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

###############################################################################
## RADIUS ACCOUNTING
class RadiusAcct:
    """
    class to manage and process RADIUS data:
    - in-memory storage of the list of dot1x clients (data commning from websocket)
    - send the RADIUS Acct packet based on the client data stored in-memory
    - generate the Acct-Stop and Interim-Update based on the client data stored in-memory
    """

    def __init__(self, enabled:bool, radius_server:str, radius_port:int, radius_secret:str) -> None:
        self.enabled = enabled
        self.pyrad_client = Client(
            server=radius_server,
            secret=radius_secret,
            acctport=radius_port,
            dict=Dictionary("dictionary")
        )


    def _send_packet(self, rad_acct:Packet):
        try:
            self.pyrad_client.SendPacket(rad_acct)
        except Timeout:
            print("RADIUS server does not reply")
            sys.exit(1)
        except socket.error as error:
            print("Network error: " + error)
            sys.exit(1)
        except Exception as e:
            print("Exception occurred", exc_info=True)

    def _generate_base_packet(self, client:MistClient) -> Packet:
        ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])

        rad_acct = self.pyrad_client.CreateAcctPacket()
        rad_acct.CreateID()
        rad_acct. AddAttribute("User-Name", client.username)
        # the Acct-Session-Id generation is not strong enough, this must be replaced
        # (e.g., if the service restarts, the client assoc_time will stay the same so
        # the session id will not change, and the service will send a new acct-start
        # with a session id already known by the RADIUS Server)
        rad_acct. AddAttribute("Acct-Session-Id", str(client.assoc_time)[2:])
        rad_acct. AddAttribute("Event-Timestamp", ts)
        rad_acct. AddAttribute("Framed-IP-Address", client.ip)
        rad_acct. AddAttribute("Called-Station-Id", f"{client.bssid}:{client.ssid}")
        rad_acct. AddAttribute("Calling-Station-Id", client.mac)
        rad_acct. AddAttribute("Acct-Delay-Time", 0)
        rad_acct. AddAttribute("Acct-Authentic", "RADIUS")
        rad_acct. AddAttribute("NAS-Port-Type", "Wireless-802.11")
        # rad_acct. AddAttribute("NAS-IP-Address", client.nas_ip_address)
        # rad_acct. AddAttribute("NAS-Identifier", client.nas_identifier)
        return rad_acct

    def _generate_start_packet(self, client:MistClient) -> Packet:
        rad_acct = self._generate_base_packet(client)
        rad_acct. AddAttribute("Acct-Status-Type", "Start")
        return rad_acct

    def _generate_update_packet(self, client:MistClient) -> Packet:
        rad_acct = self._generate_base_packet(client)
        rad_acct. AddAttribute("Acct-Status-Type", "Interim-Update")
        return rad_acct

    def _generate_stop_packet(self, client:MistClient, terminate_cause:str= "Port-Unneeded") -> Packet:
        rad_acct = self._generate_base_packet(client)
        rad_acct. AddAttribute("Acct-Status-Type", "Stop")
        if  0 <= client.rx_bytes <= 4294967295:
            rad_acct. AddAttribute("Acct-Input-Octets", client.rx_bytes)
        if  0 <= client.tx_bytes <= 4294967295:
            rad_acct. AddAttribute("Acct-Output-Octets", client.tx_bytes)
        if  0 <= client.rx_pkts <= 4294967295:
            rad_acct. AddAttribute("Acct-Input-Packets", client.rx_pkts)
        if  0 <= client.tx_pkts <= 4294967295:
            rad_acct. AddAttribute("Acct-Output-Packets", client.tx_pkts)
        rad_acct. AddAttribute("Acct-Session-Time", client.uptime)
        if terminate_cause:
            rad_acct. AddAttribute("Acct-Terminate-Cause", terminate_cause)
        return rad_acct

    def _get_log(self, packet:Packet):
        fields = packet.keys()
        logs = []
        for field in fields:
            logs.append(f"{field}: {packet.get(field)}")
        return ", ".join(logs)

    def start(self, client: MistClient):
        """
        send a message when a client connects
        """
        if self.enabled:
            rad_acct = self._generate_start_packet(client)
            SCRIPT_LOGGER.info(f"start: {self._get_log(rad_acct)}")
            self._send_packet(rad_acct)

    def stop(self, client: MistClient):
        """
        send a message when a client diconnects
        """
        if self.enabled:
            rad_acct = self._generate_stop_packet(client)
            SCRIPT_LOGGER.info(f"stop: {self._get_log(rad_acct)}")
            self._send_packet(rad_acct)

    def update(self, client: MistClient):
        """
        updates the Client data with data comming from Mist
        udpates
        Interim-Update will be sent we required by interim_update function
        """
        if self.enabled:
            rad_acct = self._generate_update_packet(client)
            SCRIPT_LOGGER.info(f"update: {self._get_log(rad_acct)}")
            self._send_packet(rad_acct)
