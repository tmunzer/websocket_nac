"""
-------------------------------------------------------------------------------

    Written by Thomas Munzer (tmunzer@juniper.net)
    Github repository: https://github.com/tmunzer/websocket_nac/

    This script is licensed under the MIT License.

-------------------------------------------------------------------------------
"""
import logging
import sys
import socket
from datetime import datetime
from mist_orchestrator import MistClient

SCRIPT_LOGGER = logging.getLogger(__name__)
SCRIPT_LOGGER.setLevel(logging.DEBUG)

###############################################################################
## SYSLOG ACCOUNTING
class SyslogAcct:
    """
    class to manage and process RADIUS data:
    - in-memory storage of the list of dot1x clients (data commning from websocket)
    - send the RADIUS Acct packet based on the client data stored in-memory
    - generate the Acct-Stop and Interim-Update based on the client data stored in-memory
    """

    def __init__(self, enabled:bool, syslog_server: str, syslog_port: int) -> None:
        self.enabled = enabled
        self.logger = logging.getLogger("Mist Syslog Logger")
        self.logger.setLevel(logging.DEBUG)
        self.handler = logging.handlers.SysLogHandler(
            address=(syslog_server, syslog_port)
        )
        self.logger.addHandler(self.handler)
        self.logger.debug("process starter")

    def _generate_syslog_message(self, status:str, client:MistClient):
        """
        generate the syslog message based on the message to send.
        Available variables are listed above

        Available SYSLOG fields
        -- user info
        NOTE: if PPSK_SYNC is enabled, ppsk_name will be set as client.username
        client.psk_id
        client.username
        -- info
        client.dual_band
        client.family
        client.group
        client.hostname
        client.ip
        client.is_guest
        client.mac
        client.manufacture
        client.model
        client.os
        client.vlan_id
        -- ap info
        client.ap_id
        client.ap_mac
        client.bssid
        client.site_id
        -- wlan info
        client.ssid
        client.wlan_id
        -- association info
        client.assoc_time
        client.band
        client.channel
        client.idle_time
        client.key_mgmt
        client.last_seen
        client.proto
        client.rssi
        client.snr
        client.uptime
        _ttl
        -- accounting info
        client.tx_rate
        client.rx_rate
        client.tx_pkts
        client.rx_pkts
        client.tx_bytes
        client.rx_bytes
        client.tx_retries
        client.rx_retries
        client.tx_bps
        client.rx_bps
        """
        if status == "start":
            return f"Login events—[{datetime.now()}] Userauthentication success User:{client.username} IP:{client.ip}"
        elif status == "stop":
            return f"Logout events—[{datetime.now()}] Userauthentication success User:{client.username} IP:{client.ip}"
        else:
            return f"Login events—[{datetime.now()}] Userauthentication success User:{client.username} IP:{client.ip}"

    def _send_packet(self, acct_message: str):
        try:
            self.logger.info(acct_message)
        except socket.error as error:
            SCRIPT_LOGGER.error("Network error: " + error)
            sys.exit(1)
        except Exception as e:
            SCRIPT_LOGGER.error("Exception occurred", exc_info=True)

    def start(self, client: MistClient):
        """
        send a message when a client connects
        """
        if self.enabled:
            syslog_message = self._generate_syslog_message("start", client)
            SCRIPT_LOGGER.info(f"start: {syslog_message}")
            self._send_packet(syslog_message)

    def stop(self, client: MistClient):
        """
        send a message when a client diconnects
        """
        if self.enabled:
            syslog_message = self._generate_syslog_message("stop", client)
            SCRIPT_LOGGER.info(f"stop: {syslog_message}")
            self._send_packet(syslog_message)

    def update(self, client: MistClient):
        """
        updates the Client data with data comming from Mist
        udpates
        Interim-Update will be sent we required by interim_update function
        """
        if self.enabled:
            syslog_message = self._generate_syslog_message("update", client)
            SCRIPT_LOGGER.info(f"update: {syslog_message}")
            self._send_packet(syslog_message)