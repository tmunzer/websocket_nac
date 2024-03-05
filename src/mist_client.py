import logging
from datetime import datetime
from mist_psks import MistPsks

SCRIPT_LOGGER = logging.getLogger(__name__)
SCRIPT_LOGGER.setLevel(logging.DEBUG)


###############################################################################
## CLIENT
class MistClient:
    """
    Class to process and store client information
    """

    def __init__(self) -> None:
        self.mac = ""
        self.site_id = ""
        self.assoc_time = 0
        self.family = ""
        self.model = ""
        self.os = ""
        self.manufacture = ""
        self.hostname = ""
        self.bssid = ""
        self.ip = ""
        self.ap_mac = ""
        self.ap_id = ""
        self.last_seen = 0
        self.uptime = 0
        self.ssid = ""
        self.wlan_id = ""
        self.dual_band = False
        self.is_guest = False
        self.key_mgmt = ""
        self.group = ""
        self.band = ""
        self.channel = 0
        self.vlan_id = ""
        self.username = ""
        self.psk_id = ""
        self.proto = ""
        self.rssi = 0
        self.snr = 0
        self.idle_time = 0
        self.tx_rate = 0
        self.rx_rate = 0
        self.tx_pkts = 0
        self.rx_pkts = 0
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.tx_retries = 0
        self.rx_retries = 0
        self.tx_bps = 0
        self.rx_bps = 0
        self._ttl = 0
        self.last_sent = 0
        self.last_updated = 0

    def check_session(self, client_data: dict, mist_psks: MistPsks, checked_fields:list=["wlan_id", "vlan_id", "username"]):
        """
        check if specific client info has changed.

        return:
        bool
            True if a field has changed, False otherwise
        """
        for field in checked_fields:
            mist_value = client_data.get(field)
            if field == "username" and client_data.get("psk_id"):
                mist_value = mist_psks.get_psk_name(client_data.get("psk_id"))
            if getattr(self, field) != mist_value:
                SCRIPT_LOGGER.debug(
                    f"client {client_data.get('mac')} info changed: {field} from {getattr(self, field)} to {mist_value}"
                )
                return True
        SCRIPT_LOGGER.debug(f"client {client_data.get('mac')} info are the same")
        return False

    def check_update_required(self, interim_acct_interval: int = 0):
        """
        Used when INTERIM_ACCT_INTERVAL > 0
        check if the update must be sent
        """
        if interim_acct_interval > 0:
            ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])
            return self.last_sent + interim_acct_interval <= ts
        else:
            return False

    def check_disconnect(self, client_timeout: int = 120):
        """
        Used when CLIENT_TIMEOUT > 0
        check if the client must be considered as disconnected
        because no update has been received for more than CLIENT_TIMEOUT seconds
        """

        ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])
        return self.last_updated + client_timeout <= ts

    def update_last_sent(self):
        """
        Used when INTERIM_ACCT_INTERVAL > 0
        update the last_sent timestamp.
        """
        self.last_sent = int(str(datetime.timestamp(datetime.now())).split(".")[0])
        
    def update_client_data(self, client_data: dict, mist_psks: MistPsks):
        """
        Update the client info
        """
        self.mac = client_data.get("mac")
        self.site_id = client_data.get("site_id")
        self.assoc_time = client_data.get("assoc_time")
        self.family = client_data.get("family")
        self.model = client_data.get("model")
        self.os = client_data.get("os")
        self.manufacture = client_data.get("manufacture")
        self.hostname = client_data.get("hostname")
        self.bssid = client_data.get("bssid")
        self.ip = client_data.get("ip")
        self.ap_mac = client_data.get("ap_mac")
        self.ap_id = client_data.get("ap_id")
        self.last_seen = client_data.get("last_seen")
        self.uptime = client_data.get("uptime")
        self.ssid = client_data.get("ssid")
        self.wlan_id = client_data.get("wlan_id")
        self.dual_band = client_data.get("dual_band")
        self.is_guest = client_data.get("is_guest")
        self.key_mgmt = client_data.get("key_mgmt")
        self.group = client_data.get("group")
        self.band = client_data.get("band")
        self.channel = client_data.get("channel")
        self.vlan_id = client_data.get("vlan_id")
        self.username = client_data.get("username")
        self.psk_id = client_data.get("psk_id")
        self.proto = client_data.get("proto")
        self.rssi = client_data.get("rssi")
        self.snr = client_data.get("snr")
        self.idle_time = client_data.get("idle_time")
        self.tx_rate = client_data.get("tx_rate")
        self.rx_rate = client_data.get("rx_rate")
        self.tx_pkts = client_data.get("tx_pkts")
        self.rx_pkts = client_data.get("rx_pkts")
        self.tx_bytes = client_data.get("tx_bytes")
        self.rx_bytes = client_data.get("rx_bytes")
        self.tx_retries = client_data.get("tx_retries")
        self.rx_retries = client_data.get("rx_retries")
        self.tx_bps = client_data.get("tx_bps")
        self.rx_bps = client_data.get("rx_bps")
        self._ttl = client_data.get("_ttl")
        self.last_updated = int(str(datetime.timestamp(datetime.now())).split(".")[0])

        if not self.username and self.psk_id:
            self.username = mist_psks.get_psk_name(self.psk_id)
