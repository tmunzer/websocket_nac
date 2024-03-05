import logging
from datetime import datetime
from mist_psks import MistPsks
from mist_client import MistClient

SCRIPT_LOGGER = logging.getLogger(__name__)
SCRIPT_LOGGER.setLevel(logging.DEBUG)


class MistOrcherstator:
    def __init__(
        self,
        interim_interval: int = 0,
        client_timeout: int = 120,
    ) -> None:
        self.interim_update = interim_interval
        self.client_timeout = client_timeout
        self.clients = {}

    def set_psk_sync(self, mist_host: str, mist_token: str, org_id: str, sync_org: bool, sync_sites: bool, sync_interval: int = 0) -> None:
        self.psks = MistPsks(mist_host, mist_token, org_id, sync_org, sync_sites, sync_interval)


    def chron(self) -> dict:
        interim = {
            "update":[],
            "stop": []
        }
        self.psks.sync()
        interim = self._process_interim_update()
        return interim

    def copy_client(self, client_mac:str) -> MistClient:
        client = self.get_client(client_mac)
        client_copy = MistClient()
        if client:
            data = {
                "mac": client.mac,
                "site_id": client.site_id,
                "assoc_time": client.assoc_time,
                "family": client.family,
                "model": client.model,
                "os": client.os,
                "manufacture": client.manufacture,
                "hostname": client.hostname,
                "bssid": client.bssid,
                "ip": client.ip,
                "ap_mac": client.ap_mac,
                "ap_id": client.ap_id,
                "last_seen": client.last_seen,
                "uptime": client.uptime,
                "ssid": client.ssid,
                "wlan_id": client.wlan_id,
                "dual_band": client.dual_band,
                "is_guest": client.is_guest,
                "key_mgmt": client.key_mgmt,
                "group": client.group,
                "band": client.band,
                "channel": client.channel,
                "vlan_id": client.vlan_id,
                "username": client.username,
                "psk_id": client.psk_id,
                "proto": client.proto,
                "rssi": client.rssi,
                "snr": client.snr,
                "idle_time": client.idle_time,
                "tx_rate": client.tx_rate,
                "rx_rate": client.rx_rate,
                "tx_pkts": client.tx_pkts,
                "rx_pkts": client.rx_pkts,
                "tx_bytes": client.tx_bytes,
                "rx_bytes": client.rx_bytes,
                "tx_retries": client.tx_retries,
                "rx_retries": client.rx_retries,
                "tx_bps": client.tx_bps,
                "rx_bps": client.rx_bps,
                "_ttl": client._ttl,
                "last_sent": client.last_sent,
                "last_updated": client.last_updated,
            }
            client_copy.update_client_data(data, self.psks)
        return client_copy


    def delete_client(self, client_mac:str) -> None:
        del self.clients[client_mac]

    def new_client(self, client_mac:str, client_data:dict) -> MistClient:
        SCRIPT_LOGGER.info(f"Mist Update - {client_mac} not in client list. Processing Acct Start")
        client = self._new_client(client_mac, client_data)
        return client

    def update_client(self, client_mac:str, known_client:MistClient, client_data:dict) -> MistClient:
        checked_fields = [
            "site_id",
            "hostname",
            "ip",
            "ssid",
            "wlan_id",
            "vlan_id",
            "psk_id",
            "username",
        ]
        if known_client.check_session(client_data, self.psks, checked_fields):
            SCRIPT_LOGGER.info(f"Mist Update - {client_mac} in client list and Client Connection Info changed. Processing Acct Stop/Start")
            self.delete_client(client_mac)
            return self._new_client(client_mac, client_data)
        else:
            SCRIPT_LOGGER.info(f"Mist Update - {client_mac} in client list and Client Connection Info didn't change. Updating Client data")
            return self._update_client(client_mac, client_data)

    def get_client(self, client_mac:str) -> MistClient:
        return self.clients.get(client_mac)

    def _new_client(self, client_mac:str, client_data:dict) -> MistClient:
        client = MistClient()
        client.update_client_data(client_data, self.psks)
        self.clients[client_mac] = client
        return client

    def _update_client(self, client_mac: str, client_data: dict) -> MistClient:
        client: MistClient = self.clients[client_mac]
        client.update_client_data(client_data, self.psks)
        return client

    def _process_interim_update(self):
        interim = {
            "update":[],
            "stop": []
        }
        for client_mac in list(self.clients):
            client: MistClient = self.clients[client_mac]
            if client.check_disconnect(self.client_timeout):
                print(
                    f"RUNTIME Update - last update for {client_mac} is more than {self.client_timeout}s ago. Sending Acct-Stop and cleaning client data"
                )
                interim["stop"].append(client)
            elif client.check_update_required(self.interim_update):
                print(
                    f"RUNTIME Update - last interim update for {client_mac} was sent more than {self.interim_update}s ago. Sending Interim-Update"
                )
                interim["update"].append(client)
        return interim

