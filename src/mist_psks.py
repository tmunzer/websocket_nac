"""
-------------------------------------------------------------------------------

    Written by Thomas Munzer (tmunzer@juniper.net)
    Github repository: https://github.com/tmunzer/websocket_nac/

    This script is licensed under the MIT License.

-------------------------------------------------------------------------------
"""
import logging
from datetime import datetime
import mistapi

SCRIPT_LOGGER = logging.getLogger(__name__)
SCRIPT_LOGGER.setLevel(logging.DEBUG)

###############################################################################
## PSKS
class MistPsks:
    """
    Class to syncrhonise the Mist PSKs and store the psk_id/psk_name mapping
    """

    def __init__(
        self,
        mist_host: str,
        mist_token: str,
        org_id: str,
        sync_org: bool,
        sync_sites: bool,
        sync_interval: int = 0,
    ) -> None:
        self.psks = {}
        self.org_id = org_id
        self.sync_org = sync_org
        self.sync_sites = sync_sites
        self.sync_interval = sync_interval
        self.last_sync = 0
        self.session = mistapi.APISession(
            host=mist_host, apitoken=mist_token, show_cli_notif=False
        )
        self.session.login()
        self.sync()

    def get_psk_name(self, psk_id: str) -> str:
        """
        get the PSK name based on its id

        params:
        psk_id  str

        returns:
        str
            psk.name if present, psk.id otherwise
        """
        return self.psks.get(psk_id, psk_id)

    def sync(self) -> None:
        """
        retrieve the PSKs from the Mist Cloud and store the psk_id/psk_name mapping
        """
        ts = int(str(datetime.timestamp(datetime.now())).split(".")[0])
        if self.last_sync + self.sync_interval < ts:
            SCRIPT_LOGGER.info(f"PSKS Sync - process started at {ts}")
            if self.sync_org:
                self._sync_org()
            if self.sync_sites:
                self.sync_sites()
            self.last_sync = int(str(datetime.timestamp(datetime.now())).split(".")[0])
            SCRIPT_LOGGER.info(
                f"PSKS Sync - process finished at {ts}: {len(self.psks)} psks synced"
            )

    def _sync_org(self) -> None:
        SCRIPT_LOGGER.info(
            f"PSKS ORG Sync - Starting ORG sync for org_id {self.org_id}"
        )
        resp = mistapi.api.v1.orgs.psks.listOrgPsks(
            self.session, self.org_id, limit=1000
        )
        data = mistapi.get_all(self.session, resp)
        self._process_psks(data)

    def _sync_sites(self) -> None:
        SCRIPT_LOGGER.info(
            f"PSKS SITE Sync - Retrieving Site list for org_id {self.org_id}"
        )
        resp = mistapi.api.v1.orgs.sites.listOrgSites(
            self.session, self.org_id, limit=1000
        )
        sites = mistapi.get_all(self.session, resp)
        for site in sites:
            site_id = site.get("id")
            SCRIPT_LOGGER.info(
                f"PSKS SITE Sync - Starting SITE sync for site_id {site_id}"
            )
            if site_id:
                resp = mistapi.api.v1.sites.psks.listSitePsks(
                    self.session, site_id, limit=1000
                )
                data = mistapi.get_all(self.session, resp)
                self._process_psks(data)

    def _process_psks(self, psks: list) -> None:
        for psk in psks:
            psk_id = psk.get("id")
            if psk_id:
                self.psks[psk_id] = psk.get("name", psk_id)