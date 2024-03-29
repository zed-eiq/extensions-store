#!/usr/bin/env python
import json

from eiq_edk import ExporterProcess

from packer import to_ms_sentinel_json
from upload_helper import Oauth2Service, MicrosoftSentinelService, MSSentinelException

MS_SENTINEL_API = "https://graph.microsoft.com/beta/"
PACKAGE_LIMIT = 100


class MainApp(ExporterProcess):

    def pack_data(self, raw_data):

        self.send_info(
            {
                "code": "INF-0001",
                "message": "Execution started",
                "description": "MS-Sentinel started packing data"
            }
        )

        data = json.loads(raw_data.decode())
        update_strategy = self.args.update_strategy
        packed_data = to_ms_sentinel_json(update_strategy, data)
        self.save_packed_data(json.dumps(packed_data).encode())

        self.send_info(
            {
                "code": "INF-0003",
                "message": "Execution completed successfully",
                "description": "MS-Sentinel packed_data  completed successfully."
            }
        )

        stash_dict = {self.config['tenant_id']: {}}
        self.save_stash(stash_dict)

    def upload_data(self, raw_data=None):

        self.send_info(
            {
                "code": "INF-0001",
                "message": "Execution started",
                "description": "MS-Sentinel started uploading data"
            }
        )

        # stash = {self.config['tenant_id']: {}} # need to be added in function above
        try:
            token_service = Oauth2Service(
                stash=self.stash,
                auth_url="https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                scope_field="scope",
                scope_value="https://graph.microsoft.com/.default",
                tenant_id=self.config['tenant_id'],
                client_id=self.config['client_id'],
                client_secret=self.config['client_secret'],
            )
            ms_sentinel_service = MicrosoftSentinelService(
                self.config.get('api_url', MS_SENTINEL_API), token_service
            )
        except MSSentinelException as ex:
            self.send_error(ex.message)

        self.send_info({
            "code": "INF-0002",
            "message": "State transition",
            "description": "Run state make Oauth2 token"
        })
        new_indicators = []
        deleted_indicators = []

        pushed_indicators = []
        if self.stash.get("pushed_indicators"):
            pushed_indicators = self.stash["pushed_indicators"].split(",")

            # in REPLACE mode, first delete everything pushed by this feed
        if self.args.update_strategy == "REPLACE" and pushed_indicators:
            deleted_indicators.extend(pushed_indicators)
            pushed_indicators = []

        populate_indicator_lists(
            new_indicators,
            deleted_indicators,
            json.loads(raw_data.decode()),
            self.args.update_strategy,
        )
        package = []
        for index, indicator in enumerate(deleted_indicators):
            package.append(indicator)
            if len(package) == PACKAGE_LIMIT or index == len(deleted_indicators) - 1:
                try:
                    ms_sentinel_service.delete_indicators(package)
                except MSSentinelException as ex:
                    self.send_error(ex.message)
                package = []

        for index, indicator in enumerate(new_indicators):

            package.append(indicator)
            if len(package) == PACKAGE_LIMIT or index == len(new_indicators) - 1:
                try:
                    ms_sentinel_service.submit_indicators(package)
                except MSSentinelException as ex:
                    self.send_error(ex.message)
                package = []

        # store all new Sentinel indicator externalIds in local stash
        pushed_indicators.extend([item["externalId"] for item in new_indicators])
        self.stash['pushed_indicators'] = ",".join(list(set(pushed_indicators)))

        self.send_info({
            "code": "INF-0003",
            "message": "Execution completed successfully",
            "description": f"{len(new_indicators)} indicators pushed successfully."
        })
        self.save_stash(self.stash)


def populate_indicator_lists(
        new_indicators, deleted_indicators, indicators, update_strategy
):
    if not indicators:
        return

    if update_strategy == "DIFF":
        _new_indicators, _deleted_indicators = split_indicators(indicators)
        new_indicators.extend(_new_indicators)
        deleted_indicators.extend(_deleted_indicators)
    else:
        for external_id in indicators.keys():
            for key in indicators[external_id].keys():
                new_indicators.append(indicators[external_id][key])


def split_indicators(indicators):
    """
    Sort out what's for submit endpoint and what's for delete endpoint.
    :param indicators: list of outgoing feed block indicators
    :return: lists of new and deleted indicators
    """
    new_indicators = []
    deleted_indicators = []
    for external_id in indicators.keys():
        if indicators[external_id].get("deleted"):
            deleted_indicators.append(external_id)
        else:
            new_indicators.extend(indicators[external_id].values())
    return new_indicators, deleted_indicators


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
