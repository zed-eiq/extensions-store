#!/usr/bin/env python3
from eiq_edk import EnrichmentProcess


class MainApp(EnrichmentProcess):

    def enrich(self, kind: str, value: str):
        print("download data page by page and update pagination context")

    def supported_extract_types(self) -> tp.List[ExtractType]:
        print("Return list of supported extract types")


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
