open("{{ cookiecutter.extension_name }}/process.py", "x")

# Code for outgoing type of extension
if "{{ cookiecutter.extension_type }}" == "outgoing":
    with open("{{ cookiecutter.extension_name }}/process.py", "w") as f:
        f.write('''#!/usr/bin/env python3
from eiq_edk import ExporterProcess


class MainApp(ExporterProcess):

    def pack_data(self, raw_data):
        print("Write code for packing data.")

    def upload_data(self, packed_data):
        print("Write code for sending data to write on another environment.")


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
''')


# Code for incoming type of extension
elif "{{ cookiecutter.extension_type }}" == "incoming":
    with open("{{ cookiecutter.extension_name }}/process.py", "w") as f:
        f.write('''#!/usr/bin/env python3
from eiq_edk import ImporterProcess


class MainApp(ImporterProcess):

    def download(self):
        print("Downloading raw data. Add your code here")

    def transform(self, raw_data):
        print("Transform single package of raw data. Add your code here")


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
''')

# Code for enricher type extension
elif "{{ cookiecutter.extension_type }}" == "enricher":
    with open("{{ cookiecutter.extension_name }}/process.py", "w") as f:
        f.write('''#!/usr/bin/env python3
from eiq_edk import EnrichmentProcess


class MainApp(EnrichmentProcess):

    def enrich(self, kind: str, value: str):
        print("download data page by page and update pagination context")

    def supported_extract_types(self) -> tp.List[ExtractType]:
        print("Return list of supported extract types")

if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
''')
