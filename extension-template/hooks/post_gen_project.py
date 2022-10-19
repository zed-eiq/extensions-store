open("{{ cookiecutter.extension_name }}/process.py", "x")

# Code for outgoing type of extension
if "{{ cookiecutter.extension_type }}" == "outgoing":
    with open("{{ cookiecutter.extension_name }}/process.py", "w") as f:
        f.write('''#!/usr/bin/env python
from dev_kit.eiq_edk import ExporterProcess


class MainApp(ExporterProcess):

    def pack_data(self):
        print("Write code for packing data.")

    def upload_data(self, raw_data=None):
        print("Write code for sending data to write on another environment.")


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
''')


# Code for incoming type of extension
elif "{{ cookiecutter.extension_type }}" == "incoming":
    with open("{{ cookiecutter.extension_name }}/process.py", "w") as f:
        f.write('''#!/usr/bin/env python
from dev_kit.eiq_edk import ImporterProcess


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
        f.write('''#!/usr/bin/env python
from dev_kit.eiq_edk import EnrichmentProcess


class MainApp(EnrichmentProcess):

    def download(self):
        print("download data page by page and update pagination context")


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
''')
