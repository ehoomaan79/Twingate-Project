.PHONY: test controller relay connector client

PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python)

test:
	$(PYTHON) -m unittest discover -s tests -v

controller:
	$(PYTHON) modules/controller/service.py --config modules/controller/config.example.toml

relay:
	$(PYTHON) modules/relay/service.py --config modules/relay/config.example.toml

connector:
	$(PYTHON) modules/connector/service.py --config modules/connector/config.example.toml

client:
	$(PYTHON) modules/client/service.py --config modules/client/config.example.toml
