.PHONY: test demo serve

PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python)

test:
	$(PYTHON) -m unittest discover -s tests -v

demo:
	$(PYTHON) run_simulation.py

serve:
	$(PYTHON) relay_server.py --host 127.0.0.1 --port 9000
