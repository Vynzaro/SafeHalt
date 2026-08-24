.PHONY: test check

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

check: test
	PYTHONPATH=src python3 -m compileall -q src
	bash -n install.sh uninstall.sh
