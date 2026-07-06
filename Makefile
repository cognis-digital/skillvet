# skillvet — stdlib-only core; dev extras add pytest (+ optional shrike-sec).
PYTHON ?= python3

.PHONY: help install install-content dev test demos smoke sarif lint clean

help:
	@echo "make install         install skillvet (core, no runtime deps)"
	@echo "make install-content install with the optional shrike-sec content scan"
	@echo "make dev             install dev extras (pytest)"
	@echo "make test            run the pytest suite"
	@echo "make demos           run every demo (demos/run_all.py)"
	@echo "make smoke           CLI smoke test: vet benign+malicious, sarif, baseline+diff"
	@echo "make sarif           emit SARIF for the malicious demo"

install:
	$(PYTHON) -m pip install .

install-content:
	$(PYTHON) -m pip install ".[content]"

dev:
	$(PYTHON) -m pip install -e ".[dev]" || $(PYTHON) -m pip install pytest

test:
	$(PYTHON) -m pytest -q

demos:
	$(PYTHON) demos/run_all.py

smoke:
	$(PYTHON) -m skillvet.cli vet demos/benign-skill --no-content;    test $$? -eq 0
	$(PYTHON) -m skillvet.cli vet demos/malicious-skill --no-content; test $$? -eq 2
	$(PYTHON) -m skillvet.cli vet demos/malicious-skill --no-content -f sarif > /dev/null
	$(PYTHON) -m skillvet.cli baseline demos/rugpull/v1-benign --no-content -o /tmp/skillvet_bl.json
	$(PYTHON) -m skillvet.cli diff /tmp/skillvet_bl.json demos/rugpull/v2-malicious --no-content; test $$? -eq 2
	@echo "smoke OK"

sarif:
	$(PYTHON) -m skillvet.cli vet demos/malicious-skill --no-content -f sarif

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
