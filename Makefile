PY ?= python

.PHONY: test demo bench

test:
	$(PY) -m pytest -q

demo:
	$(PY) -m tracegate.cli demo

bench:
	$(PY) -m tracegate.cli bench --services 50 --deps 100
