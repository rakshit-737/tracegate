PY ?= python

.PHONY: test test-real lint demo data scans bench bench-typo bench-lineage bench-images bench-scale serve

test:          ## unit tests on committed fixtures (what CI runs)
	$(PY) -m pytest -q -m "not realdata"

test-real:     ## tests on the full downloaded datasets
	$(PY) -m pytest -q -m realdata

lint:
	$(PY) -m ruff check .

demo:
	$(PY) -m tracegate.cli demo

data:          ## OSV dumps, popularity lists, Syft/Trivy binaries, real repos (~450 MB)
	$(PY) scripts/download_data.py all

scans:         ## run real Syft + Trivy over the pinned images and cloned repos
	$(PY) scripts/scan_real.py all

bench: bench-typo bench-lineage bench-images bench-scale

bench-typo:
	$(PY) benchmarks/typosquat_eval.py

bench-lineage:
	$(PY) benchmarks/lineage_eval.py --snapshots 12

bench-images:
	$(PY) benchmarks/images_eval.py

bench-scale:
	$(PY) benchmarks/scale_eval.py

serve:
	$(PY) -m tracegate.cli serve
