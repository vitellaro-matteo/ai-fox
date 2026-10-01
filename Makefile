# Every target forwards to scripts/tasks.py, so each one also works without
# make:  python scripts/tasks.py <target>
# On Windows use mingw32-make instead of make.

PYTHON ?= python
TASKS := up down logs test lock ingest seed import-workflows export-workflows \
         eval demo demo-offline reset stats

.PHONY: $(TASKS) help
help:
	@$(PYTHON) scripts/tasks.py

$(TASKS):
	@$(PYTHON) scripts/tasks.py $@
