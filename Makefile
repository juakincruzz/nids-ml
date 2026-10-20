# Por defecto se usa el Python del entorno virtual. En la CI se sobrescribe: make test PY=python
PY ?= .venv/bin/python

.PHONY: help install data train evaluate web test lint format clean

help:
	@echo "make install   crea .venv e instala el proyecto con los extras [dev]"
	@echo "make data      descarga y limpia CIC-IDS2017 (fase 2)"
	@echo "make train     entrena las referencias y el modelo (fase 3)"
	@echo "make evaluate  ejecuta los protocolos y guarda reports/ (fase 3)"
	@echo "make web       arranca el panel en http://127.0.0.1:8000 (fase 6)"
	@echo "make test      pytest (sin los tests marcados como slow)"
	@echo "make lint      ruff check + comprobación de formato"
	@echo "make format    aplica el formato de ruff y los arreglos automáticos"

.venv/bin/python:
	python3 -m venv .venv

install: .venv/bin/python
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

data:
	$(PY) -m nids.data

train:
	$(PY) -m nids.models

evaluate:
	$(PY) -m nids.evaluation

web:
	$(PY) -m nids.web

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

format:
	$(PY) -m ruff format .
	$(PY) -m ruff check --fix .

clean:
	rm -rf .pytest_cache .ruff_cache build dist src/*.egg-info
	find . -name __pycache__ -type d -not -path "./.venv/*" -exec rm -rf {} +
