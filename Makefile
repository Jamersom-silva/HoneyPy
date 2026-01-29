.PHONY: install test run clean docker-build docker-run docs

# Variáveis
PYTHON = python3
PIP = pip3
VENV = venv
SRC_DIR = src
TEST_DIR = tests
CONFIG_DIR = config

# Instalação
install: venv
	$(VENV)/bin/pip install -r requirements.txt
	$(VENV)/bin/pip install -e .

# Ambiente virtual
venv:
	$(PYTHON) -m venv $(VENV)

# Testes
test:
	$(PYTHON) -m pytest $(TEST_DIR) -v

test-coverage:
	$(PYTHON) -m pytest $(TEST_DIR) --cov=$(SRC_DIR) --cov-report=html

# Execução
run:
	$(PYTHON) honeypy.py --monitor

run-dev:
	$(PYTHON) honeypy.py --monitor --config $(CONFIG_DIR)/development_config.json

# Docker
docker-build:
	docker build -t honeypy:latest .

docker-run:
	docker run -d --name honeypy --network host \
		-v ./config:/etc/honeypy \
		-v honeypy_data:/var/lib/honeypy \
		honeypy:latest

docker-stop:
	docker stop honeypy && docker rm honeypy

# Documentação
docs:
	cd docs && make html

# Limpeza
clean:
	rm -rf $(VENV)
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf __pycache__
	rm -rf $(SRC_DIR)/__pycache__
	rm -rf $(TEST_DIR)/__pycache__
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name ".coverage" -delete

# Formatação
format:
	$(VENV)/bin/black $(SRC_DIR) $(TEST_DIR)
	$(VENV)/bin/isort $(SRC_DIR) $(TEST_DIR)

# Linting
lint:
	$(VENV)/bin/flake8 $(SRC_DIR) $(TEST_DIR)
	$(VENV)/bin/mypy $(SRC_DIR)

# Backup
backup:
	./scripts/backup_logs.sh

# Help
help:
	@echo "Comandos disponíveis:"
	@echo "  make install     - Instala dependências"
	@echo "  make test        - Executa testes"
	@echo "  make run         - Executa o HoneyPy"
	@echo "  make docker-build- Constrói imagem Docker"
	@echo "  make clean       - Limpa arquivos temporários"
	@echo "  make format      - Formata código"
	@echo "  make lint        - Verifica qualidade do código"
	@echo "  make backup      - Faz backup dos logs"