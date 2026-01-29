#!/bin/bash

set -e

BACKUP_DIR="/backup/honeypy"
LOG_DIR="/var/log/honeypy"
DATA_DIR="/var/lib/honeypy"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="honeypy_backup_${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

echo "Iniciando backup do HoneyPy..."
echo "Timestamp: ${TIMESTAMP}"
echo "Backup path: ${BACKUP_PATH}"

mkdir -p "${BACKUP_DIR}"
mkdir -p "${BACKUP_PATH}"

echo "Backup de logs..."
if [ -d "${LOG_DIR}" ]; then
    cp -r "${LOG_DIR}" "${BACKUP_PATH}/logs"
    echo "Logs copiados"
else
    echo "Diretório de logs não encontrado: ${LOG_DIR}"
fi

echo "Backup de dados..."
if [ -d "${DATA_DIR}" ]; then
    cp -r "${DATA_DIR}" "${BACKUP_PATH}/data"
    echo "Dados copiados"
else
    echo "Diretório de dados não encontrado: ${DATA_DIR}"
fi

echo "Backup de configuração..."
if [ -d "/etc/honeypy" ]; then
    cp -r "/etc/honeypy" "${BACKUP_PATH}/config"
    echo "Configuração copiada"
else
    echo "Diretório de configuração não encontrado: /etc/honeypy"
fi

echo "Criando arquivo de metadados..."
cat > "${BACKUP_PATH}/metadata.txt" << EOF
HoneyPy Backup
==============
Timestamp: ${TIMESTAMP}
Backup ID: ${BACKUP_NAME}
System: $(uname -a)
HoneyPy Version: $(honeypy --version 2>/dev/null || echo "Desconhecido")
Directories:
- Logs: ${LOG_DIR}
- Data: ${DATA_DIR}
- Config: /etc/honeypy
EOF

echo "Criando arquivo compactado..."
cd "${BACKUP_DIR}"
tar -czf "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}"

echo "Limpando diretório temporário..."
rm -rf "${BACKUP_PATH}"

echo "Verificando backup..."
BACKUP_FILE="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
if [ -f "${BACKUP_FILE}" ]; then
    BACKUP_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
    echo "Backup criado com sucesso!"
    echo "Arquivo: ${BACKUP_FILE}"
    echo "Tamanho: ${BACKUP_SIZE}"
    
    echo "Backups antigos..."
    find "${BACKUP_DIR}" -name "honeypy_backup_*.tar.gz" -mtime +30 -type f | while read old_backup; do
        echo "Removendo backup antigo: ${old_backup}"
        rm -f "${old_backup}"
    done
else
    echo "ERRO: Backup não foi criado!"
    exit 1
fi

echo "Backup concluído!"