#!/bin/bash

set -e

REPORTS_DIR="/var/lib/honeypy/reports"
ARCHIVE_DIR="/var/lib/honeypy/archived_reports"
DAYS_TO_KEEP=90
COMPRESS_AFTER_DAYS=7

echo "Iniciando rotação de relatórios..."
echo "Diretório de relatórios: ${REPORTS_DIR}"
echo "Diretório de arquivamento: ${ARCHIVE_DIR}"
echo "Manter relatórios por: ${DAYS_TO_KEEP} dias"
echo "Comprimir após: ${COMPRESS_AFTER_DAYS} dias"

mkdir -p "${ARCHIVE_DIR}"

echo "Processando relatórios diários..."
DAILY_DIR="${REPORTS_DIR}/daily"
if [ -d "${DAILY_DIR}" ]; then
    find "${DAILY_DIR}" -name "*.json" -mtime +${COMPRESS_AFTER_DAYS} -type f | while read report; do
        echo "Comprimindo relatório: $(basename ${report})"
        gzip -f "${report}"
    done
    
    find "${DAILY_DIR}" -name "*.json.gz" -mtime +${DAYS_TO_KEEP} -type f | while read report; do
        echo "Arquivando relatório antigo: $(basename ${report})"
        mv "${report}" "${ARCHIVE_DIR}/"
    done
fi

echo "Processando relatórios semanais..."
WEEKLY_DIR="${REPORTS_DIR}/weekly"
if [ -d "${WEEKLY_DIR}" ]; then
    find "${WEEKLY_DIR}" -name "*.json" -mtime +${COMPRESS_AFTER_DAYS} -type f | while read report; do
        echo "Comprimindo relatório semanal: $(basename ${report})"
        gzip -f "${report}"
    done
    
    find "${WEEKLY_DIR}" -name "*.json.gz" -mtime +180 -type f | while read report; do
        echo "Arquivando relatório semanal antigo: $(basename ${report})"
        mv "${report}" "${ARCHIVE_DIR}/"
    done
fi

echo "Processando relatórios mensais..."
MONTHLY_DIR="${REPORTS_DIR}/monthly"
if [ -d "${MONTHLY_DIR}" ]; then
    find "${MONTHLY_DIR}" -name "*.json" -mtime +${COMPRESS_AFTER_DAYS} -type f | while read report; do
        echo "Comprimindo relatório mensal: $(basename ${report})"
        gzip -f "${report}"
    done
    
    find "${MONTHLY_DIR}" -name "*.json.gz" -mtime +365 -type f | while read report; do
        echo "Arquivando relatório mensal antigo: $(basename ${report})"
        mv "${report}" "${ARCHIVE_DIR}/"
    done
fi

echo "Limpando arquivos antigos do diretório de arquivamento..."
find "${ARCHIVE_DIR}" -name "*.gz" -mtime +730 -type f -delete

echo "Verificando espaço em disco..."
echo "Uso do diretório de relatórios:"
du -sh "${REPORTS_DIR}"
echo "Uso do diretório de arquivamento:"
du -sh "${ARCHIVE_DIR}"

echo "Roteação de relatórios concluída!"