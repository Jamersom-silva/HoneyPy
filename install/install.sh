#!/bin/bash
# Script de instalação completo do HoneyPy

set -e

echo "=========================================="
echo "       HoneyPy - Instalação              "
echo "=========================================="

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para imprimir mensagens
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verifica se é root
if [ "$EUID" -ne 0 ]; then
    print_error "Por favor, execute como root ou com sudo"
    exit 1
fi

# Variáveis
INSTALL_DIR="/opt/honeypy"
CONFIG_DIR="/etc/honeypy"
LOG_DIR="/var/log/honeypy"
DATA_DIR="/var/lib/honeypy"
BIN_DIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"

print_info "Criando estrutura de diretórios..."

# Cria diretórios principais
mkdir -p $INSTALL_DIR
mkdir -p $CONFIG_DIR
mkdir -p $LOG_DIR
mkdir -p $DATA_DIR/{logs,reports,state,databases}
mkdir -p $DATA_DIR/reports/{daily,weekly,monthly}

print_info "Copiando arquivos do sistema..."

# Copia código fonte
cp -r src/ $INSTALL_DIR/src/
cp honeypy.py $INSTALL_DIR/
cp pyproject.toml $INSTALL_DIR/
cp requirements.txt $INSTALL_DIR/

# Copia configurações
cp config/default_config.json $CONFIG_DIR/
cp config/production_config.json $CONFIG_DIR/

# Copia scripts
cp -r scripts/ $INSTALL_DIR/scripts/
chmod +x $INSTALL_DIR/scripts/*.sh

# Copia documentação
cp -r docs/ $INSTALL_DIR/docs/

print_info "Configurando permissões..."

# Define permissões
chown -R root:root $INSTALL_DIR
chmod 755 $INSTALL_DIR
chmod 644 $CONFIG_DIR/*.json

# Cria link simbólico para o executável
ln -sf $INSTALL_DIR/honeypy.py $BIN_DIR/honeypy
chmod +x $BIN_DIR/honeypy

print_info "Instalando dependências Python..."

# Instala dependências Python
if command -v pip3 &> /dev/null; then
    pip3 install -r $INSTALL_DIR/requirements.txt
else
    print_warning "pip3 não encontrado, instalando..."
    apt-get update && apt-get install -y python3-pip
    pip3 install -r $INSTALL_DIR/requirements.txt
fi

print_info "Configurando serviço systemd..."

# Configura serviço systemd
cp install/systemd/honeypy.service $SERVICE_DIR/
cp install/systemd/honeypy@.service $SERVICE_DIR/

systemctl daemon-reload
systemctl enable honeypy.service

print_info "Configurando logrotate..."

# Configura logrotate
cat > /etc/logrotate.d/honeypy << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 root root
    sharedscripts
    postrotate
        systemctl reload honeypy.service > /dev/null 2>&1 || true
    endscript
}
EOF

print_info "Configurando cron jobs..."

# Configura tarefas cron
crontab -l > /tmp/honeypy_cron 2>/dev/null || true

cat >> /tmp/honeypy_cron << EOF
# HoneyPy - Backup diário de logs
0 2 * * * $INSTALL_DIR/scripts/backup_logs.sh > /dev/null 2>&1

# HoneyPy - Geração de relatório semanal
0 3 * * 0 $BIN_DIR/honeypy --report --type weekly > /dev/null 2>&1

# HoneyPy - Limpeza de relatórios antigos
0 4 * * * find $DATA_DIR/reports -name "*.json" -mtime +90 -delete
EOF

crontab /tmp/honeypy_cron
rm /tmp/honeypy_cron

print_info "Criando usuário dedicado..."

# Cria usuário dedicado para o serviço
if ! id -u honeypy &>/dev/null; then
    useradd -r -s /bin/false -d $DATA_DIR honeypy
fi

# Ajusta permissões do usuário
chown -R honeypy:honeypy $LOG_DIR
chown -R honeypy:honeypy $DATA_DIR

print_info "Configurando firewall..."

# Configura regras básicas do firewall
if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
    ufw allow 22/tcp comment "SSH"
    ufw --force enable
fi

print_info "Criando arquivo de configuração inicial..."

# Cria arquivo de configuração inicial se não existir
if [ ! -f $CONFIG_DIR/config.json ]; then
    cp $CONFIG_DIR/production_config.json $CONFIG_DIR/config.json
    
    # Gera token de API aleatório
    API_TOKEN=$(openssl rand -hex 32)
    sed -i "s/\"auth_token\": \"\"/\"auth_token\": \"$API_TOKEN\"/" $CONFIG_DIR/config.json
    
    print_info "Token de API gerado: $API_TOKEN"
    print_warning "Guarde este token em local seguro!"
fi

print_info "Testando instalação..."

# Testa a instalação
if $BIN_DIR/honeypy --version; then
    print_info "Teste concluído com sucesso!"
else
    print_error "Falha no teste da instalação"
    exit 1
fi

cat << EOF

==========================================
    HoneyPy - Instalação Concluída!
==========================================

Diretórios:
  Instalação:   $INSTALL_DIR
  Configuração: $CONFIG_DIR
  Logs:         $LOG_DIR
  Dados:        $DATA_DIR

Comandos disponíveis:
  Iniciar:      systemctl start honeypy
  Parar:        systemctl stop honeypy
  Status:       systemctl status honeypy
  Logs:         journalctl -u honeypy -f
  Configurar:   nano $CONFIG_DIR/config.json

Acesso web (se habilitado):
  http://localhost:8080

Documentação:
  $INSTALL_DIR/docs/

==========================================
EOF

print_info "Iniciando serviço..."
systemctl start honeypy.service

print_info "Verificando status..."
sleep 2
systemctl status honeypy.service --no-pager