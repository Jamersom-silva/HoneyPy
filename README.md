# HoneyPy - Sistema de Detecção de Ataques de Brute Force

Sistema de monitoramento de ameaças que detecta ataques de brute force, captura informações dos IPs agressores e gera logs estruturados para análise de incidentes.

## Características

- **Detecção Inteligente**: Análise de padrões de tentativas de acesso
- **Multi-serviço**: Suporte a SSH, FTP, HTTP, MySQL, RDP, e outros
- **Bloqueio Automático**: Integração com iptables para bloqueio em tempo real
- **Logs Estruturados**: JSON para fácil análise e integração com SIEM
- **Relatórios Automáticos**: Diários, semanais e mensais
- **Interface Web**: Dashboard para visualização e gerenciamento
- **GeoIP**: Localização geográfica de atacantes
- **API REST**: Interface para integração com outros sistemas
- **Containerização**: Pronto para Docker e Kubernetes

## Instalação Rápida

### Usando Docker (Recomendado)

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/honeypy.git
cd honeypy

# Configure o arquivo docker-compose.yml
cp docker-compose.example.yml docker-compose.yml
# Edite as configurações conforme necessário

# Inicie o sistema
docker-compose up -d

# Clone o repositório
git clone https://github.com/seu-usuario/honeypy.git
cd honeypy

# Instale dependências
pip install -r requirements.txt

# Configure o sistema
cp config/default_config.json /etc/honeypy/config.json
# Edite o arquivo de configuração conforme necessário

# Execute o script de instalação
sudo ./install/install.sh

# Inicie o serviço
sudo systemctl start honeypy

# Como serviço
sudo systemctl start honeypy

# Manualmente
sudo honeypy --monitor --config /etc/honeypy/config.json

# Relatório diário
sudo honeypy --report --type daily

# Relatório semanal
sudo honeypy --report --type weekly

# Listar IPs suspeitos
sudo honeypy --list-ips --limit 20

# Informações de um IP específico
sudo honeypy --ip-info 192.168.1.100

# Bloquear IP manualmente
sudo honeypy --block-ip 203.0.113.45 --duration 48