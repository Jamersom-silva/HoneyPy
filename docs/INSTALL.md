# Guia de Instalação do HoneyPy

## Requisitos do Sistema

### Hardware Mínimo
- CPU: 1 núcleo
- RAM: 512 MB
- Armazenamento: 1 GB (recomendado 10 GB para logs)

### Software
- Sistema Operacional: Linux (Ubuntu 20.04+, Debian 10+, CentOS 8+)
- Python: 3.8 ou superior
- iptables (para bloqueio de IPs)
- systemd (para execução como serviço)

### Permissões
- Acesso de leitura aos logs do sistema
- Permissão de root para bloqueio com iptables
- Permissão para criar arquivos em `/var/log` e `/var/lib`

## Métodos de Instalação

### 1. Instalação Rápida (Script)

```bash
# Baixe o HoneyPy
git clone https://github.com/yourusername/honeypy.git
cd honeypy

# Execute como root
sudo ./install/install.sh

# 1. Clone o repositório
git clone https://github.com/yourusername/honeypy.git
cd honeypy

# 2. Instale dependências Python
pip install -r requirements.txt

# 3. Crie diretórios
sudo mkdir -p /etc/honeypy
sudo mkdir -p /var/log/honeypy
sudo mkdir -p /var/lib/honeypy/{reports,logs,state,databases}

# 4. Copie configurações
sudo cp config/production_config.json /etc/honeypy/config.json

# 5. Copie binário
sudo cp honeypy.py /usr/local/bin/honeypy
sudo chmod +x /usr/local/bin/honeypy

# 6. Crie usuário
sudo useradd -r -s /bin/false -d /var/lib/honeypy honeypy

# 7. Configure permissões
sudo chown -R honeypy:honeypy /var/log/honeypy /var/lib/honeypy

# 8. Configure systemd
sudo cp install/systemd/honeypy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable honeypy.service



# Construa a imagem
docker build -t honeypy:latest .

# Crie diretórios para dados persistentes
mkdir -p /var/lib/honeypy/{config,logs,data}

# Copie configuração
cp config/production_config.json /var/lib/honeypy/config/

# Execute container
docker run -d \
  --name honeypy \
  --network host \
  --cap-add=NET_ADMIN \
  --restart unless-stopped \
  -v /var/lib/honeypy/config:/etc/honeypy:ro \
  -v /var/lib/honeypy/data:/var/lib/honeypy \
  -v /var/lib/honeypy/logs:/var/log/honeypy \
  -v /var/log:/host_logs:ro \
  honeypy:latest


  # Clone o repositório
git clone https://github.com/yourusername/honeypy.git
cd honeypy

# Configure
cp docker-compose.example.yml docker-compose.yml
# Edite docker-compose.yml conforme necessário

# Inicie
docker-compose up -d