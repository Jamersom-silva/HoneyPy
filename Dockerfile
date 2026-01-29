FROM python:3.9-slim

# Define variáveis de ambiente
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HONEYPY_HOME=/opt/honeypy

# Instala dependências do sistema
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    curl \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Cria usuário não-root
RUN useradd -r -s /bin/false honeypy

# Cria diretórios
RUN mkdir -p $HONEYPY_HOME \
    /etc/honeypy \
    /var/log/honeypy \
    /var/lib/honeypy

# Copia arquivos do projeto
COPY . $HONEYPY_HOME/

# Define permissões
RUN chown -R honeypy:honeypy $HONEYPY_HOME \
    /var/log/honeypy \
    /var/lib/honeypy

# Instala dependências Python
WORKDIR $HONEYPY_HOME
RUN pip install --no-cache-dir -r requirements.txt

# Expõe porta da API (se habilitada)
EXPOSE 8080

# Muda para usuário honeypy
USER honeypy

# Comando de inicialização
CMD ["python", "honeypy.py", "--monitor"]