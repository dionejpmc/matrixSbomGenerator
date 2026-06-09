# matrix/docker/app/Dockerfile
FROM python:3.12-slim

# Evita a geração de arquivos .pyc e garante logs em tempo real
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Instala dependências de sistema necessárias
RUN apt-get update && apt-get install -y \
    postgresql-client \
    libmagic1 \
    curl \
    gcc \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin


# Instala as dependências Python (Argon2, Django 5, Neo4j, etc.)
# Certifique-se de que o arquivo requirements.txt existe em matrix/app/
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código da aplicação e scripts de inicialização
COPY app/ /app/
COPY scripts/ /scripts/

RUN apt-get update && apt-get install -y \
    postgresql-client \
    libmagic1 \
    curl \
    squashfs-tools \
    e2fsprogs \
    && rm -rf /var/lib/apt/lists/*

# Garante permissão de execução para o entrypoint (vital para Mac/Linux)
RUN chmod +x /scripts/*.sh



# O entrypoint aguarda DB/Neo4j antes de rodar migrations
ENTRYPOINT ["/scripts/entrypoint.sh"]