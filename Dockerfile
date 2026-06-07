# ── Stage 1 : outils recon ProjectDiscovery (Go) ────────────────────────────
FROM golang:1.23-alpine AS pdtools
RUN apk add --no-cache git
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ── Stage 2 : image finale (Python + binaires recon) ────────────────────────
FROM python:3.13-slim
WORKDIR /app

# Binaires Go (le httpx PD, pas l'homonyme Python) — isolés dans l'image
COPY --from=pdtools /go/bin/subfinder /go/bin/httpx /go/bin/nuclei /usr/local/bin/

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV PYTHONPATH=/app
# Point d'entrée = la CLI bb. Tout tourne DANS le conteneur, séparé de l'hôte.
ENTRYPOINT ["python", "-m", "bb"]
CMD ["--help"]
