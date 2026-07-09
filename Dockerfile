# ai-protect — batteries-included image.
#
# Bakes in the high-value scanners that install reliably so `ai-protect doctor`
# lights up out of the box, with zero host setup. The remaining adapters
# (Burp, Metasploit, garak/pyrit, …) stay opt-in — see the README.
#
# Heavy but included: CodeQL (semantic SAST) and Presidio (PHI/PII, needs the
# ~400 MB en_core_web_lg spaCy model). Together they add ~2-3 GB to the image;
# the trade is that `codeql` and `presidio` report live out of the box.
#
#   docker build -t ai-protect .
#   docker run --rm -p 8000:8000 -v ai-protect-data:/home/aip/.ai-protect ai-protect
#   # → dashboard at http://localhost:8000
#
# For the full stack (UI + a ZAP DAST daemon), use docker-compose.yml instead.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps: downloaders + a few scanner runtimes (perl→nikto-style, etc.).
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git unzip jq \
    && rm -rf /var/lib/apt/lists/*

# --- single-binary scanners via official, arch-aware installers ---
# Using upstream install.sh scripts (not pinned release URLs) so the build
# stays arch-portable and doesn't rot as release naming changes.
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
 && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin \
 && curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin \
 && curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
 && curl -sSfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b /usr/local/bin \
 && grype version && syft version && trufflehog --version && trivy --version && gosec --version

# --- CodeQL bundle (semantic SAST) ---
# The BUNDLE, not the bare CLI: it ships the precompiled query packs so the
# `<lang>-security-extended` suite resolves offline (see ai_protect/adapters/codeql.py).
# linux64 asset = x86_64; latest release resolved at build time via the API.
RUN CODEQL_URL="$(curl -sSfL https://api.github.com/repos/github/codeql-action/releases/latest \
        | jq -r '.assets[] | select(.name=="codeql-bundle-linux64.tar.gz") | .browser_download_url')" \
 && curl -sSfL "$CODEQL_URL" -o /tmp/codeql.tar.gz \
 && tar xzf /tmp/codeql.tar.gz -C /opt \
 && rm /tmp/codeql.tar.gz \
 && ln -s /opt/codeql/codeql /usr/local/bin/codeql \
 && codeql --version

WORKDIR /app

# Install the project first (its own deps), then the pip-installable scanners
# as a second layer so a project-only change doesn't re-resolve the scanners.
COPY pyproject.toml README.md LICENSE ./
COPY ai_protect ./ai_protect
RUN pip install . \
 && pip install \
        semgrep \
        bandit \
        detect-secrets \
        pip-audit \
        checkov \
        modelscan \
        njsscan \
        presidio-analyzer \
 && python -m spacy download en_core_web_lg

# Non-root runtime user; data home is a volume so findings/config persist.
RUN useradd --create-home --uid 10001 aip \
 && mkdir -p /home/aip/.ai-protect \
 && chown -R aip:aip /home/aip
USER aip
ENV HOME=/home/aip
VOLUME /home/aip/.ai-protect

EXPOSE 8000
# Bind 0.0.0.0 deliberately — required to reach the UI from outside the
# container (the app defaults to loopback for host safety).
CMD ["ai-protect-ui", "--host", "0.0.0.0", "--port", "8000"]
