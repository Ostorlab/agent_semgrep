FROM python:3.11-alpine as base
FROM base as builder
RUN apk add build-base
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt
FROM base
RUN apk add libmagic curl wget jq
COPY --from=builder /install /usr/local

ARG ARTIFACT_NAME="musllinux_x86"
RUN DOWNLOAD_LINK=$(curl -s https://api.github.com/repos/opengrep/opengrep/releases \
    | jq -r --arg name "$ARTIFACT_NAME" '[.[] | select(.assets | length > 0)][0].assets[] | select(.name | test($name)).browser_download_url' | head -n 1)\
    && wget -O /usr/bin/opengrep "$DOWNLOAD_LINK" \
    && chmod +x /usr/bin/opengrep

RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY oxo.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3.11", "/app/agent/opengrep_agent.py"]
