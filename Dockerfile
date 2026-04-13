FROM python:3.11-alpine as base
FROM base as builder
RUN apk add build-base
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --upgrade pip
RUN pip install --prefix=/install -r /requirement.txt
FROM base
RUN apk add libmagic bash curl
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh -o /tmp/install-opengrep.sh \
    && bash /tmp/install-opengrep.sh -v v1.19.0 \
    && rm /tmp/install-opengrep.sh
COPY --from=builder /install /usr/local
ENV PATH="/root/.opengrep/cli/latest:${PATH}"
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3.11", "/app/agent/semgrep_agent.py"]
