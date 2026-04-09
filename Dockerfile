FROM python:3.11-alpine as base
FROM base as builder
RUN apk add build-base
RUN mkdir /install /semgrep_app
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --upgrade pip
RUN pip install --prefix=/install -r /requirement.txt
RUN pip install --target=/semgrep_app semgrep==1.99.0
FROM base
RUN apk add libmagic
COPY --from=builder /install /usr/local
COPY --from=builder /semgrep_app /opt/semgrep
ENV PATH="/opt/semgrep/bin:${PATH}"
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app:/opt/semgrep
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3.11", "/app/agent/semgrep_agent.py"]
