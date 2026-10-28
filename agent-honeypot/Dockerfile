FROM python:3.12-slim
LABEL org.opencontainers.image.title="agent-honeypot" \
      org.opencontainers.image.description="Deception controls for AI-agent insider risk" \
      org.opencontainers.image.source="https://github.com/cybersmeashish/cybernonics_tools"
RUN useradd --create-home --uid 10001 honeypot && mkdir -p /state /agent-workspace \
    && chown honeypot:honeypot /state /agent-workspace
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY agent_honeypot ./agent_honeypot
RUN pip install --no-cache-dir ".[yaml]"
USER honeypot
ENV AGENT_HONEYPOT_STATE=/state
EXPOSE 8080
HEALTHCHECK NONE
ENTRYPOINT ["agent-honeypot"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
