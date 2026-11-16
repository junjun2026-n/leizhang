FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock && useradd --uid 10001 --create-home jump
RUN python -m playwright install --with-deps chromium && chmod -R a+rX /ms-playwright
COPY --chown=jump:jump . .
RUN mkdir -p /app/ssh-host-key && chown jump:jump /app/ssh-host-key
USER jump
EXPOSE 8200
CMD ["uvicorn","jump_ssh.main:create_app","--factory","--host","0.0.0.0","--port","8200","--workers","1","--no-proxy-headers","--ws-max-size","32768"]
