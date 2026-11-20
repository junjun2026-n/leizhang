# ============================================================
# 文件名称：Dockerfile
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：定义应用容器镜像构建步骤。
#           文件用途：供堡垒机的 leizhang/Dockerfile 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
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
