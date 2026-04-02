FROM python:3.11-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制代码
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY content.yaml .
COPY pyproject.toml .

# 创建报告目录
RUN mkdir -p reports

# 暴露端口
EXPOSE 8000

# 环境变量
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# 启动命令
CMD ["python", "-m", "uvicorn", "api_relay_audit.web.main:app", "--host", "0.0.0.0", "--port", "8000"]
