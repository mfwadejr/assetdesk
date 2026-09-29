FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN mkdir -p /app/data
ENV ASSETDESK_DB=/app/data/assets.sqlite3
EXPOSE 8080
CMD ["python", "app.py"]
