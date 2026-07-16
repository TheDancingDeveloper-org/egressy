FROM python:3.14-alpine

RUN addgroup -S validator && adduser -S -G validator validator
WORKDIR /app
COPY external_probe_service.py /app/external_probe_service.py
USER validator
EXPOSE 443
ENTRYPOINT ["python3", "/app/external_probe_service.py"]
