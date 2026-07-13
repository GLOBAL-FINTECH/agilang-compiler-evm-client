FROM python:3.12.4-slim
WORKDIR /opt/agilang
COPY vendor/agilang ./vendor/agilang
COPY compiler_distribution ./compiler_distribution
RUN pip install --no-cache-dir -r compiler_distribution/requirements.txt
ENV AGILANG_COMPILER_HOST=0.0.0.0 AGILANG_COMPILER_PORT=8090 PYTHONHASHSEED=0
EXPOSE 8090
RUN python compiler_distribution/verify_install.py
ENTRYPOINT ["python", "compiler_distribution/compiler_service.py"]
