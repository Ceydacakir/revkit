FROM python:3.12-slim
WORKDIR /work
COPY requirements.txt .
RUN pip install -U pip && pip install -r requirements.txt
COPY . .
RUN pip install -e .
ENTRYPOINT ["revkit"]
