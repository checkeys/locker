FROM ghcr.io/bondbox/xpip:latest as builder

WORKDIR /app

COPY . .
RUN pip3 install --break-system-packages -r requirements.txt
RUN xpip-build --debug setup --all

FROM python:3.9-slim as runner

WORKDIR /app

COPY ./xpwauth .
COPY --from=builder /app/dist/*.whl .

RUN pip install --no-cache-dir *.whl

EXPOSE 3000

CMD ["locker", "--stdout", "--debug"]
