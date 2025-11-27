FROM golang:latest AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgpgme-dev \
    libbtrfs-dev \
    libdevmapper-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /home/appuser && chown 1000:1000 /home/appuser

WORKDIR /app

ADD . /app

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOEXPERIMENT=jsonv2 go build -o supervisor cmd/noyra/main.go

RUN echo "appuser:x:1000:1000::/home/appuser:/sbin/nologin" > /tmp/passwd && \
    echo "appgroup:x:1000:" > /tmp/group

FROM debian

COPY --from=builder /tmp/passwd /etc/passwd
COPY --from=builder /tmp/group /etc/group

COPY --from=builder --chown=1000:1000 /home/appuser /home/appuser
COPY --from=builder /app/supervisor /

USER 1000:1000
ENV HOME=/home/appuser

ENTRYPOINT ["sleep", "6000"]
