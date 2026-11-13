ARG GO_VERSION=1
FROM golang:${GO_VERSION}-bookworm as builder

WORKDIR /usr/src/app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Cada deploy toma la pseudo-versión más nueva publicada en el proxy.
RUN go get github.com/sensorwave-dev/sensorwave@latest && go build -v -o /run-app .

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /run-app /usr/local/bin/

CMD ["/usr/local/bin/run-app"]