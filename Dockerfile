# syntax=docker/dockerfile:1

# ---- build ------------------------------------------------------------------
FROM golang:1.23-alpine AS build
WORKDIR /src

# Dependencies first so edits to source do not invalidate the module layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /out/airlock ./cmd/airlock

# ---- test -------------------------------------------------------------------
# `make docker-test` builds this stage. CGO is needed for -race.
FROM golang:1.23-alpine AS test
WORKDIR /src
RUN apk add --no-cache gcc musl-dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go vet ./... && go test -race -count=1 ./...

# ---- runtime ----------------------------------------------------------------
# Distroless-style: a static binary and a CA bundle, nothing else. Airlock
# handles prompts, so the smaller the surface the better.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 airlock \
 && mkdir -p /home/airlock/.airlock \
 && chown -R airlock:airlock /home/airlock

COPY --from=build /out/airlock /usr/local/bin/airlock

USER airlock
WORKDIR /home/airlock
EXPOSE 4455

# Bind to all interfaces inside the container; publish it narrowly on the host.
#   docker run -p 127.0.0.1:4455:4455 -v $PWD/airlock.yaml:/home/airlock/airlock.yaml airlock
ENTRYPOINT ["airlock"]
CMD ["run", "--policy", "/home/airlock/airlock.yaml", "--listen", "0.0.0.0:4455"]
