FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/gpbox ./cmd/gpbox

FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS novnc
ARG NOVNC_VERSION=1.5.0
ADD --checksum=sha256:6a73e41f98388a5348b7902f54b02d177cb73b7e5eb0a7a0dcf688cc2c79b42a \
    https://github.com/novnc/noVNC/archive/refs/tags/v${NOVNC_VERSION}.tar.gz /tmp/novnc.tar.gz
RUN mkdir -p /opt/novnc \
 && tar -xzf /tmp/novnc.tar.gz -C /tmp \
 && cd /tmp/noVNC-${NOVNC_VERSION} \
 && cp -r app core vendor vnc.html /opt/novnc/

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="gpbox" \
      org.opencontainers.image.description="GlobalProtect VPN in a container" \
      org.opencontainers.image.source="https://github.com/jjezewski/gpbox" \
      org.opencontainers.image.licenses="Zlib"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openconnect ocproxy ca-certificates tini \
      chromium fonts-liberation xvfb x11vnc \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/*

COPY --from=novnc /opt/novnc /opt/novnc
COPY --from=build /out/gpbox /usr/local/bin/gpbox

EXPOSE 1080 6080
VOLUME ["/data"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=30s \
  CMD test -f /tmp/gpbox-connected || exit 1

ENTRYPOINT ["tini", "--", "gpbox"]
