# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build

ARG VERSION=dev
ARG COMMIT=
ARG BUILD_DATE=

WORKDIR /src

# The module has no external dependencies, so there is nothing to download.
# Copying go.mod first still gives the layer cache something stable to hold.
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0
RUN go build -trimpath \
      -ldflags="-s -w \
        -X github.com/flugschreiber/flugschreiber/internal/version.Version=${VERSION} \
        -X github.com/flugschreiber/flugschreiber/internal/version.Commit=${COMMIT} \
        -X github.com/flugschreiber/flugschreiber/internal/version.Date=${BUILD_DATE}" \
      -o /out/flugschreiber ./cmd/flugschreiber

# Staged here so the final stage can copy it with the right ownership: the base
# image has no shell to mkdir with, and Docker seeds a new named volume from
# the image directory's contents and permissions. Without this, the volume
# would be created root-owned and the nonroot process could not write to it.
RUN mkdir -p /out/data

# distroless static: no shell, no package manager, no libc. There is nothing in
# the image for an attacker who reaches the proxy to pivot into, and nothing
# that shows up in a CVE scan except the binary itself.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/flugschreiber /usr/local/bin/flugschreiber
COPY --from=build --chown=65532:65532 /out/data /var/lib/flugschreiber

# 65532 is the nonroot user in the base image. The evidence directory is a
# volume so that the container filesystem can stay read-only.
USER 65532:65532
VOLUME ["/var/lib/flugschreiber"]
EXPOSE 8080

ENV FLUGSCHREIBER_LISTEN=":8080" \
    FLUGSCHREIBER_DATA_DIR="/var/lib/flugschreiber"

ENTRYPOINT ["/usr/local/bin/flugschreiber"]
CMD ["serve"]
