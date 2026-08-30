ARG VEIL_BUILD_COMMIT=development

FROM golang:1.26.6-alpine AS build
ARG VEIL_BUILD_COMMIT
RUN apk add --no-cache nodejs
WORKDIR /src
COPY veil-server/go.mod veil-server/go.sum veil-server/
RUN cd veil-server && go mod download
COPY veil-server/. veil-server/
COPY scripts/generate-third-party-notices.mjs scripts/generate-third-party-notices.mjs
COPY third_party/go-modules.allow third_party/go-modules.allow
RUN node scripts/generate-third-party-notices.mjs \
      --component gateway \
      --repo-root /src \
      --output veil-server/THIRD_PARTY_NOTICES.txt \
    && cd veil-server \
    && CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.buildCommit=${VEIL_BUILD_COMMIT}" \
    -o veil-gateway ./cmd/gateway \
    && CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w" \
    -o veil-admin ./cmd/veil-admin

FROM alpine:3.24
ARG VEIL_BUILD_COMMIT
LABEL org.opencontainers.image.title="Veil Gateway" \
      org.opencontainers.image.description="Self-hosted Veil messaging gateway" \
      org.opencontainers.image.source="https://github.com/NaveLIL/veil" \
      org.opencontainers.image.revision="${VEIL_BUILD_COMMIT}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 veil \
    && adduser -S -D -H -u 10001 -G veil veil \
    && install -d -o veil -g veil /var/veil/uploads \
    && install -d -m 0755 /usr/share/licenses/veil \
    && { \
      printf '%s\n' 'ALPINE RUNTIME PACKAGE INVENTORY'; \
      apk info --from installed --no-network | sort | while IFS= read -r package; do \
        printf '\n'; \
        apk info --from installed --no-network -v "$package"; \
        apk info --from installed --no-network --description "$package"; \
        apk info --from installed --no-network --webpage "$package"; \
        apk info --from installed --no-network --license "$package"; \
      done; \
    } > /usr/share/licenses/veil/ALPINE_PACKAGES.txt
WORKDIR /app
COPY --from=build /src/veil-server/veil-gateway /app/veil-gateway
COPY --from=build /src/veil-server/veil-admin /app/veil-admin
COPY --from=build /src/veil-server/THIRD_PARTY_NOTICES.txt /usr/share/licenses/veil/THIRD_PARTY_NOTICES.txt
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md TRADEMARKS.md /usr/share/licenses/veil/
RUN chmod 0755 /usr/share/licenses /usr/share/licenses/veil \
    && chmod 0644 /usr/share/licenses/veil/ALPINE_PACKAGES.txt \
        /usr/share/licenses/veil/LICENSE \
        /usr/share/licenses/veil/NOTICE \
        /usr/share/licenses/veil/THIRD_PARTY_NOTICES.md \
        /usr/share/licenses/veil/THIRD_PARTY_NOTICES.txt \
        /usr/share/licenses/veil/TRADEMARKS.md
USER veil:veil
EXPOSE 8080
ENTRYPOINT ["/app/veil-gateway"]
