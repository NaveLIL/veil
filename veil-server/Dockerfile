FROM golang:1.25-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o veil-gateway ./cmd/gateway

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /app/veil-gateway /app/veil-gateway
# Bake release artifacts (.deb, .AppImage, SHA256SUMS) into the image.
# The directory always exists in repo (with at least a .gitkeep) so this
# never fails; in CI/dev it may be empty, then /downloads/ returns 404.
COPY cmd/gateway/downloads /app/cmd/gateway/downloads
EXPOSE 8080
ENTRYPOINT ["/app/veil-gateway"]
