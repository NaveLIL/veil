FROM golang:1.26.5-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o veil-gateway ./cmd/gateway

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /app/veil-gateway /app/veil-gateway
EXPOSE 8080
ENTRYPOINT ["/app/veil-gateway"]
