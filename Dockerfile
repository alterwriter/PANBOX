FROM node:22-alpine AS web
WORKDIR /web
COPY web/package*.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.24-alpine AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/panbox-server ./cmd/panbox-server

FROM alpine:3.21
RUN addgroup -S panbox && adduser -S -G panbox panbox
WORKDIR /app
COPY --from=go /out/panbox-server ./panbox-server
COPY --from=web /web/dist ./web/dist
COPY migrations ./migrations
USER panbox
EXPOSE 8080
ENTRYPOINT ["./panbox-server"]
