# syntax=docker/dockerfile:1

# ---------- estágio de build ----------
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/secscan ./cmd/secscan

# ---------- imagem final: mínima, sem shell, usuário não-root ----------
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/secscan /secscan
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/secscan"]
CMD ["serve"]
