FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/guard ./cmd/guard

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/guard /guard
USER 65532:65532
EXPOSE 8081 9090
ENTRYPOINT ["/guard"]
