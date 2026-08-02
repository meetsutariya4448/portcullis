FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/portcullis ./cmd/portcullis

FROM alpine:3.20
RUN adduser -D -u 10001 portcullis
COPY --from=build /out/portcullis /usr/local/bin/portcullis
USER portcullis
ENTRYPOINT ["/usr/local/bin/portcullis"]
