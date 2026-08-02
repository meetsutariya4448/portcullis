FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /out/upstream-legacy .

FROM alpine:3.20
COPY --from=build /out/upstream-legacy /usr/local/bin/upstream-legacy
ENTRYPOINT ["/usr/local/bin/upstream-legacy"]
