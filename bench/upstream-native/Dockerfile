FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /out/upstream-native .

FROM alpine:3.20
COPY --from=build /out/upstream-native /usr/local/bin/upstream-native
ENTRYPOINT ["/usr/local/bin/upstream-native"]
