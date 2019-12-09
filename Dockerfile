FROM golang:1.12.9 AS build-env
WORKDIR /go/src/github.com/deepnetworkgmbh/security-monitor-scanners/

COPY . .
RUN go get -u github.com/gobuffalo/packr/v2/packr2
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 packr2 build -a -o scanners *.go

FROM alpine:3.10.3
WORKDIR /usr/local/bin
RUN apk --no-cache add ca-certificates

RUN addgroup -S scanners && adduser -u 1200 -S scanners -G scanners
USER 1200
COPY --from=build-env /go/src/github.com/deepnetworkgmbh/security-monitor-scanners/scanners .

WORKDIR /opt/app

CMD ["scanners"]
