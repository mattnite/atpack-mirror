FROM golang:1.23-alpine AS builder

COPY main.go go.mod go.sum .
RUN CGO_ENABLED=0 go build -o /atpack-mirror ./main.go

FROM alpine:3.21.3

COPY --from=builder /atpack-mirror /atpack-mirror

CMD ["/atpack-mirror"]
