FROM golang:1.16-alpine3.13 as cloudhsm_util_container

RUN apk add --update --no-cache musl gcc g++ make git cmake openssl-dev

RUN mkdir -p /github/workspace

WORKDIR /github/workspace

ENTRYPOINT ["/bin/sh", "-l", "-c"]
