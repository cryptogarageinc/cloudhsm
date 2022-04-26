FROM golang:1.18.1-alpine3.14 as cloudhsm_util_container

RUN apk add --update --no-cache musl gcc g++ make git cmake openssl-dev opensc

RUN mkdir -p /github/workspace

WORKDIR /github/workspace

ENTRYPOINT ["/bin/sh", "-l", "-c"]
