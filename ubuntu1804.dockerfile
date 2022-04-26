FROM ubuntu:18.04

WORKDIR /cloudhsm_setup

RUN apt-get update && \
    apt-get install -y wget git unzip make gcc g++ opensc && \
    apt-get clean

RUN wget https://dl.google.com/go/go1.18.linux-amd64.tar.gz && \
    tar -xvf go1.18.linux-amd64.tar.gz && \
    mv go /usr/local && \
    wget https://github.com/Kitware/CMake/releases/download/v3.16.2/cmake-3.16.2-Linux-x86_64.tar.gz && \
    tar -xvf cmake-3.16.2-Linux-x86_64.tar.gz && \
    mv cmake-3.16.2-Linux-x86_64 /usr/local/cmake

ENV PATH $PATH:/usr/local/cmake/bin:/usr/local/go/bin

RUN mkdir -p /github/workspace

WORKDIR /github/workspace

ENTRYPOINT ["/bin/sh", "-l", "-c"]
