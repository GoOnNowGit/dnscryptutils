FROM debian:buster-slim
LABEL maintainer "goonnowgit <goonnowgittt@gmail.com>"

ENV DEBIAN_FRONTEND=noninteractive \
    MINISIGN_VERSION=0.10

RUN apt update && apt install -y --no-install-recommends \
    python3 \
    python3-pip \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir dnsstamps requests toml

RUN curl -LO https://github.com/jedisct1/minisign/releases/download/"${MINISIGN_VERSION}"/minisign-"${MINISIGN_VERSION}"-linux.tar.gz \
    && tar xf minisign-"${MINISIGN_VERSION}"-linux.tar.gz \
    && install minisign-"${MINISIGN_VERSION}"-linux/x86_64/minisign /usr/local/bin

COPY dnsstamps-to-rules.py utils.py rules.py .

ENTRYPOINT ["python3", "dnsstamps-to-rules.py"]
CMD ["--help"]
