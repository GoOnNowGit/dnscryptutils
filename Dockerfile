FROM debian:sid-slim
LABEL maintainer "goonnowgit <goonnowgittt@gmail.com>"

ENV MINISIGN_VERSION=0.10
ENV ARCH=x86_64

COPY src/ src/
COPY dnsstamps-to-rules.py .
COPY pyproject.toml .
COPY setup.py .

RUN buildDeps=' \
	curl \
        python3-setuptools \
	' \
    && set -x \
    && apt update -qq && apt install -qqy $buildDeps --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && apt update -qq && apt install -qqy \
    ca-certificates \
    python3 \
    --no-install-recommends \
    && curl -LO https://github.com/jedisct1/minisign/releases/download/"${MINISIGN_VERSION}"/minisign-"${MINISIGN_VERSION}"-linux.tar.gz \
    && tar xf minisign-"${MINISIGN_VERSION}"-linux.tar.gz \
    && install minisign-"${MINISIGN_VERSION}"-linux/"${ARCH}"/minisign /usr/local/bin \
    && python3 setup.py install \
    && rm -rf minisign-"${MINISIGN_VERSION}"-linux.tar.gz \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get purge -y --auto-remove $buildDeps

ENTRYPOINT ["python3", "dump_sdns_info.py"]
CMD ["--help"]
