FROM debian:sid-slim
LABEL maintainer "goonnowgit <goonnowgittt@gmail.com>"

ENV MINISIGN_VERSION=0.10
ENV ARCH=x86_64

COPY src/ src/
COPY dnsstamps-to-rules.py .
COPY pyproject.toml .
COPY setup.py .

RUN apt update -qq && apt install -qqy ca-certificates python3 python3-setuptools bash curl --no-install-recommends \
    && curl -LO https://github.com/jedisct1/minisign/releases/download/"${MINISIGN_VERSION}"/minisign-"${MINISIGN_VERSION}"-linux.tar.gz \
    && tar xf minisign-"${MINISIGN_VERSION}"-linux.tar.gz \
    && install minisign-"${MINISIGN_VERSION}"-linux/"${ARCH}"/minisign /usr/local/bin \
    && python3 setup.py install \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["python3", "dnsstamps-to-rules.py"]
CMD ["--help"]
