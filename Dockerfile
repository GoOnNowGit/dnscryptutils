FROM python:3-alpine
LABEL maintainer "goonnowgit <goonnowgittt@gmail.com>"

ENV MINISIGN_VERSION=0.10

RUN apk update && apk add curl
RUN pip3 install --no-cache-dir setuptools toml

RUN curl -LO https://github.com/jedisct1/minisign/releases/download/"${MINISIGN_VERSION}"/minisign-"${MINISIGN_VERSION}"-linux.tar.gz \
    && tar xf minisign-"${MINISIGN_VERSION}"-linux.tar.gz \
    && install minisign-"${MINISIGN_VERSION}"-linux/x86_64/minisign /usr/local/bin

COPY src/ src/
COPY dnsstamps-to-rules.py .
COPY pyproject.toml .
COPY setup.py .

RUN python3 setup.py install

ENTRYPOINT ["python3", "dnsstamps-to-rules.py"]
CMD ["--help"]
