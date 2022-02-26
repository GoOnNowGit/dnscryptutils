FROM debian:buster-slim
LABEL maintainer "goonnowgit <goonnowgittt@gmail.com>"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y --no-install-recommends \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir dnsstamps requests toml

COPY dnsstamps-to-rules.py utils.py rules.py .

ENTRYPOINT ["python3", "dnsstamps-to-rules.py"]
CMD ["--help"]
