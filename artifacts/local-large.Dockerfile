FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ARG FLOSS_REPO_URL=https://github.com/iachang/floss.git
ARG FLOSS_REPO_REF=

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    git \
    iproute2 \
    sudo \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root

RUN if [ -n "$FLOSS_REPO_REF" ]; then \
      git clone --depth 1 --branch "$FLOSS_REPO_REF" "$FLOSS_REPO_URL" /root/repo; \
    else \
      git clone --depth 1 "$FLOSS_REPO_URL" /root/repo; \
    fi

WORKDIR /root/repo

RUN touch mp-spdz-0.4.2/CONFIG.mine \
    && if ! grep -qxF "MY_CFLAGS += -DINSECURE -Wno-error=unused-parameter" mp-spdz-0.4.2/CONFIG.mine; then echo "MY_CFLAGS += -DINSECURE -Wno-error=unused-parameter" >> mp-spdz-0.4.2/CONFIG.mine; fi

RUN chmod +x ./artifacts/prereq-install.sh ./scripts/setup-opmcc-bench.sh ./scripts/bench_opmcc.sh \
    && ./artifacts/prereq-install.sh

CMD ["bash"]
