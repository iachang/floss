FROM ubuntu

WORKDIR /MOSAC

# install dependency
RUN apt-get update
RUN apt-get install -y gcc cmake nasm iproute2 npm ninja-build

# install bazelisk
RUN npm install -g @bazel/bazelisk
RUN alias bazel='bazelisk'

# copy source code
COPY . /MOSAC

# copy opm script
COPY /scripts/setup-opmcc-bench.sh /scripts/setup-opmcc-bench.sh
COPY /scripts/bench_opmcc.sh /scripts/bench_opmcc.sh

# install opm and patch
RUN chmod +x /MOSAC/scripts/setup-opmcc-bench.sh
RUN chmod +x /MOSAC/scripts/bench_opmcc.sh
RUN /MOSAC/scripts/setup-opmcc-bench.sh

# It would complie and run all unit-test
# RUN bazel test -c opt //...
