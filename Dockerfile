FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install curl git gcc gdb make

WORKDIR /home/root

RUN curl -O https://www.openssl.org/source/openssl-3.0.5.tar.gz
RUN tar xzf openssl-3.0.5.tar.gz
WORKDIR ./openssl-3.0.5
RUN ./config
RUN make -j4
RUN make install
ENV LD_LIBRARY_PATH /usr/local/lib64
RUN ldconfig

RUN git clone https://github.com/laurencelundblade/QCBOR.git
WORKDIR ./QCBOR
RUN git checkout 11ea361d803589dcfa38767594236afbc8789f8b
RUN make install

WORKDIR /home/root
RUN git clone https://github.com/laurencelundblade/t_cose.git
WORKDIR ./t_cose
RUN git checkout d5ff4e282d8af34e5756627cf877ab399e7e51af
RUN make -f Makefile.ossl libt_cose.a install

WORKDIR /home/root
RUN ldconfig
COPY . ./libcsuit
WORKDIR ./libcsuit
RUN make -f Makefile.encode -B CC=gcc
RUN make -f Makefile.parser -B CC=gcc

CMD make -f Makefile.parser test