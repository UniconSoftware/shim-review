FROM ubuntu:noble

COPY . /shim-review

RUN sed -i 's/^Types: deb/& deb-src/' /etc/apt/sources.list.d/ubuntu.sources && \
    apt update -y && \
    DEBIAN_FRONTEND=noninteractive apt install -y devscripts && \
    apt build-dep -y shim && \
    cat /etc/apt/sources.list && \
    dpkg -l

RUN git clone --branch main https://github.com/UniconSoftware/shim

WORKDIR /shim
RUN git show --no-patch
RUN git branch --move main master
RUN make update
RUN make VENDOR_CERT_FILE=uc-sb-signing.crt.der
WORKDIR /

# FIXME: This only works on x86-64 efi binary
RUN hexdump -Cv /shim-review/shimx64.efi > orig && \
    hexdump -Cv /shim/shimx64.efi > build && \
    diff -u orig build
