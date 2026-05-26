ARG os
FROM docker.io/library/buildpack-deps:$os

ARG ISA_LEVEL=v1
ARG os
ARG osver
ARG rev=1
ARG version_schema

SHELL ["/bin/bash", "-c"]

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    OPENSSL_DIR=/build/openssl/.openssl \
    OPENSSL_STATIC=1 \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y debhelper devscripts po-debconf dpkg-dev libexpat-dev libgd-dev libgeoip-dev libhiredis-dev libluajit-5.1-dev libmhash-dev libpam0g-dev '^libpcre.-dev$' libperl-dev libssl-dev libxslt1-dev po-debconf quilt zlib1g-dev libmaxminddb-dev libjson-c-dev libclang-dev && \
    apt-get clean

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y && \
    rustc --version && \
    cargo --version

WORKDIR /build

RUN git ls-remote --tags https://github.com/openssl/openssl.git | grep -o 'openssl-3.6.[[:digit:]]\+$' | tail -1 > openssl_tag.txt && \
    sed 's/[OopensSLl._-]//g' openssl_tag.txt > openssl_ver.txt && \
    git ls-remote --tags https://github.com/facebook/zstd.git | grep -o 'v1.5.[[:digit:]]\+$' | tail -1 > zstd_tag.txt && \
    git clone https://github.com/openssl/openssl.git openssl -b "$(cat openssl_tag.txt)" --depth 1 && cat openssl_tag.txt && \
    git clone https://github.com/facebook/zstd.git zstd -b "$(cat zstd_tag.txt)" --depth 1 && cat zstd_tag.txt

RUN case "${ISA_LEVEL}" in \
        v2) ARCH_FLAG="-march=x86-64-v2" ;; \
        v3) ARCH_FLAG="-march=x86-64-v3 -mprefer-vector-width=256" ;; \
        *)  ARCH_FLAG="" ;; \
    esac && \
    echo "STRIP CFLAGS -flto=auto" >> /etc/dpkg/buildflags.conf && \
    echo "STRIP LDFLAGS -flto=auto" >> /etc/dpkg/buildflags.conf && \
    echo "APPEND CFLAGS $ARCH_FLAG" >> /etc/dpkg/buildflags.conf && \
    echo "APPEND LDFLAGS $ARCH_FLAG" >> /etc/dpkg/buildflags.conf && \
    echo "export CFLAGS=\"\$CFLAGS $ARCH_FLAG\"" >> /etc/environment && \
    echo 'make -j'$(nproc)' "$@"' > /bin/make1 && \
    chmod +x /bin/make1

RUN case "${ISA_LEVEL}" in \
        v3) ARCH_FLAG="-march=x86-64-v3 -mprefer-vector-width=256" ;; \
        v2) ARCH_FLAG="-march=x86-64-v2" ;; \
        *)  ARCH_FLAG="" ;; \
    esac && \
    cd /build/zstd/lib && \
    CFLAGS="$ARCH_FLAG -O3" CPPFLAGS="$ARCH_FLAG -O3" make1 libzstd.a

COPY . /build/nginx

WORKDIR /build/nginx

RUN if { [ -n "$osver" ] && [ "$osver" -ge 12 ]; } || [ "$version_schema" = "new" ]; then sed -i '1 s/(/(2:/' debian/changelog; fi && \
    BASE_CHANGELOG_DATE="$(dpkg-parsechangelog -SDate)" && \
    BASE_CHANGELOG_EPOCH="$(date -u -d "$BASE_CHANGELOG_DATE" +%s)" && \
    export SOURCE_DATE_EPOCH="$((BASE_CHANGELOG_EPOCH + 1))" && \
    BUILD_DATE="$(date -u -R -d "@$SOURCE_DATE_EPOCH")" && \
    ISA_SUFFIX=$([ "$ISA_LEVEL" = "v1" ] && echo "" || echo "+$ISA_LEVEL.") && \
    BUILD_SUFFIX="+$(cat ../openssl_ver.txt)+$osver$os$ISA_SUFFIX" && \
    dch --distribution "$os" -l "$BUILD_SUFFIX" "Build on $os" -m && \
    for ((i=1; i<rev; i++)); do dch --distribution "$os" -l "$BUILD_SUFFIX" "Rebuild" -m; done && \
    sed -i "0,/^ -- /s|^\\( -- .*\\)  .*|\\1  $BUILD_DATE|" debian/changelog && \
    test "$(dpkg-parsechangelog -SDate)" = "$BUILD_DATE" && \
    sed -i '68s/\\\\/build_inst_sw \\/' /build/nginx/auto/lib/openssl/make && \
    OPENSSL_OPT=no-apps debian/rules MAKE=make1 binary

WORKDIR /build

RUN rm -f *dbgsym* && \
    mkdir reg && \
    mv *.deb reg

FROM scratch
COPY --from=0 /build/reg /build
