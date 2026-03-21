FROM --platform=linux/amd64 ubuntu:24.04
LABEL org.opencontainers.image.authors="support@halon.io"

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN apt-get update

RUN apt-get update && apt-get install -y wget gnupg
RUN apt-get update && apt-get install -y apt-transport-https

RUN wget -qO - https://raw.githubusercontent.com/halon/pgp-keys/master/pgp-keys/7F0A73B5.gpg | tee /usr/share/keyrings/halon-archive-keyring.gpg > /dev/null
RUN echo "deb [arch=`dpkg --print-architecture` signed-by=/usr/share/keyrings/halon-archive-keyring.gpg] https://repo.halon.io/ noble stable" >> /etc/apt/sources.list.d/halon.list
RUN echo "machine repo.halon.io login ${HALON_REPO_USER} password ${HALON_REPO_PASS}" >> /etc/apt/auth.conf
RUN apt-get update && apt-get install -y halon=6.3.0

RUN apt-get update && apt-get install -y build-essential cmake git curl file

RUN echo -n "UBU2404" > /OSRELEASE.txt

RUN mkdir /tmp/halon
RUN cd /tmp/halon \
    && curl -O -L https://go.dev/dl/go1.26.1.linux-amd64.tar.gz \
    && echo "031f088e5d955bab8657ede27ad4e3bc5b7c1ba281f05f245bcc304f327c987a go1.26.1.linux-amd64.tar.gz" | sha256sum -c \
    && tar -C /usr/local -xzf go1.26.1.linux-amd64.tar.gz
RUN /usr/local/go/bin/go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin"

RUN mkdir /licenses
RUN cp /usr/local/go/LICENSE /licenses/LICENSE.go
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/ProtonMail/go-crypto/refs/heads/main/LICENSE \
    && cp LICENSE /licenses/LICENSE.go-crypto
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/ProtonMail/gopenpgp/refs/heads/main/LICENSE \
    && cp LICENSE /licenses/LICENSE.gopenpgp
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/cloudflare/circl/refs/heads/main/LICENSE \
    && cp LICENSE /licenses/LICENSE.circl
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/davecgh/go-spew/refs/heads/master/LICENSE \
    && cp LICENSE /licenses/LICENSE.go-spew
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/pmezard/go-difflib/refs/heads/master/LICENSE \
    && cp LICENSE /licenses/LICENSE.go-difflib
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/stretchr/testify/refs/heads/master/LICENSE \
    && cp LICENSE /licenses/LICENSE.testify
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/go-yaml/yaml/refs/tags/v3.0.1/LICENSE \
    && cp LICENSE /licenses/LICENSE.go-yaml

RUN rm -rf /tmp/halon

COPY build.sh /build.sh
CMD ["/build.sh"]
