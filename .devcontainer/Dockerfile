FROM --platform=linux/amd64 ubuntu:24.04
LABEL org.opencontainers.image.authors="support@halon.io"

ARG HALON_REPO_USER
ENV HALON_REPO_USER=$HALON_REPO_USER
ARG HALON_REPO_PASS
ENV HALON_REPO_PASS=$HALON_REPO_PASS

RUN apt-get update

RUN apt-get install -y wget gnupg
RUN apt-get install -y apt-transport-https

RUN wget -qO - https://raw.githubusercontent.com/halon/changelog/master/pgp-keys/7F0A73B5.asc | apt-key add -
RUN echo "deb https://repo.halon.io/ noble stable" >> /etc/apt/sources.list.d/halon.list
RUN echo "machine repo.halon.io login ${HALON_REPO_USER} password ${HALON_REPO_PASS}" >> /etc/apt/auth.conf
RUN apt-get update && apt-get install -y halon=6.3.0

RUN /usr/bin/install -d /var/run/halon
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH

RUN apt-get install -y build-essential cmake git curl

RUN echo -n "UBU2404" > /OSRELEASE.txt

RUN mkdir /tmp/halon
RUN cd /tmp/halon \
    && curl -O -L https://go.dev/dl/go1.23.4.linux-amd64.tar.gz \
    && echo "6924efde5de86fe277676e929dc9917d466efa02fb934197bc2eba35d5680971 go1.23.4.linux-amd64.tar.gz" | sha256sum -c \
    && tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz
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

COPY .devcontainer/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

RUN apt-get install -y supervisor
COPY .devcontainer/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
CMD ["/usr/bin/supervisord"]
