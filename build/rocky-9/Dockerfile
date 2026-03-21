FROM --platform=linux/amd64 rockylinux:9
LABEL org.opencontainers.image.authors="support@halon.io"

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN yum update -y && yum install -y epel-release

RUN echo "[halon]" >> /etc/yum.repos.d/Halon.repo
RUN echo "name=Halon repository" >> /etc/yum.repos.d/Halon.repo
RUN echo "baseurl=https://${HALON_REPO_USER}:${HALON_REPO_PASS}@repo.halon.io/dists/rhel9/amd64/stable" >> /etc/yum.repos.d/Halon.repo
RUN echo "gpgcheck=1" >> /etc/yum.repos.d/Halon.repo
RUN echo "gpgkey=https://raw.githubusercontent.com/halon/changelog/master/pgp-keys/7F0A73B5.asc" >> /etc/yum.repos.d/Halon.repo
RUN echo "enabled=1" >> /etc/yum.repos.d/Halon.repo
RUN yum install -y halon-6.0.0

RUN yum install -y cmake3 make gcc-c++ rpm-build

RUN echo -n "ROCKY9" > /OSRELEASE.txt

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
