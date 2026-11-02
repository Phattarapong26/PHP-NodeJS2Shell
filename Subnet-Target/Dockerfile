# Dockerfile — target ที่ทำตัวเป็นเครื่อง Linux จริงใน subnet (.38 / .40)
# ใช้ base image ของดิสโทรนั้นจริง ๆ เพื่อให้ banner ของ sshd/nginx เป็นของแท้
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

# sshd + nginx + python3 = บริการจริงของดิสโทร (ไม่ใช่ mock server)
RUN if command -v apt-get >/dev/null 2>&1; then \
        apt-get update && apt-get install -y --no-install-recommends \
            openssh-server nginx python3 procps iproute2 ca-certificates curl gcc libc-dev \
        && rm -rf /var/lib/apt/lists/*; \
    elif command -v dnf >/dev/null 2>&1; then \
        dnf -y --allowerasing install openssh-server nginx python3 procps-ng iproute ca-certificates gcc \
        && dnf clean all; \
    else \
        echo "unsupported base image: need apt or dnf" >&2 && exit 1; \
    fi

# kernel fingerprint shim + wrappers
COPY tools/ /tmp/tools/
RUN if [ -f /tmp/tools/fakekernel.c ]; then \
        gcc -O2 -shared -fPIC -o /usr/local/lib/libfakekernel.so /tmp/tools/fakekernel.c -ldl || true; \
    fi && \
    if [ ! -f /usr/local/lib/libfakekernel.so ] && [ -f /tmp/tools/libfakekernel.so ]; then \
        cp /tmp/tools/libfakekernel.so /usr/local/lib/libfakekernel.so; \
    fi && rm -rf /tmp/tools
COPY bin/uname  /usr/local/bin/uname
COPY bin/sysctl /usr/local/bin/sysctl
COPY entrypoint.sh /entrypoint.sh

RUN chmod 0755 /usr/local/bin/uname /usr/local/bin/sysctl /entrypoint.sh \
 && mkdir -p /run/sshd /os /var/log/nginx

EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]
