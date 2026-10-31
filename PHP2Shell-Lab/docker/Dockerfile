# OPScaner PHP2Shell Lab - one image, eight simulated systems
# แต่ละคอนเทนเนอร์รัน PHP ในโปรไฟล์ของตัวเอง (etc/appN.ini)
FROM php:8.2-cli

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends iputils-ping procps curl \
 && apt-get clean

WORKDIR /app
COPY common     /app/common
COPY apps       /app/apps
COPY etc        /app/etc
COPY portal.php /app/portal.php
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
 && mkdir -p /app/logs /tmp \
 && chmod -R 0777 /app/apps

ENV LAB_APP=app1 \
    LAB_PORT=8081
EXPOSE 8081
ENTRYPOINT ["/entrypoint.sh"]
