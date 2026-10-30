FROM alpine:latest

# Install PHP and essential modules
RUN apk add --no-cache php php-session php-json

WORKDIR /app

# Copy configuration files
COPY vulnerable/php.ini /etc/php-vuln.ini
COPY hardened/php.ini /etc/php-hardened.ini

# Copy web applications
COPY vulnerable /var/www/vulnerable
COPY hardened /var/www/hardened

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080 8088

ENTRYPOINT ["/entrypoint.sh"]
