# nginx2root lab image — build with a pinned version:
#   docker build --build-arg NGINX_VERSION=1.31.8 -t nginx2root-lab:vuln ./lab/nginx
ARG NGINX_VERSION=1.31.8
FROM nginx:${NGINX_VERSION}

LABEL org.opencontainers.image.title="nginx2root lab" \
      org.opencontainers.image.description="Pinned nginx target for CVE-2026-123007 exposure validation"

# Replace the stock config with one that enables HTTP/2 over TLS.
COPY nginx.conf /etc/nginx/nginx.conf
COPY html/ /usr/share/nginx/html/

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
    CMD curl -fk https://localhost/healthz || exit 1

EXPOSE 443
