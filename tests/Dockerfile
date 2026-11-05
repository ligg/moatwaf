FROM openresty/openresty:1.31.1.1-4-alpine

RUN apk add --no-cache lua5.1-busted perl
RUN mkdir -p /opt/moat/conf
COPY conf/rules/ /opt/moat/conf/rules/

WORKDIR /workspace
CMD ["/bin/sh", "tests/run_tests.sh"]
