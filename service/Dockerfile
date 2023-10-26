FROM alpine:3.18

RUN apk add libc6-compat
RUN addgroup -g 1337 chef && adduser -D -G chef -u 1337 chef
RUN mkdir /opt/chef && mkdir /opt/chef/storage
ADD ./server /opt/chef/
ADD ./entrypoint.sh /opt/chef/
RUN chown chef:chef -R /opt/chef/* && chmod 744 /opt/chef/server && chmod 744 /opt/chef/entrypoint.sh
WORKDIR /opt/chef
EXPOSE 6666
ENTRYPOINT ["/opt/chef/entrypoint.sh"]