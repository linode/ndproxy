FROM debian:bullseye
COPY ndproxy /usr/sbin
#this won't work in docker since we'll need icmp6 access
#EXPOSE 179/tcp
ENTRYPOINT ["/usr/sbin/ndproxy"]
