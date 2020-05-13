FROM ubuntu:20.04
RUN mkdir /opt/app
WORKDIR /opt/app
EXPOSE 9120
COPY auth-jwt /opt/app
COPY config.toml /opt/app
CMD GIN_MODE=release /opt/app/auth-jwt  