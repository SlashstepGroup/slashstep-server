FROM rust:1.93.1-slim
LABEL org.opencontainers.image.title="Slashstep Server"
LABEL org.opencontainers.image.authors="Christian Toney <christian.toney@beastslash.com>"
LABEL org.opencontainers.image.source="https://github.com/SlashstepGroup/slashstep-server"

WORKDIR /usr/src/app
COPY . .
RUN apt-get update -y
RUN apt-get install -y pkg-config libssl-dev
RUN cargo build --release

ARG POSTGRESQL_HOST="localhost"
ENV POSTGRESQL_HOST=${POSTGRESQL_HOST}
ARG POSTGRESQL_PORT="5432"
ENV POSTGRESQL_PORT=${POSTGRESQL_PORT}
ARG POSTGRESQL_USERNAME="postgres"
ENV POSTGRESQL_USERNAME=${POSTGRESQL_USERNAME}
ARG POSTGRESQL_PASSWORD_PATH="./secrets/postgresql-password.txt"
ENV POSTGRESQL_PASSWORD_PATH=${POSTGRESQL_PASSWORD_PATH}
ARG MAXIMUM_POSTGRESQL_CONNECTION_COUNT="5"
ENV MAXIMUM_POSTGRESQL_CONNECTION_COUNT=${MAXIMUM_POSTGRESQL_CONNECTION_COUNT}
ARG JWT_PUBLIC_KEY_PATH="./secrets/jwt-public-key.pem"
ENV JWT_PUBLIC_KEY_PATH=${JWT_PUBLIC_KEY_PATH}
ARG JWT_PRIVATE_KEY_PATH="./secrets/jwt-private-key.pem"
ENV JWT_PRIVATE_KEY_PATH=${JWT_PRIVATE_KEY_PATH}
ARG APP_PORT="3001"
ENV APP_PORT=${APP_PORT}
EXPOSE ${APP_PORT}

ENTRYPOINT ["/usr/src/app/target/release/slashstep-server"]