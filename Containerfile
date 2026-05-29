FROM rust:1.93.1-slim
LABEL org.opencontainers.image.title="Slashstep Server"
LABEL org.opencontainers.image.authors="Christian Toney <christian.toney@beastslash.com>"
LABEL org.opencontainers.image.source="https://github.com/SlashstepGroup/slashstep-server"

WORKDIR /usr/src/app
COPY . .
RUN apt-get update -y
RUN apt-get install -y pkg-config libssl-dev
RUN cargo build --release

ENTRYPOINT ["/usr/src/app/target/release/slashstep-server"]