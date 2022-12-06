FROM rust:1.64.0
WORKDIR /usr/src/pooper
COPY Cargo.toml .
COPY Cargo.lock .
COPY src/ ./src

RUN cargo install --path .
CMD ["pooper"]
