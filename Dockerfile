FROM rust
RUN mkdir -v /dms
COPY . /dms
WORKDIR /dms
RUN cargo build --release
ENTRYPOINT ["/dms/target/release/dms"]
