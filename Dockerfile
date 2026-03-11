FROM rust:1.76

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    git

COPY . .

RUN cargo build --release

EXPOSE 8333

CMD ["./target/release/misaka-node","--network","devnet","--data-dir","/data"]
