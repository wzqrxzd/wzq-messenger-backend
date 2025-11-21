FROM debian:trixie

RUN apt update && apt install -y \
  git \
  build-essential \
  cmake \
  libspdlog-dev \
  libpq-dev \
  libssl-dev \
  libargon2-dev \
  libsodium-dev \
  libasio-dev \
  libpqxx-dev \
  && rm -rf /var/lib/apt/lists/*


WORKDIR /usr/local/app

COPY . .
EXPOSE 8080

RUN cmake -S . -B build
COPY .env ./build
RUN cd build && make -j$(nproc)
