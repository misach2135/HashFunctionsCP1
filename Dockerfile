FROM rust:1.82

WORKDIR /home/app
COPY . .

RUN cargo install --path .
CMD [ "cp" ]