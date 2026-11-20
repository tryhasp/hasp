# syntax=docker/dockerfile:1.7

FROM rust:1.98-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS build
RUN apk add --no-cache build-base
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    SQLX_OFFLINE=true \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="-C target-feature=+crt-static --remap-path-prefix=/src=. --remap-path-prefix=/usr/local/cargo=/cargo"
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    target="$(rustc -vV | sed -n 's/^host: //p')" \
 && cargo build --release --locked --target "$target" -p hasp-server --bin haspd \
 && install -D "target/$target/release/haspd" /out/haspd
RUN mkdir -p /out/data /out/secrets

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/haspd /haspd
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/secrets /secrets
ENV PATH=/ \
    HASP_LISTEN=0.0.0.0:8080 \
    HASP_DATA_DIR=/data \
    HASP_SERVER_KEY=/secrets/server.key
USER 65532:65532
EXPOSE 8080
VOLUME ["/data", "/secrets"]
HEALTHCHECK --interval=30s --timeout=6s --start-period=10s --retries=3 CMD ["/haspd", "healthcheck"]
ENTRYPOINT ["/haspd"]
CMD ["serve"]
