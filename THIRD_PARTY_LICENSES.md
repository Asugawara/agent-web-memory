# Third-party licences

The `awm` binary and the container image (`Dockerfile`) bundle the Rust crates below, statically linked. `awm` itself is Apache-2.0 (see `LICENSE`).

Generated on 2026-10-02 from `cargo metadata --format-version 1 --locked --features sync,serve --filter-platform x86_64-unknown-linux-gnu` run on `crates/awm` (`agent-web-memory`, which pulls in `awm-proto` and `awm-server` with its `all` features): the normal and build dependencies reachable from the root, development dependencies excluded, the three workspace crates excluded. The licence is the SPDX expression in each crate's manifest; where it offers a choice (`OR`), any of the alternatives may be used. Regenerate it whenever `Cargo.lock` changes. Every licence below is on the allow-list of `deny.toml`, which `scripts/check.sh` enforces with `cargo deny check licenses`.

247 crates, 21 distinct licence expressions.

## Summary

| licence expression | crates |
|---|---|
| MIT OR Apache-2.0 | 138 |
| MIT | 37 |
| Unicode-3.0 | 18 |
| Apache-2.0 OR MIT | 16 |
| MIT/Apache-2.0 | 13 |
| Apache-2.0 OR ISC OR MIT | 3 |
| BSD-3-Clause | 3 |
| Unlicense OR MIT | 3 |
| Apache-2.0 | 2 |
| ISC | 2 |
| Unlicense/MIT | 2 |
| (MIT OR Apache-2.0) AND Unicode-3.0 | 1 |
| Apache-2.0 / MIT | 1 |
| Apache-2.0 AND ISC | 1 |
| Apache-2.0 OR BSL-1.0 | 1 |
| Apache-2.0 OR BSL-1.0 OR MIT | 1 |
| CDLA-Permissive-2.0 | 1 |
| MIT AND BSD-3-Clause | 1 |
| MPL-2.0 | 1 |
| Zlib | 1 |
| Zlib OR Apache-2.0 OR MIT | 1 |

## MIT OR Apache-2.0

| crate | version | repository |
|---|---|---|
| aead | 0.6.1 | https://github.com/RustCrypto/traits |
| anstream | 1.0.0 | https://github.com/rust-cli/anstyle.git |
| anstyle | 1.0.14 | https://github.com/rust-cli/anstyle.git |
| anstyle-parse | 1.0.0 | https://github.com/rust-cli/anstyle.git |
| anstyle-query | 1.1.5 | https://github.com/rust-cli/anstyle.git |
| anyhow | 1.0.104 | https://github.com/dtolnay/anyhow |
| asn1-rs | 0.7.2 | https://github.com/rusticata/asn1-rs.git |
| asn1-rs-derive | 0.6.0 | https://github.com/rusticata/asn1-rs.git |
| async-trait | 0.1.92 | https://github.com/dtolnay/async-trait |
| base64 | 0.22.1 | https://github.com/marshallpierce/rust-base64 |
| base64 | 0.23.1 | https://github.com/marshallpierce/rust-base64 |
| bitflags | 2.13.2 | https://github.com/bitflags/bitflags |
| block-buffer | 0.12.1 | https://github.com/RustCrypto/utils |
| cc | 1.5.1 | https://github.com/rust-lang/cc-rs |
| cfg-if | 1.0.5 | https://github.com/rust-lang/cfg-if |
| chacha20 | 0.10.2 | https://github.com/RustCrypto/stream-ciphers |
| chrono | 0.4.45 | https://github.com/chronotope/chrono |
| cipher | 0.5.2 | https://github.com/RustCrypto/traits |
| clap | 4.6.7 | https://github.com/clap-rs/clap |
| clap_builder | 4.6.7 | https://github.com/clap-rs/clap |
| clap_derive | 4.6.7 | https://github.com/clap-rs/clap |
| clap_lex | 1.1.1 | https://github.com/clap-rs/clap |
| colorchoice | 1.0.5 | https://github.com/rust-cli/anstyle.git |
| cpufeatures | 0.3.1 | https://github.com/RustCrypto/utils |
| crc-fast | 1.10.0 | https://github.com/awesomized/crc-fast-rust |
| crypto-common | 0.1.7 | https://github.com/RustCrypto/traits |
| crypto-common | 0.2.2 | https://github.com/RustCrypto/traits |
| deadpool | 0.13.1 | https://github.com/deadpool-rs/deadpool |
| deadpool-postgres | 0.14.2 | https://github.com/deadpool-rs/deadpool |
| deadpool-runtime | 0.3.1 | https://github.com/deadpool-rs/deadpool |
| der-parser | 10.0.0 | https://github.com/rusticata/der-parser.git |
| deranged | 0.5.8 | https://github.com/jhpratt/deranged |
| digest | 0.10.7 | https://github.com/RustCrypto/traits |
| digest | 0.11.3 | https://github.com/RustCrypto/traits |
| directories | 6.0.0 | https://github.com/soc/directories-rs |
| dirs-sys | 0.5.0 | https://github.com/dirs-dev/dirs-sys-rs |
| displaydoc | 0.2.7 | https://github.com/yaahc/displaydoc |
| either | 1.18.0 | https://github.com/rayon-rs/either |
| errno | 0.3.14 | https://github.com/lambda-fairy/rust-errno |
| find-msvc-tools | 0.1.14 | https://github.com/rust-lang/cc-rs |
| form_urlencoded | 1.2.2 | https://github.com/servo/rust-url |
| futures-channel | 0.3.34 | https://github.com/rust-lang/futures-rs |
| futures-core | 0.3.34 | https://github.com/rust-lang/futures-rs |
| futures-io | 0.3.34 | https://github.com/rust-lang/futures-rs |
| futures-macro | 0.3.34 | https://github.com/rust-lang/futures-rs |
| futures-sink | 0.3.34 | https://github.com/rust-lang/futures-rs |
| futures-task | 0.3.34 | https://github.com/rust-lang/futures-rs |
| futures-util | 0.3.34 | https://github.com/rust-lang/futures-rs |
| getrandom | 0.2.17 | https://github.com/rust-random/getrandom |
| getrandom | 0.4.3 | https://github.com/rust-random/getrandom |
| hashbrown | 0.17.1 | https://github.com/rust-lang/hashbrown |
| hashlink | 0.12.2 | https://github.com/djc/hashlink |
| heck | 0.5.0 | https://github.com/withoutboats/heck |
| hkdf | 0.13.0 | https://github.com/RustCrypto/KDFs/ |
| hmac | 0.13.0 | https://github.com/RustCrypto/MACs |
| http | 1.5.0 | https://github.com/hyperium/http |
| httparse | 1.10.1 | https://github.com/seanmonstar/httparse |
| httpdate | 1.0.3 | https://github.com/pyfisch/httpdate |
| humantime | 2.4.0 | https://github.com/chronotope/humantime |
| hybrid-array | 0.4.15 | https://github.com/RustCrypto/hybrid-array |
| iana-time-zone | 0.1.65 | https://github.com/strawlab/iana-time-zone |
| idna | 1.1.0 | https://github.com/servo/rust-url/ |
| inout | 0.2.2 | https://github.com/RustCrypto/utils |
| ipnet | 2.12.2 | https://github.com/krisprice/ipnet |
| is_terminal_polyfill | 1.70.2 | https://github.com/polyfill-rs/is_terminal_polyfill |
| itertools | 0.15.0 | https://github.com/rust-itertools/itertools |
| itoa | 1.0.18 | https://github.com/dtolnay/itoa |
| lazy_static | 1.5.1 | https://github.com/rust-lang-nursery/lazy-static.rs |
| libc | 0.2.189 | https://github.com/rust-lang/libc |
| lock_api | 0.4.14 | https://github.com/Amanieu/parking_lot |
| log | 0.4.34 | https://github.com/rust-lang/log |
| md-5 | 0.11.0 | https://github.com/RustCrypto/hashes |
| mime | 0.3.17 | https://github.com/hyperium/mime |
| num-bigint | 0.4.8 | https://github.com/rust-num/num-bigint |
| num-conv | 0.2.2 | https://github.com/jhpratt/num-conv |
| num-integer | 0.1.47 | https://github.com/rust-num/num-integer |
| num-traits | 0.2.19 | https://github.com/rust-num/num-traits |
| num_threads | 0.1.7 | https://github.com/jhpratt/num_threads |
| oid-registry | 0.8.1 | https://github.com/rusticata/oid-registry.git |
| once_cell | 1.21.4 | https://github.com/matklad/once_cell |
| openssl-probe | 0.2.1 | https://github.com/rustls/openssl-probe |
| parking_lot | 0.12.5 | https://github.com/Amanieu/parking_lot |
| parking_lot_core | 0.9.12 | https://github.com/Amanieu/parking_lot |
| percent-encoding | 2.3.2 | https://github.com/servo/rust-url/ |
| pkg-config | 0.3.34 | https://github.com/rust-lang/pkg-config-rs |
| postgres-protocol | 0.6.12 | https://github.com/rust-postgres/rust-postgres |
| postgres-types | 0.2.14 | https://github.com/rust-postgres/rust-postgres |
| powerfmt | 0.2.0 | https://github.com/jhpratt/powerfmt |
| proc-macro2 | 1.0.107 | https://github.com/dtolnay/proc-macro2 |
| quote | 1.0.47 | https://github.com/dtolnay/quote |
| rand | 0.10.3 | https://github.com/rust-random/rand |
| rand_core | 0.10.1 | https://github.com/rust-random/rand_core |
| rcgen | 0.14.10 | https://github.com/rustls/rcgen |
| regex | 1.13.1 | https://github.com/rust-lang/regex |
| regex-automata | 0.4.18 | https://github.com/rust-lang/regex |
| regex-syntax | 0.8.11 | https://github.com/rust-lang/regex |
| reqwest | 0.13.5 | https://github.com/seanmonstar/reqwest |
| rustc_version | 0.4.1 | https://github.com/djc/rustc-version-rs |
| rustls-pki-types | 1.15.1 | https://github.com/rustls/pki-types |
| rustls-platform-verifier | 0.7.1 | https://github.com/rustls/rustls-platform-verifier |
| scopeguard | 1.2.0 | https://github.com/bluss/scopeguard |
| semver | 1.0.28 | https://github.com/dtolnay/semver |
| serde | 1.0.229 | https://github.com/serde-rs/serde |
| serde_core | 1.0.229 | https://github.com/serde-rs/serde |
| serde_derive | 1.0.229 | https://github.com/serde-rs/serde |
| serde_json | 1.0.151 | https://github.com/serde-rs/json |
| serde_path_to_error | 0.1.20 | https://github.com/dtolnay/path-to-error |
| serde_spanned | 1.1.1 | https://github.com/toml-rs/toml |
| sha2 | 0.11.0 | https://github.com/RustCrypto/hashes |
| shlex | 2.0.1 | https://github.com/comex/rust-shlex |
| signal-hook-registry | 1.4.8 | https://github.com/vorner/signal-hook |
| siphasher | 1.0.4 | https://github.com/jedisct1/rust-siphash |
| smallvec | 1.16.2 | https://github.com/servo/rust-smallvec |
| socket2 | 0.6.5 | https://github.com/rust-lang/socket2 |
| stable_deref_trait | 1.2.1 | https://github.com/storyyeller/stable_deref_trait |
| syn | 2.0.119 | https://github.com/dtolnay/syn |
| syn | 3.0.6 | https://github.com/dtolnay/syn |
| thiserror | 2.0.21 | https://github.com/dtolnay/thiserror |
| thiserror-impl | 2.0.21 | https://github.com/dtolnay/thiserror |
| time | 0.3.55 | https://github.com/time-rs/time |
| time-core | 0.1.9 | https://github.com/time-rs/time |
| time-macros | 0.2.32 | https://github.com/time-rs/time |
| tokio-postgres | 0.7.18 | https://github.com/rust-postgres/rust-postgres |
| tokio-rustls | 0.26.6 | https://github.com/rustls/tokio-rustls |
| toml | 1.1.6+spec-1.1.0 | https://github.com/toml-rs/toml |
| toml_datetime | 1.1.1+spec-1.1.0 | https://github.com/toml-rs/toml |
| toml_parser | 1.1.3+spec-1.1.0 | https://github.com/toml-rs/toml |
| toml_writer | 1.1.2+spec-1.1.0 | https://github.com/toml-rs/toml |
| typenum | 1.20.1 | https://github.com/paholg/typenum |
| unicode-bidi | 0.3.18 | https://github.com/servo/unicode-bidi |
| unicode-normalization | 0.1.25 | https://github.com/unicode-rs/unicode-normalization |
| universal-hash | 0.6.1 | https://github.com/RustCrypto/traits |
| ureq | 3.4.2 | https://github.com/algesten/ureq |
| ureq-proto | 0.6.4 | https://github.com/algesten/ureq-proto |
| url | 2.5.8 | https://github.com/servo/rust-url |
| utf8-zero | 0.8.1 | https://github.com/algesten/utf8-zero |
| x509-parser | 0.18.1 | https://github.com/rusticata/x509-parser.git |
| yasna | 0.6.0 | https://github.com/qnighy/yasna.rs |

## MIT

| crate | version | repository |
|---|---|---|
| axum | 0.8.9 | https://github.com/tokio-rs/axum |
| axum-core | 0.5.6 | https://github.com/tokio-rs/axum |
| bytes | 1.12.1 | https://github.com/tokio-rs/bytes |
| data-encoding | 2.11.1 | https://github.com/ia0/data-encoding |
| generic-array | 0.14.7 | https://github.com/fizyk20/generic-array.git |
| h2 | 0.4.19 | https://github.com/hyperium/h2 |
| http-body | 1.1.0 | https://github.com/hyperium/http-body |
| http-body-util | 0.1.5 | https://github.com/hyperium/http-body |
| hyper | 1.11.1 | https://github.com/hyperium/hyper |
| hyper-util | 0.1.21 | https://github.com/hyperium/hyper-util |
| libsqlite3-sys | 0.38.2 | https://github.com/rusqlite/rusqlite |
| mio | 1.2.3 | https://github.com/tokio-rs/mio |
| nom | 7.1.3 | https://github.com/Geal/nom |
| pem | 4.0.0 | https://github.com/jcreekmore/pem-rs.git |
| phf | 0.13.1 | https://github.com/rust-phf/rust-phf |
| phf_shared | 0.13.1 | https://github.com/rust-phf/rust-phf |
| quick-xml | 0.41.0 | https://github.com/tafia/quick-xml |
| rusqlite | 0.40.2 | https://github.com/rusqlite/rusqlite |
| slab | 0.4.12 | https://github.com/tokio-rs/slab |
| spin | 0.10.1 | https://github.com/mvdnes/spin-rs.git |
| strsim | 0.11.1 | https://github.com/rapidfuzz/strsim-rs |
| synstructure | 0.13.2 | https://github.com/mystor/synstructure |
| synstructure | 0.14.0 | https://github.com/mystor/synstructure |
| tokio | 1.53.1 | https://github.com/tokio-rs/tokio |
| tokio-macros | 2.7.2 | https://github.com/tokio-rs/tokio |
| tokio-util | 0.7.19 | https://github.com/tokio-rs/tokio |
| tower | 0.5.3 | https://github.com/tower-rs/tower |
| tower-http | 0.6.11 | https://github.com/tower-rs/tower-http |
| tower-layer | 0.3.3 | https://github.com/tower-rs/tower |
| tower-service | 0.3.3 | https://github.com/tower-rs/tower |
| tracing | 0.1.44 | https://github.com/tokio-rs/tracing |
| tracing-attributes | 0.1.31 | https://github.com/tokio-rs/tracing |
| tracing-core | 0.1.36 | https://github.com/tokio-rs/tracing |
| try-lock | 0.2.5 | https://github.com/seanmonstar/try-lock |
| want | 0.3.1 | https://github.com/seanmonstar/want |
| winnow | 1.0.4 | https://github.com/winnow-rs/winnow |
| zmij | 1.0.23 | https://github.com/dtolnay/zmij |

## Unicode-3.0

| crate | version | repository |
|---|---|---|
| icu_collections | 2.3.0 | https://github.com/unicode-org/icu4x |
| icu_locale_core | 2.3.0 | https://github.com/unicode-org/icu4x |
| icu_normalizer | 2.3.0 | https://github.com/unicode-org/icu4x |
| icu_normalizer_data | 2.3.0 | https://github.com/unicode-org/icu4x |
| icu_properties | 2.3.0 | https://github.com/unicode-org/icu4x |
| icu_properties_data | 2.3.0 | https://github.com/unicode-org/icu4x |
| icu_provider | 2.3.1 | https://github.com/unicode-org/icu4x |
| litemap | 0.8.3 | https://github.com/unicode-org/icu4x |
| potential_utf | 0.1.6 | https://github.com/unicode-org/icu4x |
| tinystr | 0.8.4 | https://github.com/unicode-org/icu4x |
| writeable | 0.6.4 | https://github.com/unicode-org/icu4x |
| yoke | 0.8.3 | https://github.com/unicode-org/icu4x |
| yoke-derive | 0.8.4 | https://github.com/unicode-org/icu4x |
| zerofrom | 0.1.8 | https://github.com/unicode-org/icu4x |
| zerofrom-derive | 0.1.8 | https://github.com/unicode-org/icu4x |
| zerotrie | 0.2.5 | https://github.com/unicode-org/icu4x |
| zerovec | 0.11.8 | https://github.com/unicode-org/icu4x |
| zerovec-derive | 0.11.6 | https://github.com/unicode-org/icu4x |

## Apache-2.0 OR MIT

| crate | version | repository |
|---|---|---|
| atomic-waker | 1.1.2 | https://github.com/smol-rs/atomic-waker |
| autocfg | 1.5.1 | https://github.com/cuviper/autocfg |
| bit-vec | 0.9.1 | https://github.com/contain-rs/bit-vec |
| chacha20poly1305 | 0.11.0 | https://github.com/RustCrypto/AEADs |
| cmov | 0.5.4 | https://github.com/RustCrypto/utils |
| const-oid | 0.10.2 | https://github.com/RustCrypto/formats |
| ctutils | 0.4.2 | https://github.com/RustCrypto/utils |
| equivalent | 1.0.2 | https://github.com/indexmap-rs/equivalent |
| idna_adapter | 1.2.2 | https://github.com/hsivonen/idna_adapter |
| indexmap | 2.14.2 | https://github.com/indexmap-rs/indexmap |
| pin-project-lite | 0.2.17 | https://github.com/taiki-e/pin-project-lite |
| poly1305 | 0.9.1 | https://github.com/RustCrypto/universal-hashes |
| utf8_iter | 1.0.4 | https://github.com/hsivonen/utf8_iter |
| utf8parse | 0.2.2 | https://github.com/alacritty/vte |
| uuid | 1.26.1 | https://github.com/uuid-rs/uuid |
| zeroize | 1.9.0 | https://github.com/RustCrypto/utils |

## MIT/Apache-2.0

| crate | version | repository |
|---|---|---|
| asn1-rs-impl | 0.2.0 | https://github.com/rusticata/asn1-rs.git |
| curve25519-dalek-derive | 0.1.1 | https://github.com/dalek-cryptography/curve25519-dalek |
| fallible-iterator | 0.2.0 | https://github.com/sfackler/rust-fallible-iterator |
| fallible-iterator | 0.3.0 | https://github.com/sfackler/rust-fallible-iterator |
| fallible-streaming-iterator | 0.1.9 | https://github.com/sfackler/fallible-streaming-iterator |
| minimal-lexical | 0.2.1 | https://github.com/Alexhuszagh/minimal-lexical |
| object_store | 0.14.2 | https://github.com/apache/arrow-rs-object-store |
| rusticata-macros | 4.1.0 | https://github.com/rusticata/rusticata-macros.git |
| serde_urlencoded | 0.7.1 | https://github.com/nox/serde_urlencoded |
| stringprep | 0.1.5 | https://github.com/sfackler/rust-stringprep |
| unicode-properties | 0.1.4 | https://github.com/unicode-rs/unicode-properties |
| vcpkg | 0.2.15 | https://github.com/mcgoo/vcpkg-rs |
| version_check | 0.9.5 | https://github.com/SergioBenitez/version_check |

## Apache-2.0 OR ISC OR MIT

| crate | version | repository |
|---|---|---|
| hyper-rustls | 0.27.10 | https://github.com/rustls/hyper-rustls |
| rustls | 0.23.45 | https://github.com/rustls/rustls |
| rustls-native-certs | 0.8.4 | https://github.com/rustls/rustls-native-certs |

## BSD-3-Clause

| crate | version | repository |
|---|---|---|
| curve25519-dalek | 5.0.0 | https://github.com/dalek-cryptography/curve25519-dalek/tree/main/curve25519-dalek |
| subtle | 2.6.1 | https://github.com/dalek-cryptography/subtle |
| x25519-dalek | 3.0.0 | https://github.com/dalek-cryptography/curve25519-dalek/tree/main/x25519-dalek |

## Unlicense OR MIT

| crate | version | repository |
|---|---|---|
| aho-corasick | 1.1.5 | https://github.com/BurntSushi/aho-corasick |
| byteorder | 1.5.0 | https://github.com/BurntSushi/byteorder |
| memchr | 2.8.3 | https://github.com/BurntSushi/memchr |

## Apache-2.0

| crate | version | repository |
|---|---|---|
| instant-acme | 0.8.5 | https://github.com/djc/instant-acme |
| sync_wrapper | 1.0.2 | https://github.com/Actyx/sync_wrapper |

## ISC

| crate | version | repository |
|---|---|---|
| rustls-webpki | 0.103.15 | https://github.com/rustls/webpki |
| untrusted | 0.9.0 | https://github.com/briansmith/untrusted |

## Unlicense/MIT

| crate | version | repository |
|---|---|---|
| same-file | 1.0.6 | https://github.com/BurntSushi/same-file |
| walkdir | 2.5.0 | https://github.com/BurntSushi/walkdir |

## (MIT OR Apache-2.0) AND Unicode-3.0

| crate | version | repository |
|---|---|---|
| unicode-ident | 1.0.26 | https://github.com/dtolnay/unicode-ident |

## Apache-2.0 / MIT

| crate | version | repository |
|---|---|---|
| fnv | 1.0.7 | https://github.com/servo/rust-fnv |

## Apache-2.0 AND ISC

| crate | version | repository |
|---|---|---|
| ring | 0.17.14 | https://github.com/briansmith/ring |

## Apache-2.0 OR BSL-1.0

| crate | version | repository |
|---|---|---|
| ryu | 1.0.23 | https://github.com/dtolnay/ryu |

## Apache-2.0 OR BSL-1.0 OR MIT

| crate | version | repository |
|---|---|---|
| whoami | 2.1.3 | https://github.com/ardaku/whoami |

## CDLA-Permissive-2.0

| crate | version | repository |
|---|---|---|
| webpki-roots | 1.0.9 | https://github.com/rustls/webpki-roots |

## MIT AND BSD-3-Clause

| crate | version | repository |
|---|---|---|
| matchit | 0.8.4 | https://github.com/ibraheemdev/matchit |

## MPL-2.0

| crate | version | repository |
|---|---|---|
| option-ext | 0.2.0 | https://github.com/soc/option-ext.git |

## Zlib

| crate | version | repository |
|---|---|---|
| foldhash | 0.2.0 | https://github.com/orlp/foldhash |

## Zlib OR Apache-2.0 OR MIT

| crate | version | repository |
|---|---|---|
| tinyvec | 1.13.3 | https://github.com/Lokathor/tinyvec |
