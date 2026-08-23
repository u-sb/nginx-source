# Copyright (C) 2026 SB Maintainers
# Copyright (C) 2026 Thijs Eilander (myguard-labs)
# Copyright (C) GetPageSpeed LLC
# Copyright (C) Alex Zhang
#
use Test::Nginx::Socket 'no_plan';

no_long_string();
no_shuffle();
run_tests();

__DATA__

=== TEST 1: with no .zst present, gzip still compresses the response
ngx_http_zstd_ok() marks the request as gzip-tested and not-gzip-ok as a side
effect of deciding whether the client accepts zstd. The static handler calls it
before it knows whether a .zst file exists, so when none does and the handler
declines, those flags stay set. The gzip filter then short-circuits on

    } else if (!r->gzip_ok) {

and the response is served uncompressed even though the client offered gzip and
gzip is enabled. Deciding not to serve zstd must not veto gzip.
--- config
    gzip on;
    gzip_min_length 1;
    gzip_types text/plain;
    location /t {
        zstd_static on;
        default_type text/plain;
        root html;
        try_files /../../../t/suite/nozst.txt =404;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]



=== TEST 2: a client that offers only gzip still gets gzip
--- config
    gzip on;
    gzip_min_length 1;
    gzip_types text/plain;
    location /t {
        zstd_static on;
        default_type text/plain;
        root html;
        try_files /../../../t/suite/nozst.txt =404;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]



=== TEST 3: a real .zst is still preferred over gzip
--- config
    gzip on;
    gzip_min_length 1;
    gzip_types text/plain;
    location /t {
        zstd_static on;
        default_type text/plain;
        root html;
        try_files /../../../t/suite/test =404;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Encoding: zstd
Content-Length: 20706
--- no_error_log
[error]



=== TEST 4: zstd_static off leaves gzip entirely alone
--- config
    gzip on;
    gzip_min_length 1;
    gzip_types text/plain;
    location /t {
        zstd_static off;
        default_type text/plain;
        root html;
        try_files /../../../t/suite/nozst.txt =404;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]
