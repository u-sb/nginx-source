# Copyright (C) 2026 SB Maintainers
# Copyright (C) 2026 Thijs Eilander (myguard-labs)
# Copyright (C) Alex Zhang
#
use Test::Nginx::Socket 'no_plan';

no_long_string();
no_shuffle();

our $config = <<'EOC';
    zstd on;
    zstd_min_length 1;
    zstd_types text/plain text/html;
    default_type text/plain;

    location /200 {
        return 200 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    }

    location /204 {
        return 204;
    }

    location /206 {
        # Simulate partial content response
        add_header Content-Range 'bytes 0-9/100';
        return 206 'aaaaaaaaaa';
    }

    location /403 {
        return 403 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    }

    location /302 {
        return 302 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    }
EOC

run_tests();

__DATA__

=== TEST 1: 200 OK response is compressed
--- config eval: $::config
--- request
GET /200
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 2: 206 Partial Content is not compressed
--- config eval: $::config
--- request
GET /206
--- more_headers
Accept-Encoding: zstd
--- error_code: 206
--- response_headers
!Content-Encoding
Content-Range: bytes 0-9/100
--- no_error_log
[error]



=== TEST 3: 204 No Content is not compressed
--- config eval: $::config
--- request
GET /204
--- more_headers
Accept-Encoding: zstd
--- error_code: 204
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 4: 403 Forbidden is compressed
--- config eval: $::config
--- request
GET /403
--- more_headers
Accept-Encoding: zstd
--- error_code: 403
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 5: 302 Found is not compressed
--- config eval: $::config
--- request
GET /302
--- more_headers
Accept-Encoding: zstd
--- error_code: 302
--- response_headers
!Content-Encoding
--- no_error_log
[error]
