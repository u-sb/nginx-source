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

=== TEST 1: zstd_bypass skips compression when predicate is truthy
--- http_config
    map $http_x_no_zstd $zstd_off {
        default 0;
        "1"     1;
    }
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_bypass $zstd_off;
        default_type text/plain;
        root html;
        try_files /../../../t/suite/test =404;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
X-No-Zstd: 1
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 2: zstd_bypass value "0" does NOT bypass
--- http_config
    map $http_x_no_zstd $zstd_off {
        default 0;
        "1"     1;
    }
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_bypass $zstd_off;
        default_type text/plain;
        root html;
        try_files /../../../t/suite/test =404;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
X-No-Zstd: 0
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 3: zstd_bypass_vary appends the named field to Vary
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_bypass      $http_x_no_compression;
        zstd_bypass_vary X-No-Compression;
        default_type text/plain;
        root html;
        try_files /../../../t/suite/test =404;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: X-No-Compression
--- no_error_log
[error]



=== TEST 4: zstd_bypass identity arm still advertises Vary
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_bypass      $http_x_no_compression;
        zstd_bypass_vary X-No-Compression;
        default_type text/plain;
        root html;
        try_files /../../../t/suite/test =404;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
X-No-Compression: 1
--- response_headers
!Content-Encoding
Vary: X-No-Compression
--- no_error_log
[error]
