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

=== TEST 1: zstd_max_length skips compression when Content-Length exceeds limit
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_max_length 1000;
        zstd_types text/plain;
        default_type text/plain;
        root html;
        try_files /../../../t/suite/test =404;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 2: zstd_max_length allows compression when within limit
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_max_length 1000000;
        zstd_types text/plain;
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
--- no_error_log
[error]



=== TEST 3: zstd_window_log caps compression window
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_window_log 12;
        zstd_types text/plain;
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
--- no_error_log
[error]



=== TEST 4: zstd_long on compresses cleanly
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_long on;
        zstd_types text/plain;
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
--- no_error_log
[error]



=== TEST 5: zstd_target_cblock_size is accepted
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_target_cblock_size 16384;
        zstd_types text/plain;
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
--- no_error_log
[error]



=== TEST 6: $zstd_bytes_in and $zstd_bytes_out variables resolve cleanly
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        default_type text/plain;
        set $test_in  $zstd_bytes_in;
        set $test_out $zstd_bytes_out;
        root html;
        try_files /../../../t/suite/test =404;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]
