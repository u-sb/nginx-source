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

=== TEST 1: a response large enough to recycle output buffers is intact
Exercises the free-list path in ngx_http_zstd_filter_get_buf(). A buffer coming
back round carries the flags it was last sent with, and a stale last_buf would
truncate the response.
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_buffers 4 4k;
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



=== TEST 2: many sequential requests over one connection stay correct
--- config
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_buffers 4 4k;
        zstd_types text/plain;
        default_type text/plain;
        root html;
        try_files /../../../t/suite/test =404;
    }
--- pipelined_requests eval
["GET /t", "GET /t", "GET /t", "GET /t"]
--- more_headers
Accept-Encoding: zstd
--- error_code eval
[200, 200, 200, 200]
--- no_error_log
[error]
