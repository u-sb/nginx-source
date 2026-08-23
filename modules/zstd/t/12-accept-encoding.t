# Copyright (C) 2026 SB Maintainers
# Copyright (C) GetPageSpeed LLC
#
use Test::Nginx::Socket 'no_plan';

no_long_string();
no_shuffle();

our $config = <<'EOC';
    location /t {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        default_type text/plain;
        return 200 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    }
EOC

run_tests();

__DATA__

=== TEST 1: plain zstd is accepted
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 2: zstd;q=0 is an explicit refusal
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=0
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 3: zstd;q=0.000 is also a refusal
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=0.000
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 4: zstd;q=0.001 is the smallest acceptance
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=0.001
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 5: the wildcard accepts zstd
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: *
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 6: a wildcard refusal declines zstd
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: *;q=0
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 7: an explicit entry overrides a wildcard refusal
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: *;q=0, zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 8: an explicit refusal overrides a wildcard acceptance
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: *, zstd;q=0
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 9: zstd-foo is a different coding, not a zstd match
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: zstd-foo
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 10: notzstd is a different coding too
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: notzstd
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 11: zstd is found among several codings
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: gzip, deflate, br, zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 12: a duplicate q makes the element ambiguous and it is ignored
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=1;q=0
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 13: a quoted parameter value does not hide the coding
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: gzip;foo="bar,zstd", zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 14: a comma inside a quoted string does not create an element
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: gzip;foo="bar,zstd"
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 15: an over-long qvalue fraction is rejected, not truncated
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=0.0000000001
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 16: a huge qvalue digit run cannot overflow into acceptance
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=0.99999999999999999999999999999999999999
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 17: whitespace around the weight is tolerated
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: zstd ; q=0.5
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 18: coding names are case-insensitive
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: ZSTD
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 19: q is case-insensitive
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;Q=0
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 20: an empty list element is skipped
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: gzip,,zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 21: identity only does not accept zstd
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: identity
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 22: a trailing comma is tolerated
--- config eval: $::config
--- request
GET /t
--- more_headers
Accept-Encoding: zstd,
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]
