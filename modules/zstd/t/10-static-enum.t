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

=== TEST 1: an invalid zstd_static value is rejected with a clean config error
The zstd_static directive is parsed by nginx's ngx_conf_set_enum_slot, which
walks its ngx_conf_enum_t table until it finds a zero-length name:

    for (i = 0; e[i].name.len != 0; i++)

so the table must end in a { ngx_null_string, 0 } sentinel. Without one, an
unrecognised value walks off the end of the array and reads whatever follows it
in .data.rodata until it happens to hit a zero, instead of reporting the error.
--- config
    location /t {
        zstd_static bogus;
        return 200 'ok';
    }
--- must_die
--- error_log
invalid value "bogus"



=== TEST 2: each documented zstd_static value is still accepted
--- config
    location /off    { zstd_static off;    return 200 'off'; }
    location /on     { zstd_static on;     return 200 'on'; }
    location /always { zstd_static always; return 200 'always'; }
--- request
GET /off
--- response_body chomp
off
--- no_error_log
[error]
