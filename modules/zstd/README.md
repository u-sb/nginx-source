# Name
zstd-nginx-module - Nginx module for the [Zstandard compression](https://facebook.github.io/zstd/).

# Table of Contents

* [Status](#status)
* [Synopsis](#synopsis)
* [Set and forget](#set-and-forget)
* [Installation](#installation)
* [Directives](#directives)
  * [ngx_http_zstd_filter_module](#ngx_http_zstd_filter_module)
    * [zstd](#zstd)
    * [zstd_comp_level](#zstd_comp_level)
    * [zstd_min_length](#zstd_min_length)
    * [zstd_max_length](#zstd_max_length)
    * [zstd_types](#zstd_types)
    * [zstd_buffers](#zstd_buffers)
    * [zstd_target_cblock_size](#zstd_target_cblock_size)
    * [zstd_window_log](#zstd_window_log)
    * [zstd_long](#zstd_long)
    * [zstd_max_cctx_memory](#zstd_max_cctx_memory)
    * [zstd_bypass](#zstd_bypass)
    * [zstd_bypass_vary](#zstd_bypass_vary)
    * [zstd_dict_file](#zstd_dict_file)
  * [ngx_http_zstd_static_module](#ngx_http_zstd_static_module)
    * [zstd_static](#zstd_static)
* [Variables](#variables)
  * [$zstd_ratio](#zstd_ratio)
  * [$zstd_bytes_in](#zstd_bytes_in)
  * [$zstd_bytes_out](#zstd_bytes_out)
* [Compatibility](#compatibility)
* [Author](#author)
* [License](#license)

# Status

Production-oriented. This module is a hardened fork maintained specifically for [SB Nginx](https://github.com/u-sb/nginx-source).

It originates from the upstream [tokers/zstd-nginx-module](https://github.com/tokers/zstd-nginx-module) by Alex Zhang, and incorporates:
* Features, memory safety hardening, and test suites from [myguard-labs/nginx-zstd-module](https://github.com/myguard-labs/nginx-zstd-module) (Thijs Eilander / deb.myguard.nl)
* Test harness, bug fixes, and test suites from [GetPageSpeed/zstd-nginx-module](https://github.com/GetPageSpeed/zstd-nginx-module) (Danila Vershinin / GetPageSpeed LLC)

# Synopsis

```nginx
http {
    # Compress text responses for clients that support zstd.
    # Defaults: level 3, web-content MIME types, and a 1024-byte minimum.
    zstd             on;

    # Required: emit Vary: Accept-Encoding so proxies/CDNs cache correctly.
    gzip_vary        on;

    server {
        listen 80;
        server_name example.com;

        # Dynamic compression via filter module
        location /api/ {
            proxy_pass http://backend;
        }

        # Serve pre-compressed .zst files for static assets
        location /static/ {
            zstd_static on;
            root /var/www;
        }
    }
}
```

For pre-compressed static files, generate them alongside the originals:

```bash
# Compress all JS and CSS files in the static directory
find /var/www/static -name "*.js" -o -name "*.css" | \
    xargs -I{} zstd -3 -k {}
# This creates file.js.zst next to file.js, etc.
```

# Set and forget

If you just want sane production compression without reading every directive, paste this into the `http {}` block of `nginx.conf` and move on. It is tuned for typical web traffic (HTML/JSON/JS/CSS/SVG) and relies on the module's built-in defaults for everything not shown.

```nginx
http {
    # --- zstd: set and forget ---
    zstd              on;    # level 3, 1 KiB minimum, common web types

    # Required so proxies/CDNs cache compressed and identity variants
    # separately. The module warns at startup if this is missing.
    gzip_vary         on;

    # Pre-compressed static assets (optional but free if you ship .zst)
    # zstd_static     on;
}
```

Why these values, and why nothing else is needed:

* **`zstd_comp_level 3`** — the built-in default; for real web content this beats `gzip -6` on ratio at comparable or better speed. Levels ≥ 9 cost CPU steeply for marginal gain; only raise it for infrequently-generated, cached responses.
* **`zstd_min_length 1024`** — the built-in default; below about 1 KiB the zstd frame overhead and CPU cost usually outweigh the saving.
* **`zstd_types` is intentionally not set.** Its built-in list covers HTML, plain text, CSS, JavaScript, JSON, XML/feed formats, SVG, and common structured JSON variants (see [`zstd_types`](#zstd_types)).
* **`zstd_buffers` is intentionally not set.** The default is `2 × ZSTD_CStreamOutSize()` — libzstd's own recommended streaming output unit (~128 KB each). This lets every compress call flush a full internal block without fragmentation. Only override it if you run thousands of concurrent connections on a memory-constrained box and need to trade some throughput for a lower per-request memory floor (see [`zstd_buffers`](#zstd_buffers)).
* **`zstd_long`, `zstd_window_log`, `zstd_dict_file`, `zstd_target_cblock_size` are intentionally not set.** They are specialist levers (very large repetitive bodies, hard per-request memory caps, shared dictionaries). The defaults are correct for general traffic; reach for these only with a measured reason.

# Installation

Build nginx with the module using `--add-dynamic-module`:

```bash
./configure --add-dynamic-module=/path/to/zstd-nginx-module
make && make install
```

Then load the modules in `nginx.conf`:

```nginx
load_module modules/ngx_http_zstd_filter_module.so;
load_module modules/ngx_http_zstd_static_module.so;
```

**Notes:**

* Both `ngx_http_zstd_filter_module` and `ngx_http_zstd_static_module` are compiled together.
* If you are using a custom zstd installation, set `ZSTD_INC` (path to `zstd.h`) and `ZSTD_LIB` (path to the library) before running `configure`. If unset, the system-installed zstd is used.
* Dynamic modules (`.so`) require dynamic linking against `libzstd.so` (or a `-fPIC` compiled `libzstd.a`).

# Compatibility

| Component | Minimum | Recommended |
|---|---|---|
| **nginx** | 1.9.11 (first `--add-dynamic-module` release) | latest mainline / stable |
| **libzstd** | **1.4.0** | **≥ 1.5.6** |
| **OS** | Linux / BSD / macOS / Windows (MSVC) | — |

Notes on the libzstd floor:

* **< 1.4.0**: the streaming API the module uses (`ZSTD_compressStream2`) is unavailable; this is the hard minimum. Negative `zstd_comp_level` values are also unsupported.
* **< 1.5.6**: `zstd_target_cblock_size` has no effect — the directive is accepted but silently ignored with a config-load warning. Everything else works.
* **≥ 1.5.6**: every directive is fully functional.

# Directives

## ngx_http_zstd_filter_module

This filter module compresses responses on the fly using zstd. It runs after the upstream or file handler generates the response, and before nginx sends it to the client. Compression is applied only when the client signals support via `Accept-Encoding: zstd`. 2xx responses are eligible for compression — except the bodyless `204 No Content` and `205 Reset Content` — as well as `403` and `404`. Partial content (`206`) is strictly excluded to prevent range stream corruption.

> **Required:** Enable `gzip_vary on;` alongside this module. When compression is applied, the module sets `r->gzip_vary = 1`, which causes nginx to emit a `Vary: Accept-Encoding` response header.

---

### zstd

**Syntax:** `zstd on | off;`  
**Default:** `zstd off;`  
**Context:** `http, server, location, if in location`  

Enables or disables on-the-fly zstd compression for responses.

---

### zstd_comp_level

**Syntax:** `zstd_comp_level level;`  
**Default:** `zstd_comp_level 3;`  
**Context:** `http, server, location`  

Sets the zstd compression level. Accepted values depend on the installed zstd library version:

| Range | Meaning |
|---|---|
| `1` to `ZSTD_maxCLevel()` (22) | Standard levels — higher = better ratio, slower |
| `0` | Library default (`ZSTD_CLEVEL_DEFAULT`, currently level 3) |
| `ZSTD_minCLevel()` (-131072) to `-1` | Fast/negative levels — lower ratio, minimal CPU cost (requires zstd ≥ 1.4.0) |

---

### zstd_min_length

**Syntax:** `zstd_min_length length;`  
**Default:** `zstd_min_length 1024;`  
**Context:** `http, server, location`  

Sets the minimum response size (in bytes) required for compression to apply. The size is taken from the `Content-Length` response header; responses without `Content-Length` are always eligible.

---

### zstd_max_length

**Syntax:** `zstd_max_length length;`  
**Default:** `—` (no limit)  
**Context:** `http, server, location`  

Sets the maximum response size that will be compressed:

* **Before compression starts**, when the response advertises a `Content-Length` larger than the limit: the response is passed through uncompressed.
* **During compression**, for chunked/streaming responses with *no* `Content-Length`: the running input total is tracked, and if it exceeds the limit the request is **aborted** to protect the worker from an unbounded upstream.

---

### zstd_types

**Syntax:** `zstd_types mime-type ...;`  
**Default:** `zstd_types text/html text/plain text/css text/csv application/json application/x-ndjson application/json-seq application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml application/atom+xml application/ld+json application/manifest+json application/problem+json application/rss+xml application/vnd.api+json application/xhtml+xml application/wasm text/wgsl;`  
**Context:** `http, server, location`  

When omitted, the default covers common textual web representations. If set explicitly, `text/html` is always included along with the listed MIME types. Use `*` to match all MIME types.

---

### zstd_buffers

**Syntax:** `zstd_buffers number size;`  
**Default:** `zstd_buffers 2 <ZSTD_CStreamOutSize()>;` (~128 KB each)  
**Context:** `http, server, location`  

Configures the number and size of output buffers used during compression.

---

### zstd_target_cblock_size

**Syntax:** `zstd_target_cblock_size size;`  
**Default:** `—` (disabled, uses ZSTD library defaults)  
**Context:** `http, server, location`  
**Requires:** libzstd ≥ v1.5.6  

Sets the target compressed block size for zstd frames to enable faster incremental parsing for clients.

---

### zstd_window_log

**Syntax:** `zstd_window_log exponent;`  
**Default:** `—` (disabled; uses level-derived default)  
**Context:** `http, server, location`  

Caps the zstd compression **window** at `2^exponent` bytes. Typical values are `20`–`24` (1–16 MB), providing a hard per-request memory ceiling.

---

### zstd_long

**Syntax:** `zstd_long on | off;`  
**Default:** `zstd_long off;`  
**Context:** `http, server, location`  

Enables zstd **long-distance matching** (`ZSTD_c_enableLongDistanceMatching`), finding repeated sequences far beyond the regular match window on large, repetitive responses.

---

### zstd_max_cctx_memory

**Syntax:** `zstd_max_cctx_memory size;`  
**Default:** `—` (disabled, no budget enforced)  
**Context:** `http, server, location`  

Asserts at **config load** that the combined zstd parameters configured for the location do not exceed `size` bytes of per-request compressor memory.

---

### zstd_bypass

**Syntax:** `zstd_bypass string ...;`  
**Default:** `—`  
**Context:** `http, server, location`  

Disables compression for the current request when at least one of the given string parameters evaluates to a non-empty value that is not `"0"`.

---

### zstd_bypass_vary

**Syntax:** `zstd_bypass_vary field-name;`  
**Default:** `—`  
**Context:** `http, server, location`  

Appends `field-name` to the response `Vary` header on every response from the location (both compressed and bypassed-identity variants), preventing cache poisoning on header/cookie-driven bypasses.

---

### zstd_dict_file

**Syntax:** `zstd_dict_file /path/to/dict;`  
**Default:** `—`  
**Context:** `http`  

Loads a pre-trained raw zstd dictionary for use during compression.

> **Requires explicit opt-in:** Requires `zstd_dict_file_unsafe on;` acknowledging that both client and server out-of-band agree on the pre-shared dictionary.

---

## ngx_http_zstd_static_module

This module serves pre-compressed `.zst` files in place of the originals, without running compression at request time. It is the zstd equivalent of nginx's `gzip_static` module.

---

### zstd_static

**Syntax:** `zstd_static on | off | always;`  
**Default:** `zstd_static off;`  
**Context:** `http, server, location`  

Controls how pre-compressed `.zst` files are served. Includes automatic 4-byte magic number verification (`0xFD2FB528`), 8MB decompression window upper-bound protection, and HTTP 206 byte-range slicing.

---

# Variables

## $zstd_ratio

The compression ratio achieved for the current response, expressed as the ratio of original size to compressed size.

## $zstd_bytes_in

The number of uncompressed (input) bytes the filter consumed for the current response. Available during the log phase.

## $zstd_bytes_out

The number of compressed (output) bytes the filter produced for the current response. Available during the log phase.

---

# Author

* Alex Zhang (张超) <zchao1995@gmail.com>, UPYUN Inc.
* Features, hardening, refactoring, and test suites by Thijs Eilander and the [deb.myguard.nl](https://deb.myguard.nl/) maintainers ([myguard-labs/nginx-zstd-module](https://github.com/myguard-labs/nginx-zstd-module)).
* Test harness, bug fixes, and test suites by Danila Vershinin / [GetPageSpeed](https://www.getpagespeed.com/) ([GetPageSpeed/zstd-nginx-module](https://github.com/GetPageSpeed/zstd-nginx-module)).
* Maintained by SB Maintainers for SB Nginx.

# License

Licensed under the [BSD 2-Clause License](LICENSE).
