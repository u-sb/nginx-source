//
// Created by root on 11/14/18.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <json-c/json.h>
#include <arpa/inet.h>
#include "ipdb.h"

static void ipdb_meta_free(ipdb_meta_data *meta) {
    int i;

    if (meta == NULL) {
        return;
    }
    if (meta->fields != NULL) {
        for (i = 0; i < meta->fields_length; ++i) {
            free(meta->fields[i]);
        }
    }
    free(meta->fields);
    free(meta->language);
    free(meta);
}

static int ipdb_json_int(json_object *obj, const char *key, int *result) {
    json_object *value;
    int64_t number;

    if (!json_object_object_get_ex(obj, key, &value)
        || !json_object_is_type(value, json_type_int)) {
        return 0;
    }
    number = json_object_get_int64(value);
    if (number < 0 || number > INT_MAX) {
        return 0;
    }
    *result = (int) number;
    return 1;
}

ipdb_meta_data *parse_meta_data(const char *meta_json) {
    int i, version;
    size_t count, length;
    int64_t offset;
    const char *name;
    json_object *value, *it;
    struct json_object_iterator language;
    json_object *obj = json_tokener_parse(meta_json);
    ipdb_meta_data *meta = calloc(1, sizeof(ipdb_meta_data));

    if (meta == NULL || obj == NULL
        || !json_object_is_type(obj, json_type_object)) {
        goto failed;
    }
    if (!ipdb_json_int(obj, "node_count", &meta->node_count)
        || !ipdb_json_int(obj, "total_size", &meta->total_size)
        || !ipdb_json_int(obj, "ip_version", &version)
        || version == 0 || (version & ~(IPv4 | IPv6)) != 0
        || meta->node_count == 0
        || meta->node_count > meta->total_size / 8) {
        goto failed;
    }
    meta->ip_version = (short) version;
    if (json_object_object_get_ex(obj, "build", &value)) {
        int64_t build;

        if (!json_object_is_type(value, json_type_int)) {
            goto failed;
        }
        build = json_object_get_int64(value);
        if (build < 0 || build > LONG_MAX) {
            goto failed;
        }
        meta->build_time = (long) build;
    }

    if (!json_object_object_get_ex(obj, "fields", &value)
        || !json_object_is_type(value, json_type_array)) {
        goto failed;
    }
    count = json_object_array_length(value);
    if (count == 0 || count > INT_MAX || count > SIZE_MAX / sizeof(char *)) {
        goto failed;
    }
    meta->fields_length = (int) count;
    meta->fields = calloc(count, sizeof(char *));
    if (meta->fields == NULL) {
        goto failed;
    }
    for (i = 0; i < meta->fields_length; ++i) {
        it = json_object_array_get_idx(value, i);
        if (!json_object_is_type(it, json_type_string)) {
            goto failed;
        }
        length = (size_t) json_object_get_string_len(it);
        if (length == SIZE_MAX) {
            goto failed;
        }
        meta->fields[i] = malloc(length + 1);
        if (meta->fields[i] == NULL) {
            goto failed;
        }
        memcpy(meta->fields[i], json_object_get_string(it), length);
        meta->fields[i][length] = '\0';
    }

    if (!json_object_object_get_ex(obj, "languages", &value)
        || !json_object_is_type(value, json_type_object)) {
        goto failed;
    }
    count = (size_t) json_object_object_length(value);
    if (count == 0 || count > INT_MAX
        || count > SIZE_MAX / sizeof(ipdb_meta_data_language)) {
        goto failed;
    }
    meta->language_length = (int) count;
    meta->language = calloc(count, sizeof(ipdb_meta_data_language));
    if (meta->language == NULL) {
        goto failed;
    }
    language = json_object_iter_begin(value);
    for (i = 0; i < meta->language_length; ++i) {
        name = json_object_iter_peek_name(&language);
        it = json_object_iter_peek_value(&language);
        if (strlen(name) >= sizeof(meta->language[i].name)
            || !json_object_is_type(it, json_type_int)) {
            goto failed;
        }
        offset = json_object_get_int64(it);
        if (offset < 0 || offset > INT_MAX - meta->fields_length) {
            goto failed;
        }
        strcpy(meta->language[i].name, name);
        meta->language[i].offset = (int) offset;
        json_object_iter_next(&language);
    }
    json_object_put(obj);
    return meta;

failed:
    if (obj != NULL) {
        json_object_put(obj);
    }
    ipdb_meta_free(meta);
    return NULL;
}

static uint32_t ipdb_read_uint32(const unsigned char *data) {
    return ((uint32_t) data[0] << 24) | ((uint32_t) data[1] << 16)
           | ((uint32_t) data[2] << 8) | data[3];
}

static int ipdb_read_node(ipdb_reader *reader, int node, int index, int *target) {
    size_t off;
    uint32_t value;

    if (node < 0 || node >= reader->meta->node_count
        || (index != 0 && index != 1)) {
        return ErrDatabaseError;
    }
    off = (size_t) node * 8 + (size_t) index * 4;
    if (off > (size_t) reader->data_size
        || (size_t) reader->data_size - off < 4) {
        return ErrDatabaseError;
    }
    value = ipdb_read_uint32(reader->data + off);
    if (value > INT_MAX) {
        return ErrDatabaseError;
    }
    *target = (int) value;
    return ErrNoErr;
}

int ipdb_reader_new(const char *file, ipdb_reader **reader) {
    FILE *fd;
    long fsize;
    size_t meta_length;
    unsigned char header[4];
    char *meta_json = NULL;
    ipdb_reader *rd = NULL;
    int node, i, err = ErrFileSize;

    if (reader == NULL) {
        return ErrDatabaseError;
    }
    *reader = NULL;
    fd = fopen(file, "rb");
    if (fd == NULL) {
        return err;
    }
    if (fseek(fd, 0, SEEK_END) != 0 || (fsize = ftell(fd)) < 4
        || fsize > INT_MAX || fseek(fd, 0, SEEK_SET) != 0
        || fread(header, 1, sizeof(header), fd) != sizeof(header)) {
        goto failed;
    }
    meta_length = ipdb_read_uint32(header);
    if (meta_length == 0 || meta_length > (size_t) fsize - 4) {
        goto failed;
    }
    rd = calloc(1, sizeof(ipdb_reader));
    meta_json = malloc(meta_length + 1);
    if (rd == NULL || meta_json == NULL
        || fread(meta_json, 1, meta_length, fd) != meta_length) {
        goto failed;
    }
    meta_json[meta_length] = '\0';
    if (memchr(meta_json, '\0', meta_length) != NULL) {
        err = ErrMetaData;
        goto failed;
    }
    rd->meta = parse_meta_data(meta_json);
    free(meta_json);
    meta_json = NULL;
    if (rd->meta == NULL) {
        err = ErrMetaData;
        goto failed;
    }
    if ((size_t) rd->meta->total_size != (size_t) fsize - 4 - meta_length) {
        goto failed;
    }
    rd->file_size = (int) fsize;
    rd->data_size = rd->meta->total_size;
    rd->data = malloc((size_t) rd->data_size);
    if (rd->data == NULL
        || fread(rd->data, 1, (size_t) rd->data_size, fd) != (size_t) rd->data_size) {
        goto failed;
    }
    node = 0;
    for (i = 0; i < 96 && node < rd->meta->node_count; ++i) {
        err = ipdb_read_node(rd, node, i >= 80, &node);
        if (err != ErrNoErr) {
            goto failed;
        }
    }
    rd->v4offset = node;
    fclose(fd);
    *reader = rd;
    return ErrNoErr;

failed:
    free(meta_json);
    ipdb_reader_free(&rd);
    fclose(fd);
    return err;
}

void ipdb_reader_free(ipdb_reader **reader) {
    if (reader == NULL || *reader == NULL) {
        return;
    }
    ipdb_meta_free((*reader)->meta);
    free((*reader)->data);
    free(*reader);
    *reader = NULL;
}

int ipdb_reader_is_ipv4_support(ipdb_reader *reader) {
    return (((int) reader->meta->ip_version) & IPv4) == IPv4;

}

int ipdb_reader_is_ipv6_support(ipdb_reader *reader) {
    return (((int) reader->meta->ip_version) & IPv6) == IPv6;

}

int ipdb_resolve(ipdb_reader *reader, int node, const char **bytes, size_t *size) {
    size_t resolved, length;

    if (node <= reader->meta->node_count) {
        return ErrDatabaseError;
    }

    resolved = (size_t) (node - reader->meta->node_count)
               + (size_t) reader->meta->node_count * 8;
    if (resolved > (size_t) reader->data_size
        || (size_t) reader->data_size - resolved < 2) {
        return ErrDatabaseError;
    }
    length = ((size_t) reader->data[resolved] << 8) | reader->data[resolved + 1];
    if (length > (size_t) reader->data_size - resolved - 2) {
        return ErrDatabaseError;
    }
    *bytes = (const char *) reader->data + resolved + 2;
    *size = length;
    return ErrNoErr;
}

int ipdb_search(ipdb_reader *reader, const u_char *ip, int bit_count, int *node) {
    int i, err;

    if (bit_count != 32 && bit_count != 128) {
        return ErrIPFormat;
    }
    *node = bit_count == 32 ? reader->v4offset : 0;
    for (i = 0; i < bit_count; ++i) {
        if (*node >= reader->meta->node_count) {
            break;
        }
        err = ipdb_read_node(reader, *node,
                             (ip[i >> 3] >> (7 - (i % 8))) & 1, node);
        if (err != ErrNoErr) {
            return err;
        }
    }
    return *node > reader->meta->node_count ? ErrNoErr : ErrDataNotExists;
}

int ipdb_copy_language(ipdb_reader *reader, const char *language,
                       const char *content, size_t content_len,
                       char *body, size_t body_size) {
    int i;
    size_t off, count, field = 0, start = 0, p, length;

    for (i = 0; i < reader->meta->language_length; ++i) {
        if (strcmp(language, reader->meta->language[i].name) == 0) {
            break;
        }
    }
    if (i == reader->meta->language_length) {
        return ErrNoSupportLanguage;
    }
    if (body_size == 0 || memchr(content, '\0', content_len) != NULL) {
        return ErrDatabaseError;
    }
    off = (size_t) reader->meta->language[i].offset;
    count = (size_t) reader->meta->fields_length;

    /* Records are length-prefixed, and may not have a trailing NUL. */
    for (p = 0; p <= content_len; ++p) {
        if (p != content_len && content[p] != '\t') {
            continue;
        }
        if (field == off + count - 1) {
            length = p - start;
            if (length >= body_size) {
                return ErrDatabaseError;
            }
            memcpy(body, content + start, length);
            body[length] = '\0';
            return ErrNoErr;
        }
        ++field;
        if (field == off) {
            start = p + 1;
        }
    }
    return ErrDatabaseError;
}

int ipdb_find0(ipdb_reader *reader, const char *addr, const char **body,
               size_t *body_len) {
    int node = 0;
    int err;
    struct in_addr addr4;
    struct in6_addr addr6;
    if (inet_pton(AF_INET, addr, &addr4) == 1) {
        if (!ipdb_reader_is_ipv4_support(reader)) {
            return ErrNoSupportIPv4;
        }
        err = ipdb_search(reader, (const u_char *) &addr4.s_addr, 32, &node);
        if (err != ErrNoErr) {
            return err;
        }
    } else if (inet_pton(AF_INET6, addr, &addr6) == 1) {
        if (!ipdb_reader_is_ipv6_support(reader)) {
            return ErrNoSupportIPv6;
        }
        err = ipdb_search(reader, (const u_char *) &addr6.s6_addr, 128, &node);
        if (err != ErrNoErr) {
            return err;
        }
    } else {
        return ErrIPFormat;
    }
    err = ipdb_resolve(reader, node, body, body_len);
    return err;
}

int ipdb_find1(ipdb_reader *reader, const char *addr, const char *language,
               char *body, size_t body_size) {
    int err;
    const char *content;
    size_t content_len;

    err = ipdb_find0(reader, addr, &content, &content_len);
    if (err != ErrNoErr) {
        return err;
    }
    return ipdb_copy_language(reader, language, content, content_len,
                              body, body_size);
}

int ipdb_reader_find(ipdb_reader *reader, const char *addr, const char *language,
                     char *body, size_t body_size) {
    return ipdb_find1(reader, addr, language, body, body_size);
}
