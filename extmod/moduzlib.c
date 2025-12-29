/*
 *
 * Copyright (c) 2025 Damian Parrino
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <zlib.h>

#include "py/nlr.h"
#include "py/runtime.h"

#if 0 // print debugging info
#define DEBUG_printf DEBUG_printf
#else // don't print debugging info
#define DEBUG_printf(...) (void)0
#endif

#define CHUNK_SIZE 16384  // Initial chunk size for output buffer

extern int offzip_init(int wbits);
extern int offzip_search(FILE *fd);
extern int offzip_verify(FILE *fd, uint32_t *offset, uint32_t *inlen, uint32_t *outlen);
extern void offzip_free(void);

/**
 * @brief Decompress data from input buffer to dynamically allocated output buffer
 * 
 * @param compressed_data Pointer to compressed data buffer
 * @param compressed_size Size of compressed data in bytes
 * @param decompressed Pointer to dynamically allocated decompressed buffer
 * @param window_bits Window size for decompression (use 15+16 for gzip format)
 * @return True on success, False on failure
 */

 bool micropy_decompress_buffer_dynamic(struct _mp_state_ctx_t *mp_state, 
    const unsigned char* compressed_data, size_t compressed_size,
    vstr_t* decompressed,
    int window_bits)
{
    z_stream stream;
    unsigned char* out_buffer = NULL;
    int ret;

    // Initialize zlib stream
    memset(&stream, 0, sizeof(stream));
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = compressed_size;
    stream.next_in = (Bytef*)compressed_data;

    // Initialize decompression with specified window bits
    if (inflateInit2(&stream, window_bits) != Z_OK) {
        DEBUG_printf("inflateInit2 failed\n");
        return false;
    }

    // Start with a reasonable initial buffer size
    out_buffer = (unsigned char*)malloc(CHUNK_SIZE);
    if (!out_buffer) {
        DEBUG_printf("Memory allocation failed\n");
        inflateEnd(&stream);
        return false;
    }
    
    // Decompress loop
    do {
        // Set output buffer position and available space
        stream.avail_out = CHUNK_SIZE;
        stream.next_out = out_buffer;
        
        // Decompress chunk
        ret = inflate(&stream, Z_NO_FLUSH);
        
        switch (ret) {
            case Z_NEED_DICT:
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                DEBUG_printf("Decompression error: %s\n", stream.msg);
                free(out_buffer);
                inflateEnd(&stream);
                return false;
        }
        
        // Update total output size
        size_t bytes_produced = CHUNK_SIZE - stream.avail_out;

        vstr_add_strn(decompressed, (const char*)out_buffer, bytes_produced);
        DEBUG_printf("Decompressed chunk: %zu bytes, total: %zu bytes\n", bytes_produced, stream.total_out);
    } while (ret != Z_STREAM_END);
    
    // Finish decompression
    inflateEnd(&stream);
    free(out_buffer);

    return true;
}

/**
 * @brief Helper function to compress data
 */
bool micropy_compress_buffer(struct _mp_state_ctx_t *mp_state, 
    const unsigned char* data, size_t data_size,
    vstr_t* compressed_out,
    int wbits, int level)
{
    z_stream stream;
    unsigned char* compressed = NULL;
    size_t max_compressed_size;
    int ret;

    // Calculate maximum possible compressed size
    max_compressed_size = compressBound(data_size);
    compressed = (unsigned char*)malloc(max_compressed_size);

    if (!compressed) {
        return false;
    }
    
    // Initialize zlib stream for compression
    memset(&stream, 0, sizeof(stream));
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    if (deflateInit2(&stream, level, Z_DEFLATED, wbits, 9, Z_DEFAULT_STRATEGY)) {
        DEBUG_printf("Error: zlib initialization error");
        free(compressed);
        return false;
    }

    stream.avail_in = data_size;
    stream.next_in = (Bytef*)data;
    stream.avail_out = max_compressed_size;
    stream.next_out = compressed;
    
    ret = deflate(&stream, Z_FINISH);
    
    if (ret != Z_STREAM_END) {
        free(compressed);
        deflateEnd(&stream);
        return false;
    }
    
    vstr_add_strn(compressed_out, (const char*)compressed, max_compressed_size - stream.avail_out);
    deflateEnd(&stream);
    free(compressed);
    
    return true;
}

STATIC mp_obj_t mod_uzlib_decompress(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t bufinfo;
    vstr_t out;
    bool ret;

    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);
    vstr_init(&out, 0x10);
 
    int wbits = MAX_WBITS;
    if (n_args > 1) {
        // custom window value
        wbits = mp_obj_int_get_truncated(args[1]);
    }

    ret = decompress_buffer_dynamic(bufinfo.buf, bufinfo.len, &out, wbits);

    if (!ret || out.had_error) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "Zlib decompression error"));
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &out);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uzlib_decompress_obj, 1, 2, mod_uzlib_decompress);

STATIC mp_obj_t mod_uzlib_compress(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t bufinfo;
    vstr_t out;
    bool ret;

    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);
    vstr_init(&out, 0x10);

    int wbits = MAX_WBITS;
    if (n_args > 1) {
        // custom window value
        wbits = mp_obj_int_get_truncated(args[1]);
    }

    int level = Z_BEST_COMPRESSION;
    if (n_args > 2) {
        // custom level value
        level = mp_obj_int_get_truncated(args[2]);
    }

    ret = compress_buffer(bufinfo.buf, bufinfo.len, &out, wbits, level);

    if (!ret || out.had_error) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "Zlib compression error"));
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &out);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uzlib_compress_obj, 1, 3, mod_uzlib_compress);

STATIC mp_obj_t mod_uzlib_offzip(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t bufinfo;
    mp_obj_t list;

    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    int wbits = MAX_WBITS;
    if (n_args > 1) {
        // custom window value
        wbits = mp_obj_int_get_truncated(args[1]);
    }

    if (offzip_init(wbits) != Z_OK) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "offZip init error"));
    }

    list = mp_obj_new_list(0, NULL);
    FILE* fd = fmemopen(bufinfo.buf, bufinfo.len, "rb");

    while (offzip_search(fd) == Z_OK)
    {
        mp_obj_t items[3];
        uint32_t offz = 0, inlen = 0, outlen = 0;

        if (offzip_verify(fd, &offz, &inlen, &outlen) != Z_OK) {
            DEBUG_printf("offZip unzip error\n");
            continue;
        }

        items[0] = mp_obj_new_int_from_uint(offz);
        items[1] = mp_obj_new_int_from_uint(inlen);
        items[2] = mp_obj_new_int_from_uint(outlen);
        mp_obj_list_append(list, mp_obj_new_tuple(3, items));

        DEBUG_printf("Found compressed block at offset 0x%08x: %d -> %d\n", offz, inlen, outlen);
    }

    offzip_free();
    fclose (fd);

    return list;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uzlib_offzip_obj, 1, 2, mod_uzlib_offzip);

#if MICROPY_PY_UZLIB

STATIC const mp_rom_map_elem_t mp_module_uzlib_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_uzlib) },
    { MP_ROM_QSTR(MP_QSTR_compress), MP_ROM_PTR(&mod_uzlib_compress_obj) },
    { MP_ROM_QSTR(MP_QSTR_decompress), MP_ROM_PTR(&mod_uzlib_decompress_obj) },
    { MP_ROM_QSTR(MP_QSTR_offzip), MP_ROM_PTR(&mod_uzlib_offzip_obj) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_uzlib_globals, mp_module_uzlib_globals_table);

const mp_obj_module_t mp_module_uzlib = {
    .base = { &mp_type_module },
    .name = MP_QSTR_uzlib,
    .globals = (mp_obj_dict_t*)&mp_module_uzlib_globals,
};

#endif // MICROPY_PY_UZLIB
