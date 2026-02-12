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
#include <assert.h>
#include <string.h>

#include "py/nlr.h"
#include "py/runtime.h"
#include "py/binary.h"

#include "apollo.h"
#include "crc_util.h"

// external definitions
extern void sha1( const unsigned char *input, size_t ilen, unsigned char output[20] );
extern void sha256( const unsigned char *input, size_t ilen, unsigned char output[32], int is224 );
extern void sha512( const unsigned char *input, size_t ilen, unsigned char output[64], int is384 );
extern void md5( const unsigned char *input, size_t ilen, unsigned char output[16] );
extern void sha1_hmac( const unsigned char *key, size_t keylen, const unsigned char *input, size_t ilen, unsigned char output[20] );

//---  Custom game checksum functions ---//
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_eachecksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_ffx_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_ff13_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_deadrising_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_kh25_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_khcom_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_mgs2_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_mgspw_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_sw4_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_toz_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_tiara2_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_castlevania_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_rockstar_checksum_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_dbzxv2_checksum_obj);

//---  Generic hash functions ---//
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_crc_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_crc16_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_crc32_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_crc32big_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_crc64_iso_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_crc64_ecma_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_md5_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_md5_xor_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_sha1_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_sha224_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_sha256_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_sha384_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_sha512_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_hmac_sha1_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_pbkdf2_sha1_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_pbkdf2_sha256_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_sha1_xor64_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_adler16_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_adler32_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_checksum32_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_sdbm_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_fnv1_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_add_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_wadd_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_dwadd_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_qwadd_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_wadd_le_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_dwadd_le_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_wsub_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_force_crc32_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_murmur3_32_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_jhash_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_jenkins_oaat_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_lookup3_little2_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_uhashlib_djb2_obj);


/*
 * write_le_uint16: append an unsigned 16 bits Little Endian
 * value to a buffer
 */
#define write_le_uint16(buf, val) \
	buf[0] = (uint8_t)val; \
	buf[1] = (uint8_t)(val >> 8);

#define write_be_uint16(buf, val) \
	buf[1] = (uint8_t)val; \
	buf[0] = (uint8_t)(val >> 8);

/*
 * write_le_uint32: append an unsigned 32 bits Little Endian
 * value to a buffer
 */
#define write_le_uint32(buf, val) \
	buf[0] = (uint8_t)val; \
	buf[1] = (uint8_t)(val >> 8); \
	buf[2] = (uint8_t)(val >> 16); \
	buf[3] = (uint8_t)(val >> 24);

#define write_be_uint32(buf, val) \
	buf[3] = (uint8_t)val; \
	buf[2] = (uint8_t)(val >> 8); \
	buf[1] = (uint8_t)(val >> 16); \
	buf[0] = (uint8_t)(val >> 24);

/*
 * write_le_uint64: append an unsigned 64 bits Little Endian
 * value to a buffer
 */
#define write_le_uint64(buf, val) \
    buf[0] = (uint8_t)val; \
    buf[1] = (uint8_t)(val >> 8); \
    buf[2] = (uint8_t)(val >> 16); \
    buf[3] = (uint8_t)(val >> 24); \
    buf[4] = (uint8_t)(val >> 32); \
    buf[5] = (uint8_t)(val >> 40); \
    buf[6] = (uint8_t)(val >> 48); \
    buf[7] = (uint8_t)(val >> 56);

#define write_be_uint64(buf, val) \
    buf[7] = (uint8_t)val; \
    buf[6] = (uint8_t)(val >> 8); \
    buf[5] = (uint8_t)(val >> 16); \
    buf[4] = (uint8_t)(val >> 24); \
    buf[3] = (uint8_t)(val >> 32); \
    buf[2] = (uint8_t)(val >> 40); \
    buf[1] = (uint8_t)(val >> 48); \
    buf[0] = (uint8_t)(val >> 56);

/*
 * read_be_uint64: read an unsigned 64 bits Big Endian
 * value from a buffer
 */
#define read_le_uint64(buf) \
    ((uint64_t)(buf[0]) | ((uint64_t)(buf[1]) << 8) | \
    ((uint64_t)(buf[2]) << 16) | ((uint64_t)(buf[3]) << 24) | \
    ((uint64_t)(buf[4]) << 32) | ((uint64_t)(buf[5]) << 40) | \
    ((uint64_t)(buf[6]) << 48) | ((uint64_t)(buf[7]) << 56))

#define parse_uint64_from_obj(obj, buf, ret) \
    memset(buf, 0, sizeof(buf)); \
    mp_set_unaligned(UINT64, buf, false, obj); \
    ret = read_le_uint64(buf);


mp_obj_t mod_uhashlib_add(size_t n_args, const mp_obj_t *args) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    uint32_t crc = add_hash(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    int carry = 0;
    if (n_args > 1) {
        // custom carry value
        carry = mp_obj_int_get_truncated(args[1]);
        if (carry != 2)
            nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "Invalid carry value"));

        while (crc > 0xFFFF)
        {
            crc = (crc & 0x0000FFFF) + ((crc & 0xFFFF0000) >> 8*carry);
        }

        write_be_uint16(out, crc);
    }

    return mp_obj_new_bytearray(sizeof(out) - carry, out);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uhashlib_add_obj, 1, 2, mod_uhashlib_add);

mp_obj_t mod_uhashlib_wadd(size_t n_args, const mp_obj_t *args) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    uint32_t crc = wadd_hash(bufinfo.buf, bufinfo.len, 0);
    write_be_uint32(out, crc);

    int carry = 0;
    if (n_args > 1) {
        // custom carry value
        carry = mp_obj_int_get_truncated(args[1]);
        if (carry != 2)
            nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "Invalid carry value"));

        while (crc > 0xFFFF)
        {
            crc = (crc & 0x0000FFFF) + ((crc & 0xFFFF0000) >> 8*carry);
        }

        write_be_uint16(out, crc);
    }

    return mp_obj_new_bytearray(sizeof(out) - carry, out);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uhashlib_wadd_obj, 1, 2, mod_uhashlib_wadd);

mp_obj_t mod_uhashlib_wadd_le(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = wadd_hash(bufinfo.buf, bufinfo.len, 1);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_wadd_le_obj, mod_uhashlib_wadd_le);

mp_obj_t mod_uhashlib_dwadd(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = dwadd_hash(bufinfo.buf, bufinfo.len, 0);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_dwadd_obj, mod_uhashlib_dwadd);

mp_obj_t mod_uhashlib_dwadd_le(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = dwadd_hash(bufinfo.buf, bufinfo.len, 1);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_dwadd_le_obj, mod_uhashlib_dwadd_le);

mp_obj_t mod_uhashlib_qwadd(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = qwadd_hash(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_qwadd_obj, mod_uhashlib_qwadd);

mp_obj_t mod_uhashlib_wsub(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = wsub_hash(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_wsub_obj, mod_uhashlib_wsub);

mp_obj_t mod_uhashlib_adler16(mp_obj_t data) {
    uint8_t out[2];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint16_t crc = adler16(bufinfo.buf, bufinfo.len);
    write_be_uint16(out, crc);

    return mp_obj_new_bytearray(2, out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_adler16_obj, mod_uhashlib_adler16);

mp_obj_t mod_uhashlib_adler32(size_t n_args, const mp_obj_t *args) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    uint32_t crc = adler32(0L, NULL, 0);
    if (n_args > 1) {
        // custom initial value
        crc = mp_obj_int_get_truncated(args[1]);
    }

    crc = adler32(crc, bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uhashlib_adler32_obj, 1, 2, mod_uhashlib_adler32);

mp_obj_t mod_uhashlib_checksum32(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = Checksum32_hash(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_checksum32_obj, mod_uhashlib_checksum32);

mp_obj_t mod_uhashlib_crc(size_t n_args, const mp_obj_t *args) {
    uint8_t buf[0x10] = {0};
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    int width = mp_obj_int_get_truncated(args[1]);

    if (width != 16 && width != 32 && width != 64) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "CRC width must be 16, 32 or 64"));
    }

    vstr_t vstr;
    byte *out;
    custom_crc_t crc_opts = {
        .width = width,
        .refIn = mp_obj_int_get_truncated(args[5]),
        .refOut = mp_obj_int_get_truncated(args[6]),
    };
    parse_uint64_from_obj(args[2], buf, crc_opts.poly);
    parse_uint64_from_obj(args[3], buf, crc_opts.init);
    parse_uint64_from_obj(args[4], buf, crc_opts.xor);

    switch (width)
    {
    case 16:
        vstr_init_len(&vstr, 2);
        out = (byte*)vstr.buf;
        uint16_t crc16 = crc16_hash(bufinfo.buf, bufinfo.len, &crc_opts);
        write_be_uint16(out, crc16);
        break;

    case 32:
        vstr_init_len(&vstr, 4);
        out = (byte*)vstr.buf;
        uint32_t crc32 = crc32_hash(bufinfo.buf, bufinfo.len, &crc_opts);
        write_be_uint32(out, crc32);
        break;

    case 64:
        vstr_init_len(&vstr, 8);
        out = (byte*)vstr.buf;
        uint64_t crc64 = crc64_hash(bufinfo.buf, bufinfo.len, &crc_opts);
        write_be_uint64(out, crc64);
        break;
        
    default:
        break;
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uhashlib_crc_obj, 7, 7, mod_uhashlib_crc);

mp_obj_t mod_uhashlib_crc16(mp_obj_t data) {
    uint8_t out[2];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    custom_crc_t crc_opts = {
        .init = CRC_16_INIT_VALUE,
        .poly = CRC_16_POLYNOMIAL,
        .xor = CRC_16_XOR_VALUE,
        .refIn = 0,
        .refOut = 0,
    };

    uint16_t crc = crc16_hash(bufinfo.buf, bufinfo.len, &crc_opts);
    write_be_uint16(out, crc);

    return mp_obj_new_bytearray(2, out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_crc16_obj, mod_uhashlib_crc16);

mp_obj_t mod_uhashlib_crc32(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    custom_crc_t crc_opts = {
        .init = CRC_32_INIT_VALUE,
        .poly = CRC_32_POLYNOMIAL,
        .xor = CRC_32_XOR_VALUE,
        .refIn = 1,
        .refOut = 1,
    };

    uint32_t crc = crc32_hash(bufinfo.buf, bufinfo.len, &crc_opts);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_crc32_obj, mod_uhashlib_crc32);

mp_obj_t mod_uhashlib_crc32big(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    custom_crc_t crc_opts = {
        .init = CRC_32_INIT_VALUE,
        .poly = CRC_32_POLYNOMIAL,
        .xor = CRC_32_XOR_VALUE,
        .refIn = 0,
        .refOut = 0,
    };

    uint32_t crc = crc32_hash(bufinfo.buf, bufinfo.len, &crc_opts);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_crc32big_obj, mod_uhashlib_crc32big);

mp_obj_t mod_uhashlib_crc64_ecma(mp_obj_t data) {
    uint8_t out[8];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    custom_crc_t crc_opts = {
        .init = CRC_64_ECMA182_INIT_VALUE,
        .poly = CRC_64_ECMA182_POLY,
        .xor = CRC_64_ECMA182_XOR_VALUE,
        .refIn = 0,
        .refOut = 0,
    };

    uint64_t crc = crc64_hash(bufinfo.buf, bufinfo.len, &crc_opts);
    write_be_uint64(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_crc64_ecma_obj, mod_uhashlib_crc64_ecma);

mp_obj_t mod_uhashlib_crc64_iso(mp_obj_t data) {
    uint8_t out[8];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    custom_crc_t crc_opts = {
        .init = CRC_64_ISO_INIT_VALUE,
        .poly = CRC_64_ISO_POLY,
        .xor = CRC_64_ISO_XOR_VALUE,
        .refIn = 0,
        .refOut = 0,
    };

    uint64_t crc = crc64_hash(bufinfo.buf, bufinfo.len, &crc_opts);
    write_be_uint64(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_crc64_iso_obj, mod_uhashlib_crc64_iso);

mp_obj_t mod_uhashlib_djb2(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = djb2_hash(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_djb2_obj, mod_uhashlib_djb2);

mp_obj_t mod_uhashlib_fnv1(size_t n_args, const mp_obj_t *args) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    uint32_t init_val = FNV1_INIT_VALUE;
    if (n_args > 1) {
        // custom initial value
        init_val = mp_obj_int_get_truncated(args[1]);
    }

    uint32_t crc = fnv1_hash(bufinfo.buf, bufinfo.len, init_val);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uhashlib_fnv1_obj, 1, 2, mod_uhashlib_fnv1);

mp_obj_t mod_uhashlib_force_crc32(mp_obj_t data, mp_obj_t offset, mp_obj_t newcrc) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = force_crc32(bufinfo.buf, bufinfo.len, mp_obj_int_get_truncated(offset), mp_obj_int_get_truncated(newcrc));
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_3(mod_uhashlib_force_crc32_obj, mod_uhashlib_force_crc32);

mp_obj_t mod_uhashlib_hmac_sha1(mp_obj_t key, mp_obj_t data) {
    uint8_t out[20];
    mp_buffer_info_t keyinfo, bufinfo;
    mp_get_buffer_raise(key, &keyinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    sha1_hmac(keyinfo.buf, keyinfo.len, bufinfo.buf, bufinfo.len, out);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_2(mod_uhashlib_hmac_sha1_obj, mod_uhashlib_hmac_sha1);

mp_obj_t mod_uhashlib_pbkdf2_sha1(size_t n_args, const mp_obj_t *args) {
    uint8_t out[0x200];
    mp_buffer_info_t pwdinfo, saltinfo;
    mp_get_buffer_raise(args[0], &pwdinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(args[1], &saltinfo, MP_BUFFER_READ);

    int iter = mp_obj_int_get_truncated(args[2]);
    int dklen = mp_obj_int_get_truncated(args[3]);
    dklen = MIN(dklen, sizeof(out));

    if (pbkdf2_sha1(pwdinfo.buf, pwdinfo.len, saltinfo.buf, saltinfo.len, iter, out, dklen) != 0) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "PBKDF2-SHA1 failed"));
    }

    return mp_obj_new_bytearray(dklen, out);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uhashlib_pbkdf2_sha1_obj, 4, 4, mod_uhashlib_pbkdf2_sha1);

mp_obj_t mod_uhashlib_pbkdf2_sha256(size_t n_args, const mp_obj_t *args) {
    uint8_t out[0x200];
    mp_buffer_info_t pwdinfo, saltinfo;
    mp_get_buffer_raise(args[0], &pwdinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(args[1], &saltinfo, MP_BUFFER_READ);

    int iter = mp_obj_int_get_truncated(args[2]);
    int dklen = mp_obj_int_get_truncated(args[3]);
    dklen = MIN(dklen, sizeof(out));

    if (pbkdf2_sha256(pwdinfo.buf, pwdinfo.len, saltinfo.buf, saltinfo.len, iter, out, dklen) != 0) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "PBKDF2-SHA256 failed"));
    }

    return mp_obj_new_bytearray(dklen, out);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uhashlib_pbkdf2_sha256_obj, 4, 4, mod_uhashlib_pbkdf2_sha256);

mp_obj_t mod_uhashlib_jenkins_oaat(size_t n_args, const mp_obj_t *args) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    uint32_t init_val = 0;
    if (n_args > 1) {
        // custom initial value
        init_val = mp_obj_int_get_truncated(args[1]);
    }

    uint32_t crc = jenkins_oaat_hash(bufinfo.buf, bufinfo.len, init_val);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uhashlib_jenkins_oaat_obj, 1, 2, mod_uhashlib_jenkins_oaat);

mp_obj_t mod_uhashlib_jhash(size_t n_args, const mp_obj_t *args) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    uint32_t init_val = 0;
    if (n_args > 1) {
        // custom initial value
        init_val = mp_obj_int_get_truncated(args[1]);
    }

    uint32_t crc = jhash(bufinfo.buf, bufinfo.len, init_val);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uhashlib_jhash_obj, 1, 2, mod_uhashlib_jhash);

mp_obj_t mod_uhashlib_lookup3_little2(mp_obj_t data, mp_obj_t pc_iv1, mp_obj_t pb_iv2) {
    uint8_t out[4];
    mp_obj_t items[2];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t iv1 = mp_obj_int_get_truncated(pc_iv1);
    uint32_t iv2 = mp_obj_int_get_truncated(pb_iv2);
    lookup3_hashlittle2(bufinfo.buf, bufinfo.len, &iv1, &iv2);

    write_be_uint32(out, iv1);
    items[0] = mp_obj_new_bytearray(sizeof(out), out);
    write_be_uint32(out, iv2);
    items[1] = mp_obj_new_bytearray(sizeof(out), out);

    return mp_obj_new_tuple(2, items);
}
MP_DEFINE_CONST_FUN_OBJ_3(mod_uhashlib_lookup3_little2_obj, mod_uhashlib_lookup3_little2);

mp_obj_t mod_uhashlib_sha224(mp_obj_t data) {
    uint8_t out[32];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    sha256(bufinfo.buf, bufinfo.len, out, 1);

    return mp_obj_new_bytearray(28, out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_sha224_obj, mod_uhashlib_sha224);

mp_obj_t mod_uhashlib_md5(mp_obj_t data) {
    uint8_t out[16];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    md5(bufinfo.buf, bufinfo.len, out);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_md5_obj, mod_uhashlib_md5);

mp_obj_t mod_uhashlib_md5_xor(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t hash = md5_xor_hash(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, hash);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_md5_xor_obj, mod_uhashlib_md5_xor);

mp_obj_t mod_uhashlib_murmur3_32(size_t n_args, const mp_obj_t *args) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    uint32_t init_val = 0;
    if (n_args > 1) {
        // custom initial value
        init_val = mp_obj_int_get_truncated(args[1]);
    }

    uint32_t crc = murmur3_32(bufinfo.buf, bufinfo.len, init_val);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uhashlib_murmur3_32_obj, 1, 2, mod_uhashlib_murmur3_32);

mp_obj_t mod_uhashlib_sdbm(size_t n_args, const mp_obj_t *args) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    uint32_t init_val = 0;
    if (n_args > 1) {
        // custom initial value
        init_val = mp_obj_int_get_truncated(args[1]);
    }

    uint32_t crc = sdbm_hash(bufinfo.buf, bufinfo.len, init_val);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_uhashlib_sdbm_obj, 1, 2, mod_uhashlib_sdbm);

mp_obj_t mod_uhashlib_sha1(mp_obj_t data) {
    uint8_t out[20];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    sha1(bufinfo.buf, bufinfo.len, out);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_sha1_obj, mod_uhashlib_sha1);

mp_obj_t mod_uhashlib_sha256(mp_obj_t data) {
    uint8_t out[32];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    sha256(bufinfo.buf, bufinfo.len, out, 0);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_sha256_obj, mod_uhashlib_sha256);

mp_obj_t mod_uhashlib_sha384(mp_obj_t data) {
    uint8_t out[64];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    sha512(bufinfo.buf, bufinfo.len, out, 1);

    return mp_obj_new_bytearray(48, out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_sha384_obj, mod_uhashlib_sha384);

mp_obj_t mod_uhashlib_sha512(mp_obj_t data) {
    uint8_t out[64];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    sha512(bufinfo.buf, bufinfo.len, out, 0);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_sha512_obj, mod_uhashlib_sha512);

mp_obj_t mod_uhashlib_sha1_xor64(mp_obj_t data) {
    uint8_t out[8];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint64_t shaxor = sha1_xor64_hash(bufinfo.buf, bufinfo.len);
    write_be_uint64(out, shaxor);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_sha1_xor64_obj, mod_uhashlib_sha1_xor64);

mp_obj_t mod_uhashlib_eachecksum(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = MC02_hash(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_eachecksum_obj, mod_uhashlib_eachecksum);

mp_obj_t mod_uhashlib_ffx_checksum(mp_obj_t data) {
    uint8_t out[2];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    // FFX hash is stored in little-endian
    uint16_t crc = ffx_hash(bufinfo.buf, bufinfo.len);
    write_le_uint16(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_ffx_checksum_obj, mod_uhashlib_ffx_checksum);

mp_obj_t mod_uhashlib_ff13_checksum(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    // FFXIII hash is stored in little-endian
    uint32_t crc = ff13_checksum(bufinfo.buf, bufinfo.len);
    write_le_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_ff13_checksum_obj, mod_uhashlib_ff13_checksum);

mp_obj_t mod_uhashlib_kh25_checksum(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    // Kingdom Hearts 2.5 hash is stored in little-endian
    uint32_t crc = kh25_hash(bufinfo.buf, bufinfo.len);
    write_le_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_kh25_checksum_obj, mod_uhashlib_kh25_checksum);

mp_obj_t mod_uhashlib_khcom_checksum(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = kh_com_hash(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_khcom_checksum_obj, mod_uhashlib_khcom_checksum);

mp_obj_t mod_uhashlib_mgs2_checksum(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = mgs2_hash(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_mgs2_checksum_obj, mod_uhashlib_mgs2_checksum);

mp_obj_t mod_uhashlib_mgspw_checksum(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = mgspw_Checksum(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_mgspw_checksum_obj, mod_uhashlib_mgspw_checksum);

mp_obj_t mod_uhashlib_sw4_checksum(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    mp_obj_t items[4];
    uint32_t hash[4];

    sw4_hash(bufinfo.buf, bufinfo.len, hash);
    write_be_uint32(out, hash[0]);
    items[0] = mp_obj_new_bytearray(sizeof(out), out);
    write_be_uint32(out, hash[1]);
    items[1] = mp_obj_new_bytearray(sizeof(out), out);
    write_be_uint32(out, hash[2]);
    items[2] = mp_obj_new_bytearray(sizeof(out), out);
    write_be_uint32(out, hash[3]);
    items[3] = mp_obj_new_bytearray(sizeof(out), out);

    return mp_obj_new_tuple(4, items);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_sw4_checksum_obj, mod_uhashlib_sw4_checksum);

mp_obj_t mod_uhashlib_toz_checksum(mp_obj_t data) {
    uint8_t out[20];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    toz_hash(bufinfo.buf, bufinfo.len, out);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_toz_checksum_obj, mod_uhashlib_toz_checksum);

mp_obj_t mod_uhashlib_tiara2_checksum(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = tiara2_hash(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_tiara2_checksum_obj, mod_uhashlib_tiara2_checksum);

mp_obj_t mod_uhashlib_castlevania_checksum(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    // Castlevania LOS hash is stored in little-endian
    uint32_t crc = castlevania_hash(bufinfo.buf, bufinfo.len);
    write_le_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_castlevania_checksum_obj, mod_uhashlib_castlevania_checksum);

mp_obj_t mod_uhashlib_rockstar_checksum(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t chks = 0, chks_len = 0;
    uint8_t* chks_off = NULL;
    const uint8_t* start = bufinfo.buf;

    // Updates all CHKS values
    chks_off = (uint8_t*) mp_find_subbytes(start, bufinfo.len - (start - (uint8_t*)bufinfo.buf), (uint8_t*)"CHKS", 5, 1);
    while (chks_off)
    {
        chks = read_be_uint32 ((&chks_off[4]));
        chks_len = read_be_uint32 ((&chks_off[8]));

        memset(chks_off + 8, 0, 8);
        chks = jenkins_oaat_hash((uint8_t*) (chks_off - chks_len + chks), chks_len, 0x3FAC7125);
        DEBUG_printf(" + CHKS Size: 0x%X Offset: %p - Wrote Checksum: %08X\n", chks_len, chks_off, chks);

        write_be_uint32((&chks_off[0xC]), chks);
        write_be_uint32((&chks_off[0x8]), chks_len);

        start = chks_off + 1;
        chks_off = (uint8_t*) mp_find_subbytes(start, bufinfo.len - (start - (uint8_t*)bufinfo.buf), (uint8_t*)"CHKS", 5, 1);
    }

    write_be_uint32(out, chks);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_rockstar_checksum_obj, mod_uhashlib_rockstar_checksum);

mp_obj_t mod_uhashlib_dbzxv2_checksum(mp_obj_t data) {
    uint8_t out[8];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint64_t crc = dbzxv2_checksum(bufinfo.buf, bufinfo.len);
    write_be_uint64(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_dbzxv2_checksum_obj, mod_uhashlib_dbzxv2_checksum);

mp_obj_t mod_uhashlib_deadrising_checksum(mp_obj_t data) {
    uint8_t out[4];
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    uint32_t crc = deadrising_checksum(bufinfo.buf, bufinfo.len);
    write_be_uint32(out, crc);

    return mp_obj_new_bytearray(sizeof(out), out);
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_uhashlib_deadrising_checksum_obj, mod_uhashlib_deadrising_checksum);

#if MICROPY_PY_UHASHLIB

STATIC const mp_rom_map_elem_t mp_module_hashlib_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_uhashlib) },
    { MP_ROM_QSTR(MP_QSTR_CRC_16_BITS), MP_OBJ_NEW_SMALL_INT(16) },
    { MP_ROM_QSTR(MP_QSTR_CRC_32_BITS), MP_OBJ_NEW_SMALL_INT(32) },
    { MP_ROM_QSTR(MP_QSTR_CRC_64_BITS), MP_OBJ_NEW_SMALL_INT(64) },
    { MP_ROM_QSTR(MP_QSTR_crc), MP_ROM_PTR(&mod_uhashlib_crc_obj) },
    { MP_ROM_QSTR(MP_QSTR_crc16), MP_ROM_PTR(&mod_uhashlib_crc16_obj) },
    { MP_ROM_QSTR(MP_QSTR_crc32), MP_ROM_PTR(&mod_uhashlib_crc32_obj) },
    { MP_ROM_QSTR(MP_QSTR_crc32big), MP_ROM_PTR(&mod_uhashlib_crc32big_obj) },
    { MP_ROM_QSTR(MP_QSTR_crc64_iso), MP_ROM_PTR(&mod_uhashlib_crc64_iso_obj) },
    { MP_ROM_QSTR(MP_QSTR_crc64_ecma), MP_ROM_PTR(&mod_uhashlib_crc64_ecma_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha224), MP_ROM_PTR(&mod_uhashlib_sha224_obj) },
    { MP_ROM_QSTR(MP_QSTR_md5), MP_ROM_PTR(&mod_uhashlib_md5_obj) },
    { MP_ROM_QSTR(MP_QSTR_md5_xor), MP_ROM_PTR(&mod_uhashlib_md5_xor_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha1), MP_ROM_PTR(&mod_uhashlib_sha1_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha256), MP_ROM_PTR(&mod_uhashlib_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha384), MP_ROM_PTR(&mod_uhashlib_sha384_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha512), MP_ROM_PTR(&mod_uhashlib_sha512_obj) },
    { MP_ROM_QSTR(MP_QSTR_hmac_sha1), MP_ROM_PTR(&mod_uhashlib_hmac_sha1_obj) },
    { MP_ROM_QSTR(MP_QSTR_pbkdf2_sha1), MP_ROM_PTR(&mod_uhashlib_pbkdf2_sha1_obj) },
    { MP_ROM_QSTR(MP_QSTR_pbkdf2_sha256), MP_ROM_PTR(&mod_uhashlib_pbkdf2_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha1_xor64), MP_ROM_PTR(&mod_uhashlib_sha1_xor64_obj) },
    { MP_ROM_QSTR(MP_QSTR_adler16), MP_ROM_PTR(&mod_uhashlib_adler16_obj) },
    { MP_ROM_QSTR(MP_QSTR_adler32), MP_ROM_PTR(&mod_uhashlib_adler32_obj) },
    { MP_ROM_QSTR(MP_QSTR_checksum32), MP_ROM_PTR(&mod_uhashlib_checksum32_obj) },
    { MP_ROM_QSTR(MP_QSTR_sdbm), MP_ROM_PTR(&mod_uhashlib_sdbm_obj) },
    { MP_ROM_QSTR(MP_QSTR_fnv1), MP_ROM_PTR(&mod_uhashlib_fnv1_obj) },
    { MP_ROM_QSTR(MP_QSTR_add), MP_ROM_PTR(&mod_uhashlib_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_wadd), MP_ROM_PTR(&mod_uhashlib_wadd_obj) },
    { MP_ROM_QSTR(MP_QSTR_dwadd), MP_ROM_PTR(&mod_uhashlib_dwadd_obj) },
    { MP_ROM_QSTR(MP_QSTR_qwadd), MP_ROM_PTR(&mod_uhashlib_qwadd_obj) },
    { MP_ROM_QSTR(MP_QSTR_wadd_le), MP_ROM_PTR(&mod_uhashlib_wadd_le_obj) },
    { MP_ROM_QSTR(MP_QSTR_dwadd_le), MP_ROM_PTR(&mod_uhashlib_dwadd_le_obj) },
    { MP_ROM_QSTR(MP_QSTR_wsub), MP_ROM_PTR(&mod_uhashlib_wsub_obj) },
    { MP_ROM_QSTR(MP_QSTR_force_crc32), MP_ROM_PTR(&mod_uhashlib_force_crc32_obj) },
    { MP_ROM_QSTR(MP_QSTR_murmur3_32), MP_ROM_PTR(&mod_uhashlib_murmur3_32_obj) },
    { MP_ROM_QSTR(MP_QSTR_jhash), MP_ROM_PTR(&mod_uhashlib_jhash_obj) },
    { MP_ROM_QSTR(MP_QSTR_jenkins_oaat), MP_ROM_PTR(&mod_uhashlib_jenkins_oaat_obj) },
    { MP_ROM_QSTR(MP_QSTR_lookup3_little2), MP_ROM_PTR(&mod_uhashlib_lookup3_little2_obj) },
    { MP_ROM_QSTR(MP_QSTR_djb2), MP_ROM_PTR(&mod_uhashlib_djb2_obj) },
    { MP_ROM_QSTR(MP_QSTR_ea_checksum), MP_ROM_PTR(&mod_uhashlib_eachecksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_ffx_checksum), MP_ROM_PTR(&mod_uhashlib_ffx_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_ff13_checksum), MP_ROM_PTR(&mod_uhashlib_ff13_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_kh25_checksum), MP_ROM_PTR(&mod_uhashlib_kh25_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_khcom_checksum), MP_ROM_PTR(&mod_uhashlib_khcom_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_mgs2_checksum), MP_ROM_PTR(&mod_uhashlib_mgs2_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_mgspw_checksum), MP_ROM_PTR(&mod_uhashlib_mgspw_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_sw4_checksum), MP_ROM_PTR(&mod_uhashlib_sw4_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_toz_checksum), MP_ROM_PTR(&mod_uhashlib_toz_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_tiara2_checksum), MP_ROM_PTR(&mod_uhashlib_tiara2_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_castlevania_checksum), MP_ROM_PTR(&mod_uhashlib_castlevania_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_rockstar_checksum), MP_ROM_PTR(&mod_uhashlib_rockstar_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_dbzxv2_checksum), MP_ROM_PTR(&mod_uhashlib_dbzxv2_checksum_obj) },
    { MP_ROM_QSTR(MP_QSTR_deadrising_checksum), MP_ROM_PTR(&mod_uhashlib_deadrising_checksum_obj) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_hashlib_globals, mp_module_hashlib_globals_table);

const mp_obj_module_t mp_module_uhashlib = {
    .base = { &mp_type_module },
    .name = MP_QSTR_uhashlib,
    .globals = (mp_obj_dict_t*)&mp_module_hashlib_globals,
};

#endif //MICROPY_PY_UHASHLIB
