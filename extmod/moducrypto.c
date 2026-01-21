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

//---  Custom crypto functions ---//
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_diablo3_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_dw8xl_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_silent_hill3_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_nfs_undercover_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_final_fantasy13_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_borderlands3_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_mgs_pw_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_mgs_base64_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_mgs_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_mgs5_tpp_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_monster_hunter_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_rgg_studio_obj);

//---  Generic crypto functions ---//
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_aes_ecb_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_aes_cbc_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_aes_ctr_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_des_ecb_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_des3_cbc_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_blowfish_ecb_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_blowfish_cbc_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_ucrypto_camellia_ecb_obj);


mp_obj_t mod_ucrypto_dw8xl(mp_obj_t data) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    dw8xl_encode_data(bufinfo.buf, bufinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_ucrypto_dw8xl_obj, mod_ucrypto_dw8xl);

mp_obj_t mod_ucrypto_diablo3(mp_obj_t enc_mode, mp_obj_t data) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        diablo_encrypt_data(bufinfo.buf, bufinfo.len);
    else
        // decryption mode
        diablo_decrypt_data(bufinfo.buf, bufinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_2(mod_ucrypto_diablo3_obj, mod_ucrypto_diablo3);

mp_obj_t mod_ucrypto_silent_hill3(mp_obj_t enc_mode, mp_obj_t data) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        sh3_encrypt_data(bufinfo.buf, bufinfo.len);
    else
        // decryption mode
        sh3_decrypt_data(bufinfo.buf, bufinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_2(mod_ucrypto_silent_hill3_obj, mod_ucrypto_silent_hill3);

mp_obj_t mod_ucrypto_nfs_undercover(mp_obj_t enc_mode, mp_obj_t data) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        nfsu_encrypt_data(bufinfo.buf, bufinfo.len);
    else
        // decryption mode
        nfsu_decrypt_data(bufinfo.buf, bufinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_2(mod_ucrypto_nfs_undercover_obj, mod_ucrypto_nfs_undercover);

mp_obj_t mod_ucrypto_final_fantasy13(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t bufinfo, keyinfo;
    mp_get_buffer_raise(args[1], &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &keyinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(args[0]))
        // encryption mode
        ff13_encrypt_data(mp_obj_int_get_truncated(args[3]), bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);
    else
        // decryption mode
        ff13_decrypt_data(mp_obj_int_get_truncated(args[3]), bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);

    return args[1];
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_ucrypto_final_fantasy13_obj, 4, 4, mod_ucrypto_final_fantasy13);

mp_obj_t mod_ucrypto_borderlands3(mp_obj_t enc_mode, mp_obj_t data, mp_obj_t type) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        borderlands3_Encrypt(bufinfo.buf, bufinfo.len, mp_obj_int_get_truncated(type));
    else
        // decryption mode
        borderlands3_Decrypt(bufinfo.buf, bufinfo.len, mp_obj_int_get_truncated(type));

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_3(mod_ucrypto_borderlands3_obj, mod_ucrypto_borderlands3);

mp_obj_t mod_ucrypto_mgs_pw(mp_obj_t enc_mode, mp_obj_t data) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        mgspw_Encrypt(bufinfo.buf, bufinfo.len);
    else
        // decryption mode
        mgspw_Decrypt(bufinfo.buf, bufinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_2(mod_ucrypto_mgs_pw_obj, mod_ucrypto_mgs_pw);

mp_obj_t mod_ucrypto_mgs_base64(mp_obj_t enc_mode, mp_obj_t data) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        mgs_EncodeBase64(bufinfo.buf, bufinfo.len);
    else
        // decryption mode
        mgs_DecodeBase64(bufinfo.buf, bufinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_2(mod_ucrypto_mgs_base64_obj, mod_ucrypto_mgs_base64);

mp_obj_t mod_ucrypto_mgs5_tpp(mp_obj_t data, mp_obj_t key) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    mgs5tpp_encode_data(bufinfo.buf, bufinfo.len, mp_obj_int_get_truncated(key));

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_2(mod_ucrypto_mgs5_tpp_obj, mod_ucrypto_mgs5_tpp);

mp_obj_t mod_ucrypto_rgg_studio(mp_obj_t data, mp_obj_t key) {
    mp_buffer_info_t bufinfo, keyinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(key, &keyinfo, MP_BUFFER_READ);

    rgg_xor_data(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_2(mod_ucrypto_rgg_studio_obj, mod_ucrypto_rgg_studio);

mp_obj_t mod_ucrypto_mgs(mp_obj_t enc_mode, mp_obj_t data, mp_obj_t key) {
    mp_buffer_info_t bufinfo, keyinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(key, &keyinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        mgs_Encrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);
    else
        // decryption mode
        mgs_Decrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_3(mod_ucrypto_mgs_obj, mod_ucrypto_mgs);

mp_obj_t mod_ucrypto_monster_hunter(mp_obj_t enc_mode, mp_obj_t data, mp_obj_t gver) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);

    int ver = mp_obj_int_get_truncated(gver);
    if (ver != 2 && ver != 3) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "Game version must be 2 or 3"));
    }

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        monsterhunter_encrypt_data(bufinfo.buf, bufinfo.len, ver);
    else
        // decryption mode
        monsterhunter_decrypt_data(bufinfo.buf, bufinfo.len, ver);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_3(mod_ucrypto_monster_hunter_obj, mod_ucrypto_monster_hunter);

mp_obj_t mod_ucrypto_aes_ecb(mp_obj_t enc_mode, mp_obj_t data, mp_obj_t key) {
    mp_buffer_info_t bufinfo, keyinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(key, &keyinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        aes_ecb_encrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);
    else
        // decryption mode
        aes_ecb_decrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_3(mod_ucrypto_aes_ecb_obj, mod_ucrypto_aes_ecb);

mp_obj_t mod_ucrypto_aes_ctr(mp_obj_t data, mp_obj_t key, mp_obj_t iv) {
    mp_buffer_info_t bufinfo, keyinfo, ivinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(key, &keyinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(iv, &ivinfo, MP_BUFFER_READ);

    aes_ctr_xcrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len, ivinfo.buf, ivinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_3(mod_ucrypto_aes_ctr_obj, mod_ucrypto_aes_ctr);

mp_obj_t mod_ucrypto_blowfish_ecb(mp_obj_t enc_mode, mp_obj_t data, mp_obj_t key) {
    mp_buffer_info_t bufinfo, keyinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(key, &keyinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        blowfish_ecb_encrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);
    else
        // decryption mode
        blowfish_ecb_decrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_3(mod_ucrypto_blowfish_ecb_obj, mod_ucrypto_blowfish_ecb);

mp_obj_t mod_ucrypto_camellia_ecb(mp_obj_t enc_mode, mp_obj_t data, mp_obj_t key) {
    mp_buffer_info_t bufinfo, keyinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(key, &keyinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        camellia_ecb_encrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);
    else
        // decryption mode
        camellia_ecb_decrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_3(mod_ucrypto_camellia_ecb_obj, mod_ucrypto_camellia_ecb);

mp_obj_t mod_ucrypto_des_ecb(mp_obj_t enc_mode, mp_obj_t data, mp_obj_t key) {
    mp_buffer_info_t bufinfo, keyinfo;
    mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(key, &keyinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(enc_mode))
        // encryption mode
        des_ecb_encrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);
    else
        // decryption mode
        des_ecb_decrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len);

    return data;
}
MP_DEFINE_CONST_FUN_OBJ_3(mod_ucrypto_des_ecb_obj, mod_ucrypto_des_ecb);

mp_obj_t mod_ucrypto_aes_cbc(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t bufinfo, keyinfo, ivinfo;
    mp_get_buffer_raise(args[1], &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &keyinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(args[3], &ivinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(args[0]))
        // encryption mode
        aes_cbc_encrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len, ivinfo.buf, ivinfo.len);
    else
        // decryption mode
        aes_cbc_decrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len, ivinfo.buf, ivinfo.len);

    return args[1];
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_ucrypto_aes_cbc_obj, 4, 4, mod_ucrypto_aes_cbc);

mp_obj_t mod_ucrypto_blowfish_cbc(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t bufinfo, keyinfo, ivinfo;
    mp_get_buffer_raise(args[1], &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &keyinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(args[3], &ivinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(args[0]))
        // encryption mode
        blowfish_cbc_encrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len, ivinfo.buf, ivinfo.len);
    else
        // decryption mode
        blowfish_cbc_decrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len, ivinfo.buf, ivinfo.len);

    return args[1];
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_ucrypto_blowfish_cbc_obj, 4, 4, mod_ucrypto_blowfish_cbc);

mp_obj_t mod_ucrypto_des3_cbc(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t bufinfo, keyinfo, ivinfo;
    mp_get_buffer_raise(args[1], &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &keyinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(args[3], &ivinfo, MP_BUFFER_READ);

    if (mp_obj_int_get_truncated(args[0]))
        // encryption mode
        des3_cbc_encrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len, ivinfo.buf, ivinfo.len);
    else
        // decryption mode
        des3_cbc_decrypt(bufinfo.buf, bufinfo.len, keyinfo.buf, keyinfo.len, ivinfo.buf, ivinfo.len);

    return args[1];
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_ucrypto_des3_cbc_obj, 4, 4, mod_ucrypto_des3_cbc);

#if MICROPY_PY_UCRYPTO

STATIC const mp_rom_map_elem_t mp_module_ucrypto_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ucrypto) },
    { MP_ROM_QSTR(MP_QSTR_DECRYPT), MP_OBJ_NEW_SMALL_INT(0) },
    { MP_ROM_QSTR(MP_QSTR_ENCRYPT), MP_OBJ_NEW_SMALL_INT(1) },
    { MP_ROM_QSTR(MP_QSTR_diablo3), MP_ROM_PTR(&mod_ucrypto_diablo3_obj) },
    { MP_ROM_QSTR(MP_QSTR_dw8xl), MP_ROM_PTR(&mod_ucrypto_dw8xl_obj) },
    { MP_ROM_QSTR(MP_QSTR_silent_hill3), MP_ROM_PTR(&mod_ucrypto_silent_hill3_obj) },
    { MP_ROM_QSTR(MP_QSTR_nfs_undercover), MP_ROM_PTR(&mod_ucrypto_nfs_undercover_obj) },
    { MP_ROM_QSTR(MP_QSTR_final_fantasy13), MP_ROM_PTR(&mod_ucrypto_final_fantasy13_obj) },
    { MP_ROM_QSTR(MP_QSTR_borderlands3), MP_ROM_PTR(&mod_ucrypto_borderlands3_obj) },
    { MP_ROM_QSTR(MP_QSTR_mgs_pw), MP_ROM_PTR(&mod_ucrypto_mgs_pw_obj) },
    { MP_ROM_QSTR(MP_QSTR_mgs_base64), MP_ROM_PTR(&mod_ucrypto_mgs_base64_obj) },
    { MP_ROM_QSTR(MP_QSTR_mgs), MP_ROM_PTR(&mod_ucrypto_mgs_obj) },
    { MP_ROM_QSTR(MP_QSTR_mgs5_tpp), MP_ROM_PTR(&mod_ucrypto_mgs5_tpp_obj) },
    { MP_ROM_QSTR(MP_QSTR_monster_hunter), MP_ROM_PTR(&mod_ucrypto_monster_hunter_obj) },
    { MP_ROM_QSTR(MP_QSTR_rgg_studio), MP_ROM_PTR(&mod_ucrypto_rgg_studio_obj) },
    { MP_ROM_QSTR(MP_QSTR_aes_ecb), MP_ROM_PTR(&mod_ucrypto_aes_ecb_obj) },
    { MP_ROM_QSTR(MP_QSTR_aes_cbc), MP_ROM_PTR(&mod_ucrypto_aes_cbc_obj) },
    { MP_ROM_QSTR(MP_QSTR_aes_ctr), MP_ROM_PTR(&mod_ucrypto_aes_ctr_obj) },
    { MP_ROM_QSTR(MP_QSTR_des_ecb), MP_ROM_PTR(&mod_ucrypto_des_ecb_obj) },
    { MP_ROM_QSTR(MP_QSTR_des3_cbc), MP_ROM_PTR(&mod_ucrypto_des3_cbc_obj) },
    { MP_ROM_QSTR(MP_QSTR_blowfish_ecb), MP_ROM_PTR(&mod_ucrypto_blowfish_ecb_obj) },
    { MP_ROM_QSTR(MP_QSTR_blowfish_cbc), MP_ROM_PTR(&mod_ucrypto_blowfish_cbc_obj) },
    { MP_ROM_QSTR(MP_QSTR_camellia_ecb), MP_ROM_PTR(&mod_ucrypto_camellia_ecb_obj) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_ucrypto_globals, mp_module_ucrypto_globals_table);

const mp_obj_module_t mp_module_ucrypto = {
    .base = { &mp_type_module },
    .name = MP_QSTR_ucrypto,
    .globals = (mp_obj_dict_t*)&mp_module_ucrypto_globals,
};

#endif //MICROPY_PY_UCRYPTO
