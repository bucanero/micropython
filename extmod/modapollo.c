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

//---  Generic helper functions ---//
MP_DECLARE_CONST_FUN_OBJ(mod_apollo_search_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_apollo_endian_swap_obj);
MP_DECLARE_CONST_FUN_OBJ(mod_apollo_reverse_search_obj);

STATIC const MP_DEFINE_STR_OBJ(mod_apollo_version_obj, APOLLO_LIB_VERSION);


mp_obj_t mod_apollo_endian_swap(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);

    size_t wbytes = bufinfo.len;
    if (n_args > 1) {
        // custom initial value
        wbytes = mp_obj_int_get_truncated(args[1]);
    }

    if (wbytes == 2) {
        uint16_t* out = bufinfo.buf;
        for (size_t i=0; i < bufinfo.len/2; i++)
            out[i] = __builtin_bswap16(out[i]);

    } else if (wbytes == 4) {
        uint32_t* out = bufinfo.buf;
        for (size_t i=0; i < bufinfo.len/4; i++)
            out[i] = __builtin_bswap32(out[i]);

    } else if (wbytes == 8) {
        uint64_t* out = bufinfo.buf;
        for (size_t i=0; i < bufinfo.len/8; i++)
            out[i] = __builtin_bswap64(out[i]);

    } else {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "Invalid word size for endian swap"));
    }

    return args[0];
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_apollo_endian_swap_obj, 1, 2, mod_apollo_endian_swap);

mp_obj_t mod_apollo_search(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t bufinfo, findinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(args[1], &findinfo, MP_BUFFER_READ);

    int count = 1;
    if (n_args > 2) {
        // custom initial value
        count = mp_obj_int_get_truncated(args[2]);
    }

    const uint8_t* found = NULL;
    const uint8_t* start = bufinfo.buf;

    for (int i=0; i < count; i++) {
        found = mp_find_subbytes(start, bufinfo.len - (start - (uint8_t*)bufinfo.buf), findinfo.buf, findinfo.len, 1);
        if (!found)
            return mp_const_none;

        start = found + 1;
    }

    return mp_obj_new_int_from_uint((mp_uint_t)(found - (uint8_t*)bufinfo.buf));
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_apollo_search_obj, 2, 3, mod_apollo_search);

mp_obj_t mod_apollo_reverse_search(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t bufinfo, findinfo;
    mp_get_buffer_raise(args[0], &bufinfo, MP_BUFFER_READ);
    mp_get_buffer_raise(args[1], &findinfo, MP_BUFFER_READ);

    int count = 1;
    if (n_args > 2) {
        // custom initial value
        count = mp_obj_int_get_truncated(args[2]);
    }

    const uint8_t* found = NULL;
    size_t len = bufinfo.len;

    for (int i=0; i < count; i++) {
        found = mp_find_subbytes(bufinfo.buf, len, findinfo.buf, findinfo.len, -1);
        if (!found)
            return mp_const_none;

        len = (found - (uint8_t*)bufinfo.buf);
    }

    return mp_obj_new_int_from_uint(len);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_apollo_reverse_search_obj, 2, 3, mod_apollo_reverse_search);


#if MICROPY_PY_APOLLO

STATIC const mp_rom_map_elem_t mp_module_apollo_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_apollo) },
    { MP_ROM_QSTR(MP_QSTR_version), MP_ROM_PTR(&mod_apollo_version_obj) },
    { MP_ROM_QSTR(MP_QSTR_search), MP_ROM_PTR(&mod_apollo_search_obj) },
    { MP_ROM_QSTR(MP_QSTR_endian_swap), MP_ROM_PTR(&mod_apollo_endian_swap_obj) },
    { MP_ROM_QSTR(MP_QSTR_reverse_search), MP_ROM_PTR(&mod_apollo_reverse_search_obj) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_apollo_globals, mp_module_apollo_globals_table);

const mp_obj_module_t mp_module_apollo = {
    .base = { &mp_type_module },
    .name = MP_QSTR_apollo,
    .globals = (mp_obj_dict_t*)&mp_module_apollo_globals,
};

#endif //MICROPY_PY_APOLLO
