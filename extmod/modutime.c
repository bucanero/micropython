/*
 *
 * Copyright (c) 2026 Damian Parrino
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
#include <string.h>
#include <time.h>

#include "py/nlr.h"
#include "py/obj.h"
#include "py/smallint.h"

/// \module time - time related functions
///
/// The `time` module provides functions for getting the current time and date
/// and for manipulating times and dates.
/******************************************************************************/
// Micro Python bindings

/// \function localtime([secs])
/// Convert a time expressed in seconds since Jan 1, 1970 into an 8-tuple which
/// contains: (year, month, mday, hour, minute, second, weekday, yearday)
/// If secs is not provided or None, then the current time from the system is used.
/// year includes the century (for example 2015)
/// month   is 1-12
/// mday    is 1-31
/// hour    is 0-23
/// minute  is 0-59
/// second  is 0-59
/// weekday is 0-6 for Mon-Sun.
/// yearday is 1-366
STATIC mp_obj_t time_localtime(mp_uint_t n_args, const mp_obj_t *args) {
    time_t current_time;
    struct tm *local_tm;

    if (n_args == 0 || args[0] == mp_const_none) {
        current_time = time (NULL);
    } else {
        current_time = mp_obj_get_int(args[0]);
    }

    local_tm = localtime (&current_time);

    mp_obj_t tuple[9] = {
            mp_obj_new_int(local_tm->tm_year + 1900),
            mp_obj_new_int(local_tm->tm_mon + 1),
            mp_obj_new_int(local_tm->tm_mday),
            mp_obj_new_int(local_tm->tm_hour),
            mp_obj_new_int(local_tm->tm_min),
            mp_obj_new_int(local_tm->tm_sec),
            mp_obj_new_int((local_tm->tm_wday - 1) < 0 ? 6 : (local_tm->tm_wday - 1)),
            mp_obj_new_int(local_tm->tm_yday + 1),
            mp_obj_new_int(-1)
    };

    return mp_obj_new_tuple(9, tuple);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(time_localtime_obj, 0, 1, time_localtime);

STATIC time_t micropy_time_tuple_parse(struct _mp_state_ctx_t *mp_state, mp_obj_t tuple)
{
    struct tm tm_info;
    mp_uint_t len;
    mp_obj_t *elem;

    mp_obj_get_array(tuple, &len, &elem);

    // localtime generates a tuple of len 8. CPython uses 9, so we accept both.
    if (len < 8 || len > 9) {
        nlr_raise(mp_obj_new_exception_msg(&mp_type_TypeError, "mktime() argument must be a tuple of length 8 or 9"));
    }

    tm_info.tm_year = mp_obj_get_int(elem[0]) - 1900;
    tm_info.tm_mon  = mp_obj_get_int(elem[1]) - 1;
    tm_info.tm_mday = mp_obj_get_int(elem[2]);
    tm_info.tm_hour = mp_obj_get_int(elem[3]);
    tm_info.tm_min  = mp_obj_get_int(elem[4]);
    tm_info.tm_sec  = mp_obj_get_int(elem[5]);
    tm_info.tm_isdst = -1;

    return mktime (&tm_info);
}

STATIC mp_obj_t time_mktime(mp_obj_t tuple) {
    return mp_obj_new_int_from_uint(time_tuple_parse(tuple));
}
MP_DEFINE_CONST_FUN_OBJ_1(time_mktime_obj, time_mktime);

STATIC mp_obj_t time_time(void) {
    return mp_obj_new_int(time (NULL));
}
MP_DEFINE_CONST_FUN_OBJ_0(time_time_obj, time_time);

STATIC mp_obj_t time_gmtime(mp_uint_t n_args, const mp_obj_t *args) {
    time_t current_time;
    struct tm *local_tm;

    if (n_args == 0 || args[0] == mp_const_none) {
        current_time = time (NULL);
    } else {
        current_time = mp_obj_get_int(args[0]);
    }

    local_tm = gmtime (&current_time);

    mp_obj_t tuple[9] = {
            mp_obj_new_int(local_tm->tm_year + 1900),
            mp_obj_new_int(local_tm->tm_mon + 1),
            mp_obj_new_int(local_tm->tm_mday),
            mp_obj_new_int(local_tm->tm_hour),
            mp_obj_new_int(local_tm->tm_min),
            mp_obj_new_int(local_tm->tm_sec),
            mp_obj_new_int((local_tm->tm_wday - 1) < 0 ? 6 : (local_tm->tm_wday - 1)),
            mp_obj_new_int(local_tm->tm_yday + 1),
            mp_obj_new_int(-1)
    };

    return mp_obj_new_tuple(9, tuple);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(time_gmtime_obj, 0, 1, time_gmtime);

STATIC mp_obj_t mod_time_strftime(size_t n_args, const mp_obj_t *args) {
    time_t t;
    if (n_args == 1) {
        t = time (NULL);
    } else if (mp_obj_get_type(args[1]) == &mp_type_tuple) {
        t = time_tuple_parse(args[1]);
    } else {
        // CPython requires passing struct tm, but we allow to pass time_t
        t = mp_obj_get_int(args[1]);
    }
    struct tm *tm = localtime (&t);
    char buf[64];
    size_t sz = strftime (buf, sizeof(buf), mp_obj_str_get_str(args[0]), tm);
    return mp_obj_new_str(buf, sz, false);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_time_strftime_obj, 1, 2, mod_time_strftime);

#if MICROPY_PY_UTIME

STATIC const mp_map_elem_t time_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__),        MP_OBJ_NEW_QSTR(MP_QSTR_utime) },

    { MP_ROM_QSTR(MP_QSTR_localtime),       (mp_obj_t)&time_localtime_obj },
    { MP_ROM_QSTR(MP_QSTR_mktime),          (mp_obj_t)&time_mktime_obj },
    { MP_ROM_QSTR(MP_QSTR_time),            (mp_obj_t)&time_time_obj },
    { MP_ROM_QSTR(MP_QSTR_gmtime),          (mp_obj_t)&time_gmtime_obj },
    { MP_ROM_QSTR(MP_QSTR_strftime),        (mp_obj_t)(&mod_time_strftime_obj) },
};

STATIC MP_DEFINE_CONST_DICT(time_module_globals, time_module_globals_table);

const mp_obj_module_t mp_module_utime = {
    .base = { &mp_type_module },
    .name = MP_QSTR_utime,
    .globals = (mp_obj_dict_t*)&time_module_globals,
};

#endif // MICROPY_PY_UTIME
