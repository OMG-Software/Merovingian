// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct yyjson_doc MerovingianYyjsonDoc;
    typedef struct yyjson_val MerovingianYyjsonValue;

    typedef enum MerovingianYyjsonReadCode
    {
        MEROVINGIAN_YYJSON_READ_SUCCESS = 0,
        MEROVINGIAN_YYJSON_READ_ERROR_INVALID_PARAMETER = 1,
        MEROVINGIAN_YYJSON_READ_ERROR_MEMORY_ALLOCATION = 2,
        MEROVINGIAN_YYJSON_READ_ERROR_EMPTY_CONTENT = 3,
        MEROVINGIAN_YYJSON_READ_ERROR_UNEXPECTED_CONTENT = 4,
        MEROVINGIAN_YYJSON_READ_ERROR_UNEXPECTED_END = 5,
        MEROVINGIAN_YYJSON_READ_ERROR_UNEXPECTED_CHARACTER = 6,
        MEROVINGIAN_YYJSON_READ_ERROR_JSON_STRUCTURE = 7,
        MEROVINGIAN_YYJSON_READ_ERROR_INVALID_COMMENT = 8,
        MEROVINGIAN_YYJSON_READ_ERROR_INVALID_NUMBER = 9,
        MEROVINGIAN_YYJSON_READ_ERROR_INVALID_STRING = 10,
        MEROVINGIAN_YYJSON_READ_ERROR_LITERAL = 11,
        MEROVINGIAN_YYJSON_READ_ERROR_FILE_OPEN = 12,
        MEROVINGIAN_YYJSON_READ_ERROR_FILE_READ = 13,
        MEROVINGIAN_YYJSON_READ_ERROR_MORE = 14,
    } MerovingianYyjsonReadCode;

    typedef enum MerovingianYyjsonValueType
    {
        MEROVINGIAN_YYJSON_TYPE_NULL = 0,
        MEROVINGIAN_YYJSON_TYPE_BOOL = 1,
        MEROVINGIAN_YYJSON_TYPE_RAW = 2,
        MEROVINGIAN_YYJSON_TYPE_STRING = 3,
        MEROVINGIAN_YYJSON_TYPE_ARRAY = 4,
        MEROVINGIAN_YYJSON_TYPE_OBJECT = 5,
        MEROVINGIAN_YYJSON_TYPE_NUMBER = 7,
        MEROVINGIAN_YYJSON_TYPE_UNKNOWN = 6,
    } MerovingianYyjsonValueType;

    typedef int (*MerovingianYyjsonArrayCallback)(MerovingianYyjsonValue* value, void* user_data);
    typedef int (*MerovingianYyjsonObjectCallback)(char const* key_data, size_t key_length,
                                                   MerovingianYyjsonValue* value, void* user_data);

    MerovingianYyjsonDoc* merovingian_yyjson_read_raw_numbers(char const* data, size_t length,
                                                              MerovingianYyjsonReadCode* error_code);
    // Parse JSON allowing floating-point and exponent notation. Numbers are
    // surfaced as MEROVINGIAN_YYJSON_TYPE_NUMBER and must be read with the
    // number accessor functions below.
    MerovingianYyjsonDoc* merovingian_yyjson_read_numbers(char const* data, size_t length,
                                                          MerovingianYyjsonReadCode* error_code);
    void merovingian_yyjson_doc_free(MerovingianYyjsonDoc* document);
    MerovingianYyjsonValue* merovingian_yyjson_doc_root(MerovingianYyjsonDoc* document);
    // Number of input bytes yyjson consumed while parsing the document. Used
    // by the parser to detect trailing-garbage payloads that canonical JSON
    // forbids; if the value is less than the input length, extra bytes
    // follow the top-level value and the parse must be rejected.
    size_t merovingian_yyjson_doc_bytes_read(MerovingianYyjsonDoc* document);
    MerovingianYyjsonValueType merovingian_yyjson_value_type(MerovingianYyjsonValue* value);
    int merovingian_yyjson_bool_value(MerovingianYyjsonValue* value);
    char const* merovingian_yyjson_raw_data(MerovingianYyjsonValue* value, size_t* length);
    char const* merovingian_yyjson_string_data(MerovingianYyjsonValue* value, size_t* length);
    int merovingian_yyjson_number_is_integer(MerovingianYyjsonValue* value);
    long long merovingian_yyjson_number_as_int64(MerovingianYyjsonValue* value);
    double merovingian_yyjson_number_as_double(MerovingianYyjsonValue* value);
    size_t merovingian_yyjson_array_size(MerovingianYyjsonValue* value);
    size_t merovingian_yyjson_object_size(MerovingianYyjsonValue* value);
    int merovingian_yyjson_array_foreach(MerovingianYyjsonValue* value, MerovingianYyjsonArrayCallback callback,
                                         void* user_data);
    int merovingian_yyjson_object_foreach(MerovingianYyjsonValue* value, MerovingianYyjsonObjectCallback callback,
                                          void* user_data);

#ifdef __cplusplus
}
#endif
