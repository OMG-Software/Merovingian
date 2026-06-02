// SPDX-License-Identifier: GPL-3.0-or-later

#include "yyjson_adapter.h"

#include <yyjson.h>

static MerovingianYyjsonReadCode merovingian_yyjson_map_read_code(yyjson_read_code code)
{
    if (code == YYJSON_READ_SUCCESS)
    {
        return MEROVINGIAN_YYJSON_READ_SUCCESS;
    }
    if (code == YYJSON_READ_ERROR_INVALID_PARAMETER)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_INVALID_PARAMETER;
    }
    if (code == YYJSON_READ_ERROR_MEMORY_ALLOCATION)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_MEMORY_ALLOCATION;
    }
    if (code == YYJSON_READ_ERROR_EMPTY_CONTENT)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_EMPTY_CONTENT;
    }
    if (code == YYJSON_READ_ERROR_UNEXPECTED_CONTENT)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_UNEXPECTED_CONTENT;
    }
    if (code == YYJSON_READ_ERROR_UNEXPECTED_END)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_UNEXPECTED_END;
    }
    if (code == YYJSON_READ_ERROR_UNEXPECTED_CHARACTER)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_UNEXPECTED_CHARACTER;
    }
    if (code == YYJSON_READ_ERROR_JSON_STRUCTURE)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_JSON_STRUCTURE;
    }
    if (code == YYJSON_READ_ERROR_INVALID_COMMENT)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_INVALID_COMMENT;
    }
    if (code == YYJSON_READ_ERROR_INVALID_NUMBER)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_INVALID_NUMBER;
    }
    if (code == YYJSON_READ_ERROR_INVALID_STRING)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_INVALID_STRING;
    }
    if (code == YYJSON_READ_ERROR_LITERAL)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_LITERAL;
    }
    if (code == YYJSON_READ_ERROR_FILE_OPEN)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_FILE_OPEN;
    }
    if (code == YYJSON_READ_ERROR_FILE_READ)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_FILE_READ;
    }
    if (code == YYJSON_READ_ERROR_MORE)
    {
        return MEROVINGIAN_YYJSON_READ_ERROR_MORE;
    }
    return MEROVINGIAN_YYJSON_READ_ERROR_INVALID_PARAMETER;
}

MerovingianYyjsonDoc* merovingian_yyjson_read_raw_numbers(char const* data, size_t length,
                                                          MerovingianYyjsonReadCode* error_code)
{
    yyjson_read_err error;
    // YYJSON_READ_STOP_WHEN_DONE makes the parser stop at the end of the
    // top-level value; payloads with trailing garbage (which canonical JSON
    // forbids) are then rejected. The flag has been in yyjson since 0.5.0,
    // well before the 0.12.0 pin in subprojects/yyjson.wrap.
    yyjson_doc* document = yyjson_read_opts(
        (char*)data, length, YYJSON_READ_NUMBER_AS_RAW | YYJSON_READ_STOP_WHEN_DONE, NULL, &error);
    if (error_code != NULL)
    {
        *error_code = merovingian_yyjson_map_read_code(error.code);
    }
    return document;
}

void merovingian_yyjson_doc_free(MerovingianYyjsonDoc* document)
{
    yyjson_doc_free(document);
}

MerovingianYyjsonValue* merovingian_yyjson_doc_root(MerovingianYyjsonDoc* document)
{
    return yyjson_doc_get_root(document);
}

MerovingianYyjsonValueType merovingian_yyjson_value_type(MerovingianYyjsonValue* value)
{
    if (yyjson_is_null(value))
    {
        return MEROVINGIAN_YYJSON_TYPE_NULL;
    }
    if (yyjson_is_bool(value))
    {
        return MEROVINGIAN_YYJSON_TYPE_BOOL;
    }
    if (yyjson_is_raw(value))
    {
        return MEROVINGIAN_YYJSON_TYPE_RAW;
    }
    if (yyjson_is_str(value))
    {
        return MEROVINGIAN_YYJSON_TYPE_STRING;
    }
    if (yyjson_is_arr(value))
    {
        return MEROVINGIAN_YYJSON_TYPE_ARRAY;
    }
    if (yyjson_is_obj(value))
    {
        return MEROVINGIAN_YYJSON_TYPE_OBJECT;
    }
    return MEROVINGIAN_YYJSON_TYPE_UNKNOWN;
}

int merovingian_yyjson_bool_value(MerovingianYyjsonValue* value)
{
    return yyjson_get_bool(value) ? 1 : 0;
}

char const* merovingian_yyjson_raw_data(MerovingianYyjsonValue* value, size_t* length)
{
    if (length != NULL)
    {
        *length = yyjson_get_len(value);
    }
    return yyjson_get_raw(value);
}

char const* merovingian_yyjson_string_data(MerovingianYyjsonValue* value, size_t* length)
{
    if (length != NULL)
    {
        *length = yyjson_get_len(value);
    }
    return yyjson_get_str(value);
}

size_t merovingian_yyjson_array_size(MerovingianYyjsonValue* value)
{
    return yyjson_arr_size(value);
}

size_t merovingian_yyjson_object_size(MerovingianYyjsonValue* value)
{
    return yyjson_obj_size(value);
}

int merovingian_yyjson_array_foreach(MerovingianYyjsonValue* value, MerovingianYyjsonArrayCallback callback,
                                     void* user_data)
{
    yyjson_arr_iter iterator = yyjson_arr_iter_with(value);
    yyjson_val* item = NULL;
    while ((item = yyjson_arr_iter_next(&iterator)) != NULL)
    {
        if (callback(item, user_data) == 0)
        {
            return 0;
        }
    }
    return 1;
}

int merovingian_yyjson_object_foreach(MerovingianYyjsonValue* value, MerovingianYyjsonObjectCallback callback,
                                      void* user_data)
{
    yyjson_obj_iter iterator = yyjson_obj_iter_with(value);
    yyjson_val* key = NULL;
    while ((key = yyjson_obj_iter_next(&iterator)) != NULL)
    {
        size_t key_length = 0U;
        char const* key_data = yyjson_get_str(key);
        yyjson_val* member_value = yyjson_obj_iter_get_val(key);
        key_length = yyjson_get_len(key);
        if (callback(key_data, key_length, member_value, user_data) == 0)
        {
            return 0;
        }
    }
    return 1;
}
