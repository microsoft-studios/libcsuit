/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "csuit/suit_manifest_decode.h"

/*!
    \file   suit_manifest_decode.c

    \brief  This implements libcsuit docoding

    Call suit_decode_envelope() to decode whole SUIT manifest.
 */

suit_err_t suit_decode_digest_from_item(const suit_decode_mode_t mode,
                                        QCBORDecodeContext *context,
                                        QCBORItem *item,
                                        bool next,
                                        suit_digest_t *digest)
{
    digest->algorithm_id = SUIT_ALGORITHM_ID_INVALID;
    digest->bytes.len = 0;
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t ext_len = (item->val.uCount > 2) ? item->val.uCount - 2 : 0;

    result = suit_qcbor_get_next(context, item, QCBOR_TYPE_INT64);
    if (!suit_continue(mode, result)) {
        return result;
    }
    digest->algorithm_id = item->val.int64;

    result = suit_qcbor_get_next(context, item, QCBOR_TYPE_BYTE_STRING);
    if (!suit_continue(mode, result)) {
        return result;
    }
    if (result == SUIT_SUCCESS) {
        digest->bytes.ptr = (uint8_t *)item->val.string.ptr;
        digest->bytes.len = item->val.string.len;
    }

    for (size_t i = 0; i < ext_len; i++) {
        // TODO
        if (!suit_continue(mode, SUIT_ERR_NOT_IMPLEMENTED)) {
            return SUIT_ERR_NOT_IMPLEMENTED;
        }
        if (!suit_qcbor_skip_any(context, item)) {
            return SUIT_ERR_NO_MORE_ITEMS;
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_decode_digest(const suit_decode_mode_t mode,
                              suit_buf_t *buf,
                              suit_digest_t *digest)
{
    QCBORDecodeContext digest_context;
    QCBORItem item;
    QCBORDecode_Init(&digest_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    suit_err_t result = suit_decode_digest_from_item(mode, &digest_context, &item, true, digest);
    QCBORError error = QCBORDecode_Finish(&digest_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

suit_err_t suit_decode_digest_from_bstr(const suit_decode_mode_t mode,
                                        QCBORDecodeContext *context,
                                        QCBORItem *item,
                                        bool next,
                                        suit_digest_t *digest)
{
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    suit_buf_t buf;
    buf.ptr = (uint8_t *)item->val.string.ptr;
    buf.len = item->val.string.len;
    return suit_decode_digest(mode, &buf, digest);
}

suit_err_t suit_decode_parameters_list_from_item(const suit_decode_mode_t mode,
                                                 QCBORDecodeContext *context,
                                                 QCBORItem *item,
                                                 bool next,
                                                 suit_parameters_list_t *params_list)
{
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    if (item->val.uCount >= SUIT_MAX_ARRAY_LENGTH) {
        return SUIT_ERR_NO_MEMORY;
    }

    params_list->len = item->val.uCount;
    int64_t label = INT64_MIN;
    for (size_t i = 0; i < params_list->len; i++) {
        result = suit_qcbor_get_next_label_type(context, item, QCBOR_TYPE_ANY, QCBOR_TYPE_INT64);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        if (label > item->label.int64 && !mode.ALLOW_NOT_CANONICAL_CBOR) {
            return SUIT_ERR_NOT_CANONICAL_CBOR;
        }
        label = item->label.int64;
        params_list->params[i].label = label;
        switch (label) {
        /* uint */
        case SUIT_PARAMETER_COMPONENT_SLOT:
        case SUIT_PARAMETER_IMAGE_SIZE:
        case SUIT_PARAMETER_SOURCE_COMPONENT:
        case SUIT_PARAMETER_USE_BEFORE:
        case SUIT_PARAMETER_MINIMUM_BATTERY:
        case SUIT_PARAMETER_UPDATE_PRIORITY:
            if (!suit_qcbor_value_is_uint64(item)) {
                result = SUIT_ERR_INVALID_TYPE_OF_VALUE;
                break;
            }
            params_list->params[i].value.uint64 = item->val.uint64;
            break;

        /* tstr */
        case SUIT_PARAMETER_URI:
            if (item->uDataType != QCBOR_TYPE_TEXT_STRING) {
                result = SUIT_ERR_INVALID_TYPE_OF_VALUE;
                break;
            }
            params_list->params[i].value.string.ptr = (uint8_t *)item->val.string.ptr;
            params_list->params[i].value.string.len = item->val.string.len;
            break;

        /* bstr */
        case SUIT_PARAMETER_VENDOR_IDENTIFIER:
        case SUIT_PARAMETER_CLASS_IDENTIFIER:
        case SUIT_PARAMETER_DEVICE_IDENTIFIER:
        case SUIT_PARAMETER_CONTENT:
        //case SUIT_PARAMETER_FETCH_ARGS:
        case SUIT_PARAMETER_INVOKE_ARGS:
        /* draft-ietf-suit-firmware-encryption */
        case SUIT_PARAMETER_ENCRYPTION_INFO:
            if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                result = SUIT_ERR_INVALID_TYPE_OF_VALUE;
                break;
            }
            params_list->params[i].value.string.ptr = (uint8_t *)item->val.string.ptr;
            params_list->params[i].value.string.len = item->val.string.len;
            break;

        /* bool */
        case SUIT_PARAMETER_STRICT_ORDER:
        case SUIT_PARAMETER_SOFT_FAILURE:
            if (item->uDataType == QCBOR_TYPE_TRUE) {
                params_list->params[i].value.boolean = true;
            }
            else if (item->uDataType != QCBOR_TYPE_FALSE) {
                params_list->params[i].value.boolean = false;
            }
            else {
                result = SUIT_ERR_INVALID_TYPE_OF_VALUE;
            }
            break;

        /* SUIT_Digest */
        case SUIT_PARAMETER_IMAGE_DIGEST:
            result = suit_decode_digest_from_bstr(mode, context, item, false, &params_list->params[i].value.digest);
            break;

        /* SUIT_Parameter_Version_Match */
        case SUIT_PARAMETER_VERSION:

        /* bstr wrapped SUIT_Wait_Event */
        case SUIT_PARAMETER_WAIT_INFO:

        default:
            result = SUIT_ERR_NOT_IMPLEMENTED;
            break;
        }
        if (!suit_continue(mode, result)) {
            return result;
        }
        if (result != SUIT_SUCCESS && !suit_qcbor_skip_any(context, item)) {
            return SUIT_ERR_NO_MORE_ITEMS;
        }
        result = SUIT_SUCCESS;
    }
    return result;
}

bool is_suit_directive_only(int64_t label)
{
    /* NOTE:
     * SUIT_Common_Commands is a subset of SUIT_Directive
     */
    switch (label) {
    /* {SUIT_Directive - SUIT_Common_Commands} should not come */
    case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
    case SUIT_DIRECTIVE_FETCH:
    case SUIT_DIRECTIVE_COPY:
    case SUIT_DIRECTIVE_SWAP:
    case SUIT_DIRECTIVE_INVOKE:
    //case SUIT_DIRECTIVE_FETCH_URI_LIST:
        return true;
    }
    return false;
}

suit_err_t suit_decode_command_shared_sequence_from_item(const suit_decode_mode_t mode,
                                                         QCBORDecodeContext *context,
                                                         QCBORItem *item,
                                                         bool next,
                                                         suit_command_sequence_t *cmd_seq,
                                                         bool is_shared_sequence)
{
    /* NOTE:
     * SUIT_Common_Sequence  = [ + (SUIT_Condition // SUIT_Common_Commands) ]
     * SUIT_Command_Sequence = [ + (SUIT_Condition // SUIT_Directive // SUIT_Command_Custom ] */
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t array_count = item->val.uCount;
    cmd_seq->len = 0;
    for (size_t i = 0; i < array_count; i += 2) {
        if (cmd_seq->len >= SUIT_MAX_ARRAY_LENGTH) {
            return SUIT_ERR_NO_MEMORY;
        }
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_INT64);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        /* NOTE: we are in [key, value, key, valye, ...] array,
         * and don't care about canonical CBOR
         */
        if (!(item->uDataType == QCBOR_TYPE_UINT64 ||
            (item->uDataType == QCBOR_TYPE_INT64 && item->val.int64 > 0))) {
            return SUIT_ERR_INVALID_TYPE_OF_KEY;
        }
        int64_t label = item->val.int64;

        /* SUIT_Condition // SUIT_Directive */
        if (is_shared_sequence && is_suit_directive_only(label)) {
            /* SUIT_Command_Custom should not come, so skip them */
            return SUIT_ERR_INVALID_KEY;
        }
        switch (label) {
        /* SUIT_Rep_Policy */
        case SUIT_CONDITION_VENDOR_IDENTIFIER:
        case SUIT_CONDITION_CLASS_IDENTIFIER:
        case SUIT_CONDITION_IMAGE_MATCH:
        case SUIT_CONDITION_COMPONENT_SLOT:
        case SUIT_CONDITION_CHECK_CONTENT:
        case SUIT_CONDITION_ABORT:
        case SUIT_CONDITION_DEVICE_IDENTIFIER:

        /* in draft-ietf-suit-trust-domains */
        case SUIT_CONDITION_DEPENDENCY_INTEGRITY:
        case SUIT_CONDITION_IS_DEPENDENCY:

        /* in draft-ietf-suit-update-management */
        case SUIT_CONDITION_USE_BEFORE:
        case SUIT_CONDITION_IMAGE_NOT_MATCH:
        case SUIT_CONDITION_MINIMUM_BATTERY:
        case SUIT_CONDITION_UPDATE_AUTHORIZED:
        case SUIT_CONDITION_VERSION:

        case SUIT_DIRECTIVE_WRITE:
        case SUIT_DIRECTIVE_FETCH:
        case SUIT_DIRECTIVE_COPY:
        case SUIT_DIRECTIVE_INVOKE:
        case SUIT_DIRECTIVE_SWAP:

        /* in draft-ietf-suit-update-management */
        case SUIT_DIRECTIVE_WAIT:

        /* in draft-ietf-suit-trust-domains */
        case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
        case SUIT_DIRECTIVE_UNLINK:
            result = suit_qcbor_get_next_uint(context, item);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            cmd_seq->commands[cmd_seq->len].label = label;
            cmd_seq->commands[cmd_seq->len].value.uint64 = item->val.uint64;
            cmd_seq->len++;
            break;

        /* bstr */
        case SUIT_DIRECTIVE_RUN_SEQUENCE:
            result = suit_qcbor_get_next(context, item, QCBOR_TYPE_BYTE_STRING);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            cmd_seq->commands[cmd_seq->len].label = label;
            cmd_seq->commands[cmd_seq->len].value.string.ptr = (uint8_t *)item->val.string.ptr;
            cmd_seq->commands[cmd_seq->len].value.string.len = item->val.string.len;
            cmd_seq->len++;
            break;

        /* uint, true, [ + uint ] */
        case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
            result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ANY);
            if (result != SUIT_SUCCESS) {
                return result;
            }

            cmd_seq->commands[cmd_seq->len].label = label;
            switch (item->uDataType) {
            case QCBOR_TYPE_INT64:
                if (item->val.int64 < 0) {
                    return SUIT_ERR_INVALID_TYPE_OF_VALUE;
                }
                // fallthrough
            case QCBOR_TYPE_UINT64:
                if (item->val.uint64 > SUIT_MAX_INDEX_NUM) {
                    return SUIT_ERR_INVALID_VALUE;
                }
                cmd_seq->commands[cmd_seq->len].value.index_arg.len = 1;
                cmd_seq->commands[cmd_seq->len].value.index_arg.index[0] = item->val.uint64;
                break;
            case QCBOR_TYPE_ARRAY:
                if (item->val.uCount == 0) {
                    return SUIT_ERR_INVALID_VALUE;
                }
                cmd_seq->commands[cmd_seq->len].value.index_arg.len = item->val.uCount;
                for (size_t j = 0; j < cmd_seq->commands[cmd_seq->len].value.index_arg.len; j++) {
                    if (item->val.uint64 > SUIT_MAX_INDEX_NUM) {
                        return SUIT_ERR_INVALID_VALUE;
                    }
                    cmd_seq->commands[cmd_seq->len].value.index_arg.index[j] = item->val.uint64;
                }
            case QCBOR_TYPE_TRUE:
                cmd_seq->commands[cmd_seq->len].value.index_arg.len = 0;
                break;
            default:
                return SUIT_ERR_INVALID_TYPE_OF_VALUE;
            }
            cmd_seq->len++;
            break;

        /* $$SUIT_Parameters */
        case SUIT_DIRECTIVE_SET_PARAMETERS:
        case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
            result = suit_decode_parameters_list_from_item(mode, context, item, true, &cmd_seq->commands[cmd_seq->len].value.params_list);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            cmd_seq->commands[cmd_seq->len].label = label;
            cmd_seq->len++;
            break;

        /* SUIT_Directive_Try_Each_Argument */
        case SUIT_DIRECTIVE_TRY_EACH:
            /* XXX: should not extract here? */
            result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ARRAY);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            size_t try_index = item->val.uCount;
            /* store unpacked array items */
            for (size_t j = 0; j < try_index; j++) {
                if (cmd_seq->len >= SUIT_MAX_ARRAY_LENGTH) {
                    return SUIT_ERR_NO_MEMORY;
                }
                result = suit_qcbor_get_next(context, item, QCBOR_TYPE_BYTE_STRING);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                cmd_seq->commands[cmd_seq->len].label = label;
                cmd_seq->commands[cmd_seq->len].value.string.len = item->val.string.len;
                cmd_seq->commands[cmd_seq->len].value.string.ptr = (uint8_t *)item->val.string.ptr;
                cmd_seq->len++;
            }
            break;

        /* SUIT_Override_Mult_Arg */
        //case SUIT_DIRECTIVE_OVERRIDE_MULTIPLE:

        /* SUIT_Directive_Copy_Params */
        //case SUIT_DIRECTIVE_COPY_PARAMS:

        case SUIT_CONDITION_INVALID:
        default:
            return SUIT_ERR_NOT_IMPLEMENTED;
        }
    }
    return result;
}

suit_err_t suit_decode_shared_sequence_from_item(const suit_decode_mode_t mode,
                                                 QCBORDecodeContext *context,
                                                 QCBORItem *item,
                                                 bool next,
                                                 suit_command_sequence_t *cmn_seq)
{
    return suit_decode_command_shared_sequence_from_item(mode, context, item, next, cmn_seq, true);
}

suit_err_t suit_decode_shared_sequence(const suit_decode_mode_t mode,
                                       const suit_buf_t *buf,
                                       suit_command_sequence_t *cmn_seq)
{
    QCBORDecodeContext cmn_seq_context;
    QCBORItem item;
    QCBORDecode_Init(&cmn_seq_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    suit_err_t result = suit_decode_shared_sequence_from_item(mode, &cmn_seq_context, &item, true, cmn_seq);
    QCBORError error = QCBORDecode_Finish(&cmn_seq_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

suit_err_t suit_decode_shared_sequence_from_bstr(const suit_decode_mode_t mode,
                                                 QCBORDecodeContext *context,
                                                 QCBORItem *item,
                                                 bool next,
                                                 suit_command_sequence_t *cmn_seq)
{
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    suit_buf_t buf;
    buf.len = item->val.string.len;
    buf.ptr = (uint8_t *)item->val.string.ptr;
    return suit_decode_command_sequence(mode, &buf, cmn_seq);
}

suit_err_t suit_decode_command_sequence_from_item(const suit_decode_mode_t mode,
                                                  QCBORDecodeContext *context,
                                                  QCBORItem *item,
                                                  bool next,
                                                  suit_command_sequence_t *cmd_seq)
{
    return suit_decode_command_shared_sequence_from_item(mode, context, item, next, cmd_seq, false);
}

suit_err_t suit_decode_command_sequence(const suit_decode_mode_t mode,
                                        const suit_buf_t *buf,
                                        suit_command_sequence_t *cmd_seq)
{
    QCBORDecodeContext cmd_seq_context;
    QCBORItem item;
    QCBORDecode_Init(&cmd_seq_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    suit_err_t result = suit_decode_command_sequence_from_item(mode, &cmd_seq_context, &item, true, cmd_seq);
    QCBORError error = QCBORDecode_Finish(&cmd_seq_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

suit_err_t suit_decode_command_sequence_from_bstr(const suit_decode_mode_t mode,
                                                  QCBORDecodeContext *context,
                                                  QCBORItem *item,
                                                  bool next,
                                                  suit_command_sequence_t *cmd_seq)
{
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    suit_buf_t buf;
    buf.len = item->val.string.len;
    buf.ptr = (uint8_t *)item->val.string.ptr;
    return suit_decode_command_sequence(mode, &buf, cmd_seq);
}

suit_err_t suit_decode_component_identifiers_from_item(const suit_decode_mode_t mode,
                                                       QCBORDecodeContext *context,
                                                       QCBORItem *item,
                                                       bool next,
                                                       suit_component_identifier_t *identifier)
{
    identifier->len = 0;

    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t len = item->val.uCount;
    for (size_t i = 0; i < len; i++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_BYTE_STRING);
        if (!suit_continue(mode, result)) {
            break;
        }
        if (result == SUIT_SUCCESS) {
            if (identifier->len >= SUIT_MAX_ARRAY_LENGTH) {
                result = SUIT_ERR_NO_MEMORY;
                break;
            }
            identifier->identifier[identifier->len].ptr = (uint8_t *)item->val.string.ptr;
            identifier->identifier[identifier->len].len = item->val.string.len;
            identifier->len++;
        }
    }
    return result;
}

suit_err_t suit_decode_component_identifiers(const suit_decode_mode_t mode,
                                             suit_buf_t *buf,
                                             suit_component_identifier_t *identifier)
{
    QCBORDecodeContext component_context;
    QCBORItem item;
    QCBORDecode_Init(&component_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    suit_err_t result = suit_decode_component_identifiers_from_item(mode, &component_context, &item, true, identifier);
    QCBORError error = QCBORDecode_Finish(&component_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

suit_err_t suit_decode_components_from_item(const suit_decode_mode_t mode,
                                            QCBORDecodeContext *context,
                                            QCBORItem *item,
                                            bool next,
                                            suit_component_with_index_t *components,
                                            uint8_t *num)
{
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t len = item->val.uCount;
    if (len > SUIT_MAX_INDEX_NUM) {
        return SUIT_ERR_NO_MEMORY;
    }
    for (size_t i = 0; i < len; i++) {
        result = suit_qcbor_get(context, item, true, QCBOR_TYPE_ARRAY);
        if (!suit_continue(mode, result)) {
            break;
        }
        if (result == SUIT_SUCCESS) {
            result = suit_decode_component_identifiers_from_item(mode, context, item, false, &components[i].component);
            if (result == SUIT_ERR_INVALID_TYPE_OF_VALUE) {
                if (!suit_qcbor_skip_any(context, item)) {
                    result = SUIT_ERR_FATAL;
                }
            }
            components[i].index = i;
        }
        if (!suit_continue(mode, result)) {
            break;
        }
    }
    if (num != NULL) {
        *num = len;
    }
    return result;
}

suit_err_t suit_decode_dependency_metadata_from_item(const suit_decode_mode_t mode,
                                                     QCBORDecodeContext *context,
                                                     QCBORItem *item,
                                                     bool next,
                                                     suit_dependency_metadata_t *dependency_metadata)
{
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    size_t len = item->val.uCount;
    for (size_t i = 0; i < len; i++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ANY);
        if (!suit_continue(mode, result)) {
            break;
        }

        switch (item->label.uint64) {
        case SUIT_DEPENDENCY_PREFIX:
            result = suit_decode_component_identifiers_from_item(mode, context, item, false, &dependency_metadata->prefix);
            break;
        default:
            // TODO
            result = SUIT_ERR_NOT_IMPLEMENTED;
            if (!suit_qcbor_skip_any(context, item)) {
                result = SUIT_ERR_FATAL;
            }
            break;
        }
    }
    return result;
}

suit_err_t suit_decode_dependencies_from_item(const suit_decode_mode_t mode,
                                              QCBORDecodeContext *context,
                                              QCBORItem *item,
                                              bool next,
                                              suit_dependencies_t *dependencies)
{
    dependencies->len = 0;

    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t map_count = item->val.uCount;
    for (size_t i = 0; i < map_count; i++) {
        result = suit_qcbor_get(context, item, true, QCBOR_TYPE_MAP);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        if (dependencies->len >= SUIT_MAX_ARRAY_LENGTH) {
            return SUIT_ERR_NO_MEMORY;
        }
        suit_dependency_t *dependency = &dependencies->dependency[dependencies->len];
        if (!(item->uLabelType == QCBOR_TYPE_UINT64 ||
            (item->uLabelType == QCBOR_TYPE_INT64 && item->label.int64 > 0))) {
            return SUIT_ERR_INVALID_TYPE_OF_KEY;
        }
        dependency->index = item->label.uint64;
        result = suit_decode_dependency_metadata_from_item(mode, context, item, false, &dependency->dependency_metadata);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        dependencies->len++;
    }
    return result;
}

suit_err_t suit_decode_authentication_block(const suit_decode_mode_t mode,
                                            suit_buf_t *buf,
                                            suit_buf_t *digest_buf,
                                            const suit_key_t *public_key)
{
    UsefulBufC signed_cose = {buf->ptr, buf->len};
    suit_err_t result;
    cbor_tag_key_t cose_tag = suit_judge_cose_tag_from_buf(signed_cose);

    UsefulBufC returned_payload = {.ptr = digest_buf->ptr, .len = digest_buf->len};
    switch (cose_tag) {
    case COSE_SIGN1_TAG:
        result = suit_verify_cose_sign1(signed_cose, public_key, &returned_payload);
        break;
    default:
        result = SUIT_ERR_NOT_IMPLEMENTED;
    }
    return result;
}

suit_err_t suit_decode_common_from_item(const suit_decode_mode_t mode,
                                        QCBORDecodeContext *context,
                                        QCBORItem *item,
                                        bool next,
                                        suit_common_t *common)
{
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t map_count = item->val.uCount;
    for (size_t i = 0; i < map_count; i++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ANY);
        if (!suit_continue(mode, result)) {
            break;
        }
        switch (item->label.uint64) {
        case SUIT_DEPENDENCIES:
            result = suit_decode_dependencies_from_item(mode, context, item, false, &common->dependencies);
            break;
        case SUIT_COMPONENTS:
            result = suit_decode_components_from_item(mode, context, item, false, common->components, &common->components_len);
            break;
        case SUIT_SHARED_SEQUENCE:
            result = suit_decode_shared_sequence_from_bstr(mode, context, item, false, &common->shared_seq);
            break;
        default:
            // TODO
            return SUIT_ERR_NOT_IMPLEMENTED;
        }
        if (!suit_continue(mode, result)) {
            return result;
        }
    }

    return result;
}

suit_err_t suit_decode_common_from_bstr(const suit_decode_mode_t mode,
                                        QCBORDecodeContext *context,
                                        QCBORItem *item,
                                        bool next,
                                        suit_common_t *common)
{
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    QCBORDecodeContext common_context;
    QCBORDecode_Init(&common_context,
                     item->val.string,
                     QCBOR_DECODE_MODE_NORMAL);
    result = suit_decode_common_from_item(mode, &common_context, item, true, common);
    QCBORError error = QCBORDecode_Finish(&common_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

suit_err_t suit_decode_text_component_from_item(const suit_decode_mode_t mode,
                                                QCBORDecodeContext *context,
                                                QCBORItem *item,
                                                bool next,
                                                suit_text_component_t *text_component)
{
    /* NOTE: in QCBOR_DECODE_MODE_MAP_AS_ARRAY */
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP_AS_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t map_count = item->val.uCount;
    for (size_t i = 0; i < map_count; i += 2) {
        suit_err_t result = suit_qcbor_get_next_uint(context, item);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        suit_buf_t *buf = NULL;
        switch (item->val.uint64) {
        case SUIT_TEXT_VENDOR_NAME:
            buf = &text_component->vendor_name;
            break;
        case SUIT_TEXT_MODEL_NAME:
            buf = &text_component->model_name;
            break;
        case SUIT_TEXT_VENDOR_DOMAIN:
            buf = &text_component->vendor_domain;
            break;
        case SUIT_TEXT_MODEL_INFO:
            buf = &text_component->model_info;
            break;
        case SUIT_TEXT_COMPONENT_DESCRIPTION:
            buf = &text_component->component_description;
            break;
        case SUIT_TEXT_COMPONENT_VERSION:
            buf = &text_component->component_version;
            break;
        /* in draft-ietf-suit-update-management */
        case SUIT_TEXT_VERSION_REQUIRED:
            buf = &text_component->version_required;
            break;
        default:
            return SUIT_ERR_NOT_IMPLEMENTED;
        }
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_TEXT_STRING);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        buf->len = item->val.string.len;
        buf->ptr = (uint8_t *)item->val.string.ptr;
    }
    return result;
}

suit_err_t suit_decode_text_from_item(const suit_decode_mode_t mode,
                                      QCBORDecodeContext *context,
                                      QCBORItem *item,
                                      bool next,
                                      suit_text_t *text)
{
    /* NOTE: in QCBOR_DECODE_MODE_MAP_AS_ARRAY */
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP_AS_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    size_t map_count = item->val.uCount;
    text->component_len = 0;
    for (size_t i = 0; i < map_count; i += 2) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ANY);
        if (result != SUIT_SUCCESS) {
            return result;
        }

        int64_t label = INT64_MIN;
        switch (item->uDataType) {
        case QCBOR_TYPE_ARRAY:
            if (text->component_len >= SUIT_MAX_ARRAY_LENGTH) {
                return SUIT_ERR_NO_MEMORY;
            }
            result = suit_decode_component_identifiers_from_item(mode, context, item, false, &text->component[text->component_len].key);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            result = suit_decode_text_component_from_item(mode, context, item, true, &text->component[text->component_len].text_component);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            text->component_len++;
            break;
        case QCBOR_TYPE_INT64:
            if (label > item->val.int64 && !mode.ALLOW_NOT_CANONICAL_CBOR) {
                return SUIT_ERR_NOT_CANONICAL_CBOR;
            }
            /* NOTE: we are in [key, value, key, valye, ...] array */
            label = item->val.int64;

            result = suit_qcbor_get_next(context, item, QCBOR_TYPE_TEXT_STRING);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            switch (label) {
            case SUIT_TEXT_MANIFEST_DESCRIPTION:
                text->manifest_description.ptr = (uint8_t *)item->val.string.ptr;
                text->manifest_description.len = item->val.string.len;
                break;
            case SUIT_TEXT_UPDATE_DESCRIPTION:
                text->update_description.ptr = (uint8_t *)item->val.string.ptr;
                text->update_description.len = item->val.string.len;
                break;
            case SUIT_TEXT_MANIFEST_JSON_SOURCE:
                text->manifest_json_source.ptr = (uint8_t *)item->val.string.ptr;
                text->manifest_json_source.len = item->val.string.len;
                break;
            case SUIT_TEXT_MANIFEST_YAML_SOURCE:
                text->manifest_yaml_source.ptr = (uint8_t *)item->val.string.ptr;
                text->manifest_yaml_source.len = item->val.string.len;
                break;
            default:
                return SUIT_ERR_NOT_IMPLEMENTED;
            }
            break;
        case QCBOR_TYPE_UINT64:
            /* XXX: may be used by custom */
            return SUIT_ERR_NOT_IMPLEMENTED;
        default:
            return SUIT_ERR_INVALID_TYPE_OF_KEY;
        }
    }
    return result;
}

suit_err_t suit_decode_text_from_bstr(const suit_decode_mode_t mode,
                                      QCBORDecodeContext *context,
                                      QCBORItem *item,
                                      bool next,
                                      suit_text_t *text)
{
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    QCBORDecodeContext text_context;
    /* NOTE: SUIT_Text_Map may contain component-identifier key,
             so we parse as QCBOR_DECODE_MODE_MAP_AS_ARRAY
             to prevent invalid CBOR Map */
    QCBORDecode_Init(&text_context,
                     (UsefulBufC){item->val.string.ptr, item->val.string.len},
                     QCBOR_DECODE_MODE_MAP_AS_ARRAY);
    result = suit_decode_text_from_item(mode, &text_context, item, true, text);
    QCBORError error = QCBORDecode_Finish(&text_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

suit_err_t suit_decode_manifest_from_item(const suit_decode_mode_t mode,
                                          QCBORDecodeContext *context,
                                          QCBORItem *item,
                                          bool next,
                                          suit_manifest_t *manifest)
{
    manifest->sev_man_mem.dependency_resolution_status = SUIT_SEVERABLE_INVALID;
    manifest->sev_man_mem.payload_fetch_status = SUIT_SEVERABLE_INVALID;
    manifest->sev_man_mem.install_status = SUIT_SEVERABLE_INVALID;
    manifest->sev_man_mem.text_status = SUIT_SEVERABLE_INVALID;
    manifest->sev_man_mem.coswid_status = SUIT_SEVERABLE_INVALID;

    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_MAP);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    size_t map_count = item->val.uCount;
    int64_t label = INT64_MIN;
    for (size_t i = 0; i < map_count; i++) {
        result = suit_qcbor_get_next_label_type(context, item, QCBOR_TYPE_ANY, QCBOR_TYPE_INT64);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        if (label > item->label.int64 && !mode.ALLOW_NOT_CANONICAL_CBOR) {
            return SUIT_ERR_NOT_CANONICAL_CBOR;
        }
        label = item->label.int64;
        switch (label) {
        case SUIT_MANIFEST_VERSION:
            if (!suit_qcbor_value_is_uint64(item)) {
                return SUIT_ERR_INVALID_TYPE_OF_VALUE;
            }
            manifest->version = item->val.uint64;
            break;
        case SUIT_MANIFEST_SEQUENCE_NUMBER:
            if (!suit_qcbor_value_is_uint64(item)) {
                return SUIT_ERR_INVALID_TYPE_OF_VALUE;
            }
            manifest->sequence_number = item->val.uint64;
            break;
        case SUIT_COMMON:
            result = suit_decode_common_from_bstr(mode, context, item, false, &manifest->common);
            break;
        case SUIT_MANIFEST_COMPONENT_ID:
            result = suit_decode_component_identifiers_from_item(mode, context, item, false, &manifest->manifest_component_id);
            break;
        case SUIT_DEPENDENCY_RESOLUTION:
            if (item->uDataType == QCBOR_TYPE_ARRAY) {
                /* SUIT_Digest */
                result = suit_decode_digest_from_item(mode, context, item, false, &manifest->sev_mem_dig.dependency_resolution);
            }
            else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {
                /* bstr .cbor SUIT_Command_Sequence */
                result = suit_decode_command_sequence_from_bstr(mode, context, item, false, &manifest->sev_man_mem.dependency_resolution);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                manifest->sev_man_mem.dependency_resolution_status |= SUIT_SEVERABLE_IN_MANIFEST;
                if (manifest->is_verified) {
                    manifest->sev_man_mem.dependency_resolution_status |= SUIT_SEVERABLE_IS_VERIFIED;
                }
            }
            else {
                return SUIT_ERR_INVALID_TYPE_OF_VALUE;
            }
            break;
        case SUIT_PAYLOAD_FETCH:
            if (item->uDataType == QCBOR_TYPE_ARRAY) {
                /* SUIT_Digest */
                result = suit_decode_digest_from_item(mode, context, item, false, &manifest->sev_mem_dig.payload_fetch);
            }
            else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {
                result = suit_decode_command_sequence_from_bstr(mode, context, item, false, &manifest->sev_man_mem.payload_fetch);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                manifest->sev_man_mem.payload_fetch_status |= SUIT_SEVERABLE_IN_MANIFEST;
                if (manifest->is_verified) {
                    manifest->sev_man_mem.payload_fetch_status |= SUIT_SEVERABLE_IS_VERIFIED;
                }
            }
            else {
                return SUIT_ERR_INVALID_TYPE_OF_VALUE;
            }
            break;
        case SUIT_INSTALL:
            if (item->uDataType == QCBOR_TYPE_ARRAY) {
                /* SUIT_Digest */
                result = suit_decode_digest_from_item(mode, context, item, false, &manifest->sev_mem_dig.install);
            }
            else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {
                /* bstr .cbor SUIT_Command_Sequence */
                result = suit_decode_command_sequence_from_bstr(mode, context, item, false, &manifest->sev_man_mem.install);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                manifest->sev_man_mem.install_status |= SUIT_SEVERABLE_IN_MANIFEST;
                if (manifest->is_verified) {
                    manifest->sev_man_mem.install_status |= SUIT_SEVERABLE_IS_VERIFIED;
                }
            }
            else {
                return SUIT_ERR_INVALID_TYPE_OF_VALUE;
            }
            break;
        case SUIT_TEXT:
            if (item->uDataType == QCBOR_TYPE_ARRAY) {
                /* SUIT_Digest */
                result = suit_decode_digest_from_item(mode, context, item, false, &manifest->sev_mem_dig.text);
            }
            else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {
                /* bstr .cbor SUIT_Text_Map */
                result = suit_decode_text_from_bstr(mode, context, item, false, &manifest->sev_man_mem.text);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                manifest->sev_man_mem.text_status |= SUIT_SEVERABLE_IN_MANIFEST;
                if (manifest->is_verified) {
                    manifest->sev_man_mem.text_status |= SUIT_SEVERABLE_IS_VERIFIED;
                }
            }
            else {
                return SUIT_ERR_INVALID_TYPE_OF_VALUE;
            }
            break;
        case SUIT_COSWID:
            if (item->uDataType == QCBOR_TYPE_ARRAY) {
                /* SUIT_Digest */
                result = suit_decode_digest_from_item(mode, context, item, false, &manifest->sev_mem_dig.coswid);
            }
            else if (item->uDataType == QCBOR_TYPE_BYTE_STRING) {
                /* bstr .cbor concise-software-identity */
                manifest->sev_man_mem.coswid.ptr = (uint8_t *)item->val.string.ptr;
                manifest->sev_man_mem.coswid.len = item->val.string.len;
            }
            else {
                return SUIT_ERR_INVALID_TYPE_OF_VALUE;
            }
            break;
        /* SUIT_Unseverabme_Members */
        case SUIT_VALIDATE:
            result = suit_decode_command_sequence_from_bstr(mode, context, item, false, &manifest->unsev_mem.validate);
            break;
        case SUIT_LOAD:
            result = suit_decode_command_sequence_from_bstr(mode, context, item, false, &manifest->unsev_mem.load);
            break;
        case SUIT_INVOKE:
            result = suit_decode_command_sequence_from_bstr(mode, context, item, false, &manifest->unsev_mem.invoke);
            break;
        /* in draft-ietf-suit-trust-domains */
        case SUIT_UNINSTALL:
            result = suit_decode_command_sequence_from_bstr(mode, context, item, false, &manifest->unsev_mem.uninstall);
            break;

        case SUIT_REFERENCE_URI:
            result = suit_qcbor_get_next(context, item, QCBOR_TYPE_TEXT_STRING);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            manifest->reference_uri.len = item->val.string.len;
            manifest->reference_uri.ptr = (uint8_t *)item->val.string.ptr;
            break;

        default:
            return SUIT_ERR_NOT_IMPLEMENTED;
        }
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    return result;
}

suit_err_t suit_decode_manifest(const suit_decode_mode_t mode,
                                suit_buf_t *buf,
                                suit_manifest_t *manifest)
{
    QCBORDecodeContext manifest_context;
    QCBORItem item;
    QCBORDecode_Init(&manifest_context,
                     (UsefulBufC){buf->ptr, buf->len},
                     QCBOR_DECODE_MODE_NORMAL);
    suit_err_t result = suit_decode_manifest_from_item(mode, &manifest_context, &item, true, manifest);
    QCBORError error = QCBORDecode_Finish(&manifest_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

suit_err_t suit_decode_manifest_from_bstr(const suit_decode_mode_t mode,
                                          QCBORDecodeContext *context,
                                          QCBORItem *item,
                                          bool next,
                                          suit_manifest_t *manifest,
                                          suit_digest_t *digest)
{
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_BYTE_STRING);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    /* verify the SUIT_Manifest with SUIT_Digest */
    result = suit_verify_item(context, item, digest);
    if (!suit_continue(mode, result)) {
        return result;
    }
    if (result == SUIT_SUCCESS) {
        manifest->is_verified = true;
    }
    suit_buf_t buf = {.ptr = (uint8_t *)item->val.string.ptr, .len = item->val.string.len};

    return suit_decode_manifest(mode, &buf, manifest);
}

suit_err_t suit_decode_authentication_wrapper_from_item(const suit_decode_mode_t mode,
                                                        QCBORDecodeContext *context,
                                                        QCBORItem *item,
                                                        bool next,
                                                        suit_authentication_wrapper_t *wrapper,
                                                        suit_mechanism_t mechanisms[])
{
    bool verified = false;
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    if (item->val.uCount >= SUIT_MAX_ARRAY_LENGTH) {
        return SUIT_ERR_NO_MEMORY;
    }
    wrapper->signatures_len = item->val.uCount - 1;

    result = suit_qcbor_get_next(context, item, QCBOR_TYPE_BYTE_STRING);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    suit_buf_t digest_buf;
    digest_buf.ptr = (uint8_t *)item->val.string.ptr;
    digest_buf.len = item->val.string.len;
    result = suit_decode_digest(mode, &digest_buf, &wrapper->digest);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    for (size_t i = 0; i < wrapper->signatures_len; i++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_BYTE_STRING);
        if (result != SUIT_SUCCESS) {
            suit_qcbor_skip_any(context, item);
            continue;
        }
        suit_buf_t *buf = &wrapper->signatures[i];
        buf->ptr = (uint8_t *)item->val.string.ptr;
        buf->len = item->val.string.len;

        for (int32_t j = 0; j < SUIT_MAX_KEY_NUM; j++) {
            result = suit_decode_authentication_block(mode, buf, &digest_buf, &mechanisms[j].key);
            if (result == SUIT_SUCCESS) {
                verified = true;
                mechanisms[j].use = true;
                break;
            }
        }
    }

    return (verified) ? SUIT_SUCCESS : SUIT_ERR_FAILED_TO_VERIFY;
}

suit_err_t suit_decode_authentication_wrapper(const suit_decode_mode_t mode,
                                              suit_buf_t *buf,
                                              suit_authentication_wrapper_t *wrapper,
                                              suit_mechanism_t mechanisms[])
{
    QCBORDecodeContext auth_context;
    QCBORItem item;
    QCBORDecode_Init(&auth_context, (UsefulBufC){buf->ptr, buf->len}, QCBOR_DECODE_MODE_NORMAL);
    suit_err_t result = suit_decode_authentication_wrapper_from_item(mode, &auth_context, &item, true, wrapper, mechanisms);
    QCBORError error = QCBORDecode_Finish(&auth_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

suit_err_t suit_decode_delegation_from_item(const suit_decode_mode_t mode,
                                            QCBORDecodeContext *context,
                                            QCBORItem *item,
                                            bool next,
                                            suit_delegation_t *delegation,
                                            suit_mechanism_t mechanisms[])
{
    suit_err_t result = suit_qcbor_get(context, item, next, QCBOR_TYPE_ARRAY);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    if (item->val.uCount >= SUIT_MAX_ARRAY_LENGTH) {
        return SUIT_ERR_NO_MEMORY;
    }
    delegation->delegation_chain_num = item->val.uCount;

    for (size_t i = 0; i < delegation->delegation_chain_num; i++) {
        suit_delegation_chain_t *delegation_chain = &delegation->delegation_chains[i];
        result = suit_qcbor_get(context, item, true, QCBOR_TYPE_ARRAY);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        delegation_chain->len = item->val.uCount;
        for (size_t j = 0; j < delegation_chain->len; j++) {
            result = suit_qcbor_get(context, item, true, QCBOR_TYPE_BYTE_STRING);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            delegation_chain->chain[j] = item->val.string;
            UsefulBufC cwt_payload;
            size_t k = 0;
            for (; k < SUIT_MAX_KEY_NUM; k++) {
                /* NOTE: use might be false while decoding */
                if (mechanisms[k].key.public_key == NULL) {
                    continue;
                }
                cwt_payload = NULLUsefulBufC;
                result = suit_verify_cose_sign1(delegation_chain->chain[j], &mechanisms[k].key, &cwt_payload);
                if (result == SUIT_SUCCESS) {
                    break;
                }
            }
            if (k == SUIT_MAX_KEY_NUM) {
                return SUIT_ERR_FAILED_TO_VERIFY_DELEGATION;
            }
            // search empty slot
            for (k = 0; k < SUIT_MAX_KEY_NUM; k++) {
                /* NOTE: use might be false while decoding */
                if (mechanisms[k].key.public_key == NULL) {
                    break;
                }
            }
            if (k == SUIT_MAX_KEY_NUM) {
                return SUIT_ERR_NO_MEMORY;
            }
            result = suit_set_mechanism_from_cwt_payload(cwt_payload, &mechanisms[k]);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            mechanisms[k].cose_tag = CBOR_TAG_COSE_SIGN1;
            mechanisms[k].use = false; // to be true if used as verification key
        }
    }
    return result;
}

suit_err_t suit_decode_delegation(const suit_decode_mode_t mode,
                                  UsefulBufC buf,
                                  suit_delegation_t *delegation,
                                  suit_mechanism_t mechanisms[])
{
    QCBORDecodeContext delegation_context;
    QCBORItem item;
    QCBORDecode_Init(&delegation_context, buf, QCBOR_DECODE_MODE_NORMAL);
    suit_err_t result = suit_decode_delegation_from_item(mode, &delegation_context, &item, true, delegation, mechanisms);
    QCBORError error = QCBORDecode_Finish(&delegation_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}

suit_err_t suit_decode_envelope_from_item(const suit_decode_mode_t mode,
                                          QCBORDecodeContext *context,
                                          QCBORItem *item,
                                          bool next,
                                          suit_envelope_t *envelope,
                                          suit_mechanism_t mechanisms[])
{
    suit_err_t result = SUIT_SUCCESS;

    uint64_t puTags[1];
    QCBORTagListOut Out = {0, 1, puTags};
    QCBORDecode_GetNextWithTags(context, item, &Out);
    if (Out.uNumUsed > 0) {
        if (puTags[0] == SUIT_ENVELOPE_TAG) {
            envelope->tagged = true;
        }
        else {
            return SUIT_ERR_NOT_A_SUIT_MANIFEST;
        }
    }
    if (item->uDataType != QCBOR_TYPE_MAP) {
        return SUIT_ERR_INVALID_TYPE_OF_VALUE;
    }
    size_t map_count = item->val.uCount;
    bool is_authentication_set = (mode.SKIP_AUTHENTICATION_FAILURE) ? true : false;
    bool is_manifest_set = false;
    suit_buf_t buf;
    int64_t label = INT64_MIN;
    for (size_t i = 0; i < map_count; i++) {
        result = suit_qcbor_get_next(context, item, QCBOR_TYPE_ANY);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        if (item->uLabelType == QCBOR_TYPE_TEXT_STRING) {
            /* integrated payload */
            if (envelope->payloads.len >= SUIT_MAX_ARRAY_LENGTH) {
                return SUIT_ERR_NO_MEMORY;
            }
            label = INT64_MAX;
            suit_payload_t *payload = &envelope->payloads.payload[envelope->payloads.len];
            if (envelope->payloads.len > 0 && !mode.ALLOW_NOT_CANONICAL_CBOR) {
                size_t len = (payload->key.len < item->label.string.len) ? payload->key.len : item->label.string.len;
                if (memcmp(payload->key.ptr, item->label.string.ptr, len) >= 0 && len == item->label.string.len) {
                    return SUIT_ERR_NOT_CANONICAL_CBOR;
                }
            }
            payload->key = item->label.string;
            payload->bytes = item->val.string;
            envelope->payloads.len++;
        }
        else if (item->uLabelType == QCBOR_TYPE_UINT64) {
            /* XXX: may be used by custom */
            return SUIT_ERR_NOT_IMPLEMENTED;
        }
        else if (item->uLabelType == QCBOR_TYPE_INT64) {
            if (label > item->label.int64 && !mode.ALLOW_NOT_CANONICAL_CBOR) {
                return SUIT_ERR_NOT_CANONICAL_CBOR;
            }
            label = item->label.int64;
            switch (label) {
            case SUIT_DELEGATION:
                if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                    return SUIT_ERR_INVALID_TYPE_OF_VALUE;
                }
                result = suit_decode_delegation(mode, item->val.string, &envelope->delegation, mechanisms);
                break;

            case SUIT_AUTHENTICATION:
                if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                    return SUIT_ERR_INVALID_TYPE_OF_VALUE;
                }
                buf.ptr = (uint8_t *)item->val.string.ptr;
                buf.len = item->val.string.len;
                result = suit_decode_authentication_wrapper(mode, &buf, &envelope->wrapper, mechanisms);
                if (result == SUIT_SUCCESS) {
                    is_authentication_set = true;
                }
                break;

            case SUIT_MANIFEST:
                if (is_authentication_set || mode.SKIP_AUTHENTICATION_FAILURE) {
                    result = suit_decode_manifest_from_bstr(mode, context, item, false, &envelope->manifest, &envelope->wrapper.digest);
                    if (result != SUIT_SUCCESS) {
                        return result;
                    }
                    is_manifest_set = true;
                }
                else {
                     result = SUIT_ERR_AUTHENTICATION_NOT_FOUND;
                }
                break;

            /* SUIT_Severable_Manifest_members */
            case SUIT_SEVERED_PAYLOAD_FETCH:
                if ((is_authentication_set && is_manifest_set) || mode.SKIP_AUTHENTICATION_FAILURE) {
                    result = suit_verify_item(context, item, &envelope->manifest.sev_mem_dig.payload_fetch);
                    if (!suit_continue(mode, result)) {
                        return result;
                    }
                    envelope->manifest.sev_man_mem.payload_fetch_status |= SUIT_SEVERABLE_IS_VERIFIED;
                    result = suit_decode_command_sequence_from_bstr(mode, context, item, false, &envelope->manifest.sev_man_mem.payload_fetch);
                    if (result != SUIT_SUCCESS) {
                        return result;
                    }
                    envelope->manifest.sev_man_mem.payload_fetch_status |= SUIT_SEVERABLE_IN_ENVELOPE;
                }
                else {
                    if (is_manifest_set) {
                        result = SUIT_ERR_AUTHENTICATION_NOT_FOUND;
                    }
                    else {
                        result = SUIT_ERR_FAILED_TO_VERIFY;
                    }
                }
                break;
            case SUIT_SEVERED_INSTALL:
                if ((is_authentication_set && is_manifest_set) || mode.SKIP_AUTHENTICATION_FAILURE) {
                    result = suit_verify_item(context, item, &envelope->manifest.sev_mem_dig.install);
                    if (!suit_continue(mode, result)) {
                        return result;
                    }
                    envelope->manifest.sev_man_mem.install_status |= SUIT_SEVERABLE_IS_VERIFIED;
                    result = suit_decode_command_sequence_from_bstr(mode, context, item, false, &envelope->manifest.sev_man_mem.install);
                    if (result != SUIT_SUCCESS) {
                        return result;
                    }
                    envelope->manifest.sev_man_mem.install_status |= SUIT_SEVERABLE_IN_ENVELOPE;
                }
                else {
                    if (is_manifest_set) {
                        result = SUIT_ERR_AUTHENTICATION_NOT_FOUND;
                    }
                    else {
                        result = SUIT_ERR_FAILED_TO_VERIFY;
                    }
                }
                break;
            case SUIT_SEVERED_TEXT:
                if ((is_authentication_set && is_manifest_set) || mode.SKIP_AUTHENTICATION_FAILURE) {
                    result = suit_verify_item(context, item, &envelope->manifest.sev_mem_dig.text);
                    if (!suit_continue(mode, result)) {
                        return result;
                    }
                    envelope->manifest.sev_man_mem.text_status |= SUIT_SEVERABLE_IS_VERIFIED;
                    result = suit_decode_text_from_bstr(mode, context, item, false, &envelope->manifest.sev_man_mem.text);
                    if (result != SUIT_SUCCESS) {
                        return result;
                    }
                    envelope->manifest.sev_man_mem.text_status |= SUIT_SEVERABLE_IN_ENVELOPE;
                }
                else {
                    if (is_manifest_set) {
                        result = SUIT_ERR_AUTHENTICATION_NOT_FOUND;
                    }
                    else {
                        result = SUIT_ERR_FAILED_TO_VERIFY;
                    }
                }
                break;
            case SUIT_SEVERED_COSWID:
                if ((is_authentication_set && is_manifest_set) || mode.SKIP_AUTHENTICATION_FAILURE) {
                    result = suit_verify_item(context, item, &envelope->manifest.sev_mem_dig.coswid);
                    envelope->manifest.sev_man_mem.coswid_status |= SUIT_SEVERABLE_IS_VERIFIED;
                    if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                        return SUIT_ERR_INVALID_TYPE_OF_VALUE;
                    }
                    envelope->manifest.sev_man_mem.coswid.ptr = (uint8_t *)item->val.string.ptr;
                    envelope->manifest.sev_man_mem.coswid.len = item->val.string.len;
                    envelope->manifest.sev_man_mem.coswid_status |= SUIT_SEVERABLE_IN_ENVELOPE;
                }
                else {
                    if (is_manifest_set) {
                        result = SUIT_ERR_AUTHENTICATION_NOT_FOUND;
                    }
                    else {
                        result = SUIT_ERR_FAILED_TO_VERIFY;
                    }
                }
                break;
            case SUIT_SEVERED_DEPENDENCY_RESOLUTION:
                if ((is_authentication_set && is_manifest_set) || mode.SKIP_AUTHENTICATION_FAILURE) {
                    result = suit_verify_item(context, item, &envelope->manifest.sev_mem_dig.dependency_resolution);
                    if (!suit_continue(mode, result)) {
                        break;
                    }
                    result = suit_decode_command_sequence_from_bstr(mode, context, item, false, &envelope->manifest.sev_man_mem.dependency_resolution);
                    if (result != SUIT_SUCCESS) {
                        return result;
                    }
                    envelope->manifest.sev_man_mem.dependency_resolution_status |= SUIT_SEVERABLE_IN_ENVELOPE;
                }
                else {
                    if (is_manifest_set) {
                        result = SUIT_ERR_AUTHENTICATION_NOT_FOUND;
                    }
                    else {
                        result = SUIT_ERR_FAILED_TO_VERIFY;
                    }
                }
                break;

            // TODO
            default:
                return SUIT_ERR_NOT_IMPLEMENTED;
            }
            if (!suit_continue(mode, result)) {
                return result;
            }
            if (result != SUIT_SUCCESS && !suit_qcbor_skip_any(context, item)) {
                return SUIT_ERR_NO_MORE_ITEMS;
            }
            result = SUIT_SUCCESS;
        }
    }
    return result;
}

/*
    Public function. See suit_manifest_decode.h
 */
suit_err_t suit_decode_envelope(const suit_decode_mode_t mode,
                                suit_buf_t *buf,
                                suit_envelope_t *envelope,
                                suit_mechanism_t mechanisms[])
{
    QCBORDecodeContext decode_context;
    QCBORItem item;
    QCBORDecode_Init(&decode_context,
                     (UsefulBufC){buf->ptr, buf->len},
                     QCBOR_DECODE_MODE_NORMAL);
    suit_err_t result = suit_decode_envelope_from_item(mode, &decode_context, &item, true, envelope, mechanisms);
    QCBORError error = QCBORDecode_Finish(&decode_context);
    if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
        result = suit_error_from_qcbor_error(error);
    }
    return result;
}
