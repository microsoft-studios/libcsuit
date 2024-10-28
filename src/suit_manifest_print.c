/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*!
    \file   suit_manifest_print.c

    \brief  This implements libcsuit printing

    Call these functions if you want to print the decoded structures and definitions.
 */

#include "csuit/suit_manifest_print.h"

char* suit_err_to_str(suit_err_t error)
{
    switch (error) {
    case SUIT_SUCCESS:
        return "SUIT_SUCCESS";
    case SUIT_ERR_FATAL:
        return "SUIT_ERR_FATAL";
    case SUIT_ERR_NOT_A_SUIT_MANIFEST:
        return "SUIT_ERR_NOT_A_SUIT_MANIFEST";

    case SUIT_ERR_NO_MEMORY:
        return "SUIT_ERR_NO_MEMORY";
    case SUIT_ERR_NOT_FOUND:
        return "SUIT_ERR_NOT_FOUND";
    case SUIT_ERR_PARAMETER_NOT_FOUND:
        return "SUIT_ERR_PARAMETER_NOT_FOUND";
    case SUIT_ERR_AUTHENTICATION_NOT_FOUND:
        return "SUIT_ERR_AUTHENTICATION_NOT_FOUND";
    case SUIT_ERR_MANIFEST_KEY_NOT_FOUND:
        return "SUIT_ERR_MANIFEST_KEY_NOT_FOUND";

    case SUIT_ERR_INVALID_TYPE_OF_VALUE:
        return "SUIT_INVALID_TYPE_OF_VALUE";
    case SUIT_ERR_INVALID_VALUE:
        return "SUIT_ERR_INVALID_VALUE";
    case SUIT_ERR_INVALID_TYPE_OF_KEY:
        return "SUIT_ERR_INVALID_TYPE_OF_KEY";
    case SUIT_ERR_INVALID_KEY:
        return "SUIT_ERR_INVALID_KEY";
    case SUIT_ERR_NO_MORE_ITEMS:
        return "SUIT_ERR_NO_MORE_ITEMS";
    case SUIT_ERR_NOT_IMPLEMENTED:
        return "SUIT_ERR_NOT_IMPLEMENTED";
    case SUIT_ERR_FAILED_TO_VERIFY:
        return "SUIT_ERR_FAILED_TO_VERIFY";
    case SUIT_ERR_FAILED_TO_SIGN:
        return "SUIT_ERR_FAILED_TO_SIGN";
    case SUIT_ERR_FAILED_TO_DECRYPT:
        return "SUIT_ERR_FAILED_TO_DECRYPT";
    case SUIT_ERR_FAILED_TO_ENCRYPT:
        return "SUIT_ERR_FAILED_TO_ENCRYPT";
    case SUIT_ERR_FAILED_TO_VERIFY_DELEGATION:
        return "SUIT_ERR_FAILED_TO_VERIFY_DELEGATION";
    case SUIT_ERR_CONDITION_MISMATCH:
        return "SUIT_ERR_CONDITION_MISMATCH";

    case SUIT_ERR_REDUNDANT:
        return "SUIT_ERR_REDUNDANT";
    case SUIT_ERR_NOT_CANONICAL_CBOR:
        return "SUIT_ERR_NOT_CANONICAL_CBOR";
    case SUIT_ERR_INVALID_MANIFEST_VERSION:
        return "SUIT_ERR_INVALID_MANIFEST_VERSION";
    case SUIT_ERR_TRY_OUT:
        return "SUIT_ERR_TRY_OUT";
    case SUIT_ERR_ABORT:
        return "SUIT_ERR_ABORT";
    }
    return NULL;
}

char* suit_cbor_tag_to_str(cbor_tag_key_t tag)
{
    switch (tag) {
    case COSE_SIGN_TAG:
        return "COSE_Sign_Tag";
    case COSE_SIGN1_TAG:
        return "COSE_Sign1_Tag";
    case COSE_ENCRYPT_TAG:
        return "COSE_Encrypt_Tag";
    case COSE_ENCRYPT0_TAG:
        return "COSE_Encrypt0_Tag";
    case COSE_MAC_TAG:
        return "COSE_Mac_Tag";
    case COSE_MAC0_TAG:
        return "COSE_Mac0_Tag";
    case COSE_KEY_TAG:
        return "COSE_Key_Tag";
    case COSE_KEY_SET_TAG:
        return "COSE_Key_Set_Tag";
    case SUIT_ENVELOPE_TAG:
        return "SUIT_Envelope_Tag";
    default:
        return "UNKNOWN_Tag";
    }
}


char* suit_envelope_key_to_str(suit_envelope_key_t envelope_key)
{
    switch (envelope_key) {
    case SUIT_DELEGATION:
        return "delegation";
    case SUIT_AUTHENTICATION:
        return "authentication";
    case SUIT_MANIFEST:
        return "manifest";
    case SUIT_ENVELOPE_KEY_INVALID:
    case SUIT_SEVERED_DEPENDENCY_RESOLUTION:
    case SUIT_SEVERED_PAYLOAD_FETCH:
    case SUIT_SEVERED_INSTALL:
    case SUIT_SEVERED_TEXT:
    case SUIT_SEVERED_COSWID:
    case SUIT_INTEGRATED_PAYLOAD:
        break;
    }
    return NULL;
}

char* suit_manifest_key_to_str(suit_manifest_key_t manifest_key)
{
    switch (manifest_key) {
    case SUIT_MANIFEST_VERSION:
        return "manifest-version";
    case SUIT_MANIFEST_SEQUENCE_NUMBER:
        return "manifest-sequence-number";
    case SUIT_COMMON:
        return "common";
    case SUIT_REFERENCE_URI:
        return "reference-uri";
    case SUIT_MANIFEST_COMPONENT_ID:
        return "manifest-component-id";
    case SUIT_VALIDATE:
        return "validate";
    case SUIT_LOAD:
        return "load";
    case SUIT_INVOKE:
        return "invoke";
    case SUIT_COSWID:
        return "coswid";
    case SUIT_DEPENDENCY_RESOLUTION:
        return "dependency-resolution";
    case SUIT_PAYLOAD_FETCH:
        return "payload-fetch";
    case SUIT_INSTALL:
        return "install";
    case SUIT_TEXT:
        return "text";
    case SUIT_UNINSTALL:
        return "uninstall";
    case SUIT_COMMON_KEY_INVALID:
        break;
    }
    return NULL;
}

char* suit_common_key_to_str(suit_common_key_t common_key)
{
    switch (common_key) {
    case SUIT_DEPENDENCIES:
        return "dependencies";
    case SUIT_COMPONENTS:
        return "components";
    case SUIT_SHARED_SEQUENCE:
        return "shared-sequence";
    case SUIT_COMMON_KEY_INVALID:
        break;
    }
    return NULL;
}

char* suit_command_sequence_key_to_str(suit_con_dir_key_t condition_directive)
{
    switch (condition_directive) {
    case SUIT_CONDITION_VENDOR_IDENTIFIER:
        return "condition-vendor-identifier";
    case SUIT_CONDITION_CLASS_IDENTIFIER:
        return "condition-class-identifier";
    case SUIT_CONDITION_IMAGE_MATCH:
        return "condition-image-match";
    case SUIT_CONDITION_COMPONENT_SLOT:
        return "condition-component-slot";
    case SUIT_CONDITION_CHECK_CONTENT:
        return "condition-check-content";
    case SUIT_CONDITION_ABORT:
        return "condition-abort";
    case SUIT_CONDITION_DEVICE_IDENTIFIER:
        return "condition-device-identifier";

    case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
        return "directive-set-component-index";
    case SUIT_DIRECTIVE_TRY_EACH:
        return "directive-try-each";
    case SUIT_DIRECTIVE_WRITE:
        return "directive-write";
    case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
        return "directive-override-parameters";
    case SUIT_DIRECTIVE_FETCH:
        return "directive-fetch";
    case SUIT_DIRECTIVE_COPY:
        return "directive-copy";
    case SUIT_DIRECTIVE_INVOKE:
        return "directive-invoke";
    case SUIT_DIRECTIVE_SWAP:
        return "directive-swap";
    case SUIT_DIRECTIVE_RUN_SEQUENCE:
        return "directive-run-sequence";

    /* draft-ietf-suit-trust-domains */
    case SUIT_CONDITION_DEPENDENCY_INTEGRITY:
        return "condition-dependency-integrity";
    case SUIT_CONDITION_IS_DEPENDENCY:
        return "condition-is-dependency";

    case SUIT_DIRECTIVE_PROCESS_DEPENDENCY:
        return "directive-process-dependency";
    case SUIT_DIRECTIVE_SET_PARAMETERS:
        return "directive-set-parameters";
    case SUIT_DIRECTIVE_UNLINK:
        return "directive-unlink";

    /* draft-ietf-suit-update-management */
    case SUIT_CONDITION_IMAGE_NOT_MATCH:
        return "condition-image-not-match";
    case SUIT_CONDITION_MINIMUM_BATTERY:
        return "condition-minimum-battery";
    case SUIT_CONDITION_UPDATE_AUTHORIZED:
        return "condition-update-authorized";
    case SUIT_CONDITION_VERSION:
        return "condition-version";
    case SUIT_CONDITION_USE_BEFORE:
        return "condition-use-before";

    case SUIT_DIRECTIVE_WAIT:
        return "directive-wait";
    case SUIT_DIRECTIVE_OVERRIDE_MULTIPLE:
        return "directive-override-multiple";
    case SUIT_DIRECTIVE_COPY_PARAMS:
        return "directive-copy-params";

    case SUIT_CONDITION_INVALID:
    //case SUIT_DIRECTIVE_INVALID:
        break;
    }
    return NULL;
}

char* suit_parameter_key_to_str(suit_parameter_key_t parameter)
{
    switch (parameter) {
    case SUIT_PARAMETER_VENDOR_IDENTIFIER:
        return "vendor-id";
    case SUIT_PARAMETER_CLASS_IDENTIFIER:
        return "class-id";
    case SUIT_PARAMETER_IMAGE_DIGEST:
        return "image-digest";
    case SUIT_PARAMETER_USE_BEFORE:
        return "use-before";
    case SUIT_PARAMETER_COMPONENT_SLOT:
        return "component-slot";
    case SUIT_PARAMETER_STRICT_ORDER:
        return "strict-order";
    case SUIT_PARAMETER_SOFT_FAILURE:
        return "soft-failure";
    case SUIT_PARAMETER_IMAGE_SIZE:
        return "image-size";
    case SUIT_PARAMETER_CONTENT:
        return "content";
    case SUIT_PARAMETER_ENCRYPTION_INFO:
        return "encryption-info";
    case SUIT_PARAMETER_URI:
        return "uri";
    case SUIT_PARAMETER_SOURCE_COMPONENT:
        return "source-component";
    case SUIT_PARAMETER_INVOKE_ARGS:
        return "invoke-args";
    case SUIT_PARAMETER_DEVICE_IDENTIFIER:
        return "device-identifier";
    case SUIT_PARAMETER_MINIMUM_BATTERY:
        return "minimum-battery";
    case SUIT_PARAMETER_UPDATE_PRIORITY:
        return "update-priority";
    case SUIT_PARAMETER_VERSION:
        return "version";
    case SUIT_PARAMETER_WAIT_INFO:
        return "wait-info";
    case SUIT_PARAMETER_FETCH_ARGS:
        return "fetch-args";
    case SUIT_PARAMETER_INVALID:
        break;
    }
    return NULL;
}

char* suit_version_comparison_type_to_str(suit_condition_version_comparison_types_t type)
{
    switch (type) {
    case SUIT_CONDITION_VERSION_COMPARISON_GREATER:
        return "greater";
    case SUIT_CONDITION_VERSION_COMPARISON_GREATER_EQUAL:
        return "greater-equal";
    case SUIT_CONDITION_VERSION_COMPARISON_EQUAL:
        return "equal";
    case SUIT_CONDITION_VERSION_COMPARISON_LESSER_EQUAL:
        return "lesser-equal";
    case SUIT_CONDITION_VERSION_COMPARISON_LESSER:
        return "lesser";
    case SUIT_CONDITION_VERSION_COMPARISON_INVALID:
        break;
    }
    return NULL;
}

char* suit_wait_event_key_to_str(suit_wait_event_key_t key)
{
    switch (key) {
    case SUIT_WAIT_EVENT_AUTHORIZATION:
        return "authorization";
    case SUIT_WAIT_EVENT_POWER:
        return "power";
    case SUIT_WAIT_EVENT_NETWORK:
        return "network";
    case SUIT_WAIT_EVENT_OTHER_DEVICE_VERSION:
        return "other-device-version";
    case SUIT_WAIT_EVENT_TIME:
        return "time";
    case SUIT_WAIT_EVENT_TIME_OF_DAY:
        return "time-of-day";
    case SUIT_WAIT_EVENT_DAY_OF_WEEK:
        return "day-of-week";
    case SUIT_WAIT_EVENT_INVALID:
        break;
    }
    return NULL;
}

char* suit_cose_protected_key_to_str(int64_t key)
{
    switch (key) {
    case -1:
        return "ephemeral key";
    case 1:
        return "alg";
    case 2:
        return "crit";
    case 3:
        return "content type";
    case 4:
        return "kid";
    case 5:
        return "IV";
    case 6:
        return "Partial IV";
    case 7:
        return "counter signature";
    }
    return NULL;
}

/*
 *  see https://datatracker.ietf.org/doc/draft-moran-suit-mti/
 */
char* suit_cose_alg_to_str(int64_t id)
{
    switch (id) {
    case -16:
        return "SHA-256";
    case -18:
        return "SHAKE128";
    case -43:
        return "SHA-384";
    case -44:
        return "SHA-512";
    case -45:
        return "SHAKE256";

    case 5:
        return "HMAC-256";
    case 6:
        return "HMAC-384";
    case 7:
        return "HMAC-512";

    case -7:
        return "ES256";
    case -8:
        return "EdDSA";
    case -35:
        return "ES384";
    case -36:
        return "ES512";

    case -46:
        return "HSS-LMS";
/*
    case :
        return "XMSS";
    case :
        return "Falcon-512";
    case :
        return "SPHINCS+";
    case :
        return "Crystals-Dilithium";
        */

    case -3:
        return "A128KW";
    case -4:
        return "A192KW";
    case -5:
        return "A256KW";

/*
    case :
        return "HPKE";
        */
    case -25:
        return "ECDH-ES + HKDF-256";
    case -26:
        return "ECDH-ES + HKDF-512";
    case -29:
        return "ECDH-ES + A128KW";
    case -30:
        return "ECDH-ES + A192KW";
    case -31:
        return "ECDH-ES + A256KW";

/*
    case :
        return "CRYSTALS-KYBER";
        */

    case 1:
        return "A128GCM";
    case 2:
        return "A192GCM";
    case 3:
        return "A256GCM";
    case 24:
        return "ChaCha20/Poly1305";
    case 25:
        return "AES-MAC 128/128";
    case 26:
        return "AES-MAC 256/128";
    case 30:
        return "AES-CCM-16-128-128";
    case 31:
        return "AES-CCM-16-128-256";
    case 32:
        return "AES-CCM-64-128-128";
    case 33:
        return "AES-CCM-64-128-256";
    }
    return NULL;
}

char* suit_cose_kty_to_str(int64_t kty)
{
    switch (kty) {
    case 1:
        return "OKP";
    case 2:
        return "EC2";
    case 3:
        return "RSA";
    case 4:
        return "Symmetric";
    case 5:
        return "HSS-LMS";
    case 6:
        return "WalnutDSA";
    }
    return NULL;
}

char* suit_cose_crv_to_str(int64_t crv)
{
    switch (crv) {
    case 1:
        return "P-256";
    case 2:
        return "P-384";
    case 3:
        return "P-521";
    case 4:
        return "X25519";
    case 5:
        return "X448";
    case 6:
        return "Ed25519";
    case 7:
        return "Ed448";
    case 8:
        return "secp256k1";
    }
    return NULL;
}
void suit_print_cose_key(QCBORDecodeContext *context,
                         QCBORItem *item,
                         const uint8_t indent_space,
                         const uint8_t indent_delta)
{
    printf("{\n");
    const size_t map_count = item->val.uCount;
    for (size_t i = 0; i < map_count; i++) {
        QCBORDecode_GetNext(context, item);
        printf("%*s", indent_space + indent_delta, "");
        switch (item->label.int64) {
        case 1: /* kty */
            printf("/ kty / 1: %ld / %s /", item->val.int64, suit_cose_kty_to_str(item->val.int64));
            break;
        case -1: /* crv */
            printf("/ crv / -1: %ld / %s /", item->val.int64, suit_cose_crv_to_str(item->val.int64));
            break;
        case -2: /* x */
            printf("/ x / -2: / ");
            suit_print_hex(item->val.string.ptr, item->val.string.len);
            break;
        case -3: /* y */
            printf("/ y / -3: / ");
            suit_print_hex(item->val.string.ptr, item->val.string.len);
            break;
        }
        if (i + 1 != item->val.uCount) {
            printf(",");
        }
        printf("\n");
    }

    printf("%*s}", indent_space, "");
}

void suit_print_cose_header_value(QCBORDecodeContext *context,
                                  QCBORItem *item,
                                  const uint8_t indent_space,
                                  const uint8_t indent_delta)
{
    switch (item->label.int64) {
    case -1: /* ephemeral key */
        suit_print_cose_key(context, item, indent_space, indent_delta);
        break;
    case 1: /* alg */
        printf("%ld / %s /", item->val.int64, suit_cose_alg_to_str(item->val.int64));
        break;
    case 4: /* kid */
    case 5: /* IV */
        suit_print_hex(item->val.string.ptr, item->val.string.len);
        break;
    default:
        printf("(UNKNOWN)");
        break;
    }
}

bool is_available_char_for_filename(const char c)
{
    return (('a' <= c && c <= 'z') ||
            ('A' <= c && c <= 'Z') ||
            ('0' <= c && c <= '9') ||
            ('_' == c) ||
            ('.' == c) ||
            ('-' == c));
}

suit_err_t suit_component_identifier_to_filename(const suit_component_identifier_t *comp_id,
                                                 const size_t max_filename_len,
                                                 char filename[])
{
    size_t pos = 0;

    pos += sprintf(&filename[pos], "./tmp");
    for (size_t i = 0; i < comp_id->len; i++) {
        if (pos + 1 + 1 > max_filename_len) {
            return SUIT_ERR_NO_MEMORY;
        }
        pos += sprintf(&filename[pos], "/");

        bool available = true;
        for (size_t j = 0; j < comp_id->identifier[i].len; j++) {
            if (!is_available_char_for_filename(comp_id->identifier[i].ptr[j])) {
                available = false;
            }
        }
        if (available) {
            if (pos + comp_id->identifier[i].len + 1 > max_filename_len) {
                return SUIT_ERR_NO_MEMORY;
            }
            memcpy(&filename[pos], comp_id->identifier[i].ptr, comp_id->identifier[i].len);
            pos += comp_id->identifier[i].len;
        }
        else {
            if (pos + 2 * comp_id->identifier[i].len + 1 > max_filename_len) {
                return SUIT_ERR_NO_MEMORY;
            }
            for (size_t j = 0; j < comp_id->identifier[i].len; j++) {
                pos += sprintf(&filename[pos], "%02x", comp_id->identifier[i].ptr[j]);
            }
        }
    }
    filename[pos] = '\0';

    return SUIT_SUCCESS;
}

suit_err_t suit_print_hex_string(const uint8_t *array,
                                 const size_t size)
{
    if (array == NULL) {
        return SUIT_ERR_FATAL;
    }
    printf("h'");
    for (size_t i = 0; i < size; i++) {
        printf("%02x", (unsigned char)array[i]);
    }
    printf("'");
    return SUIT_SUCCESS;
}

bool suit_is_printable_char(const uint8_t c)
{
    return (' ' <= c && c <= '~');
}

bool suit_printable_hex_string(const char *array,
                               const size_t size)
{
    size_t i;
    for (i = 0; i < size; i++) {
        if (!suit_is_printable_char(array[i])) {
            return false;
        }
    }
    return true;
}

suit_err_t suit_print_tstr_body(const char *text,
                                const size_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (text[i] == '\n') {
            putchar('\\'); putchar('n');
        }
        else {
            putchar(text[i]);
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_tstr(const char *text,
                           const size_t size)
{
    if (text == NULL) {
        return SUIT_ERR_FATAL;
    }

    printf("\"");
    suit_print_tstr_body(text, size);
    printf("\"");
    return SUIT_SUCCESS;
}

suit_err_t suit_print_tstr_in_max(const char *text,
                                  const size_t size,
                                  const size_t size_max)
{
    suit_err_t result = SUIT_SUCCESS;
    if (size <= size_max) {
        result = suit_print_tstr(text, size);
    }
    else {
        result = suit_print_tstr(text, size_max);
        printf("..");
    }
    return result;
}

suit_err_t suit_print_string(const suit_buf_t *string)
{
    return suit_print_tstr_in_max((const char *)string->ptr, string->len, SUIT_MAX_PRINT_TEXT_COUNT);
}

suit_err_t suit_print_hex(const uint8_t *array, const size_t size)
{
    if (size == 0) {
        printf("h''");
        return SUIT_SUCCESS;
    }
    if (array == NULL) {
        return SUIT_ERR_FATAL;
    }
    if (suit_printable_hex_string((const char *)array, size)) {
        printf("'");
        suit_print_tstr_body((const char *)array, size);
        printf("'");
    }
    else {
        printf("h'");
        for (size_t i = 0; i < size; i++) {
            printf("%02X", (unsigned char)array[i]);
        }
        printf("'");
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_hex_in_max(const uint8_t *array,
                                 const size_t size,
                                 const size_t size_max)
{
    suit_err_t result = SUIT_SUCCESS;
    if (size <= size_max) {
        result = suit_print_hex(array, size);
    }
    else {
        result = suit_print_hex(array, size_max);
        printf("..");
    }
    return result;
}

suit_err_t suit_print_uuid(const suit_buf_t *buf)
{
    if (buf == NULL || buf->len != 16) {
        return SUIT_ERR_INVALID_TYPE_OF_VALUE;
    }
    uint8_t digits[] = {4, 2, 2, 2, 6};
    uint8_t pos = 0;
    for (uint8_t i = 0; i < 5; i++) {
        for (uint8_t j = 0; j < digits[i]; j++) {
            printf("%02x", (unsigned char)buf->ptr[pos]);
            pos++;
        }
        if (i != 4) {
            printf("-");
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_cose_header(QCBORDecodeContext *context,
                                  const uint8_t indent_space,
                                  const uint8_t indent_delta)
{
    suit_err_t result = SUIT_SUCCESS;
    QCBORItem item;
    QCBORDecode_EnterMap(context, &item);
    printf("{");
    size_t len = item.val.uCount;
    for (size_t i = 0; i < len; i++) {
        result = suit_qcbor_get_next(context, &item, QCBOR_TYPE_ANY);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n%*s/ %s / %ld: ", indent_space + indent_delta, "", suit_cose_protected_key_to_str(item.label.int64), item.label.int64);
        suit_print_cose_header_value(context, &item, indent_space + indent_delta, indent_delta);
        if (i + 1 != len) {
            printf(",");
        }
    }
    printf("\n%*s}", indent_space, "");
    QCBORDecode_ExitMap(context);
    return result;
}

suit_err_t suit_print_encryption_info(const suit_buf_t *encryption_info,
                                      const uint32_t indent_space,
                                      const uint32_t indent_delta)
{
    if (encryption_info == NULL) {
        return SUIT_ERR_FATAL;
    }
    printf("<< ");
    suit_err_t result = SUIT_SUCCESS;
    if (encryption_info->ptr != NULL && encryption_info->len > 0) {
        QCBORDecodeContext context;
        QCBORItem item;
        QCBORDecode_Init(&context, (UsefulBufC){encryption_info->ptr, encryption_info->len}, QCBOR_DECODE_MODE_NORMAL);

        uint64_t puTags[3];
        QCBORTagListOut Out = {0, 3, puTags};
        QCBORDecode_GetNextWithTags(&context, &item, &Out);
        if (item.uDataType != QCBOR_TYPE_ARRAY) {
            return SUIT_ERR_INVALID_TYPE_OF_VALUE;
        }
        for (size_t i = 0; i < Out.uNumUsed; i++) {
            printf("%ld(", puTags[i]);
        }
        printf("[\n");
        size_t cose_struct_len = item.val.uCount;

        QCBORDecode_PeekNext(&context, &item);
        printf("%*s/ protected: / ", indent_space + indent_delta, "");
        if (item.val.string.len > 0) {
            printf("<< ");
            QCBORDecode_EnterBstrWrapped(&context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
            suit_print_cose_header(&context, indent_space + indent_delta, indent_delta);
            QCBORDecode_ExitBstrWrapped(&context);
            printf(" >>,\n");
        }
        else {
            QCBORDecode_GetNext(&context, &item);
            printf("h'',\n");
        }

        printf("%*s/ unprotected: / ", indent_space + indent_delta, "");
        suit_print_cose_header(&context, indent_space + indent_delta, indent_delta);

        result = suit_qcbor_get_next(&context, &item, QCBOR_TYPE_ANY);
        if (result != SUIT_SUCCESS) {
            printf("val = %u\n", item.uDataType);
            return result;
        }
        printf(",\n%*s/ payload: / ", indent_space + indent_delta, "");
        if (item.uDataType == QCBOR_TYPE_NULL) {
            printf("null");
        }
        else if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            suit_print_hex(item.val.string.ptr, item.val.string.len);
        }
        else {
            return SUIT_ERR_INVALID_TYPE_OF_VALUE;
        }

        if (cose_struct_len > 3) {
            result = suit_qcbor_get_next(&context, &item, QCBOR_TYPE_ARRAY);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            printf(",\n%*s/ recipients: / [\n", indent_space + indent_delta, "");
            size_t num_recipients = item.val.uCount;
            for (size_t i = 0; i < num_recipients; i++) {
                result = suit_qcbor_get_next(&context, &item, QCBOR_TYPE_ARRAY);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                size_t len = item.val.uCount;
                if (len < 3) {
                    return SUIT_ERR_FATAL;
                }
                printf("%*s[\n", indent_space + 2 * indent_delta, "");
                printf("%*s/ protected: / ", indent_space + 3 * indent_delta, "");
                if (item.val.string.len > 0) {
                    printf("<< ");
                    QCBORDecode_EnterBstrWrapped(&context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
                    suit_print_cose_header(&context, indent_space + 3 * indent_delta, indent_delta);
                    QCBORDecode_ExitBstrWrapped(&context);
                    printf(" >>,\n");
                }
                else {
                    QCBORDecode_GetNext(&context, &item);
                    printf("h'',\n");
                }
                printf("%*s/ unprotected: / ", indent_space + 3 * indent_delta, "");
                suit_print_cose_header(&context, indent_space + 3 * indent_delta, indent_delta);
                printf(",\n");

                result = suit_qcbor_get_next(&context, &item, QCBOR_TYPE_ANY);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                printf("%*s/ CEK: / ", indent_space + 3 * indent_delta, "");
                if (item.uDataType == QCBOR_TYPE_NULL) {
                    printf("null\n");
                }
                else if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                    suit_print_hex(item.val.string.ptr, item.val.string.len);
                    printf("\n");
                }
                else {
                    return SUIT_ERR_INVALID_TYPE_OF_VALUE;
                }
                printf("%*s]", indent_space + 2 * indent_delta, "");
                if (i + 1 < num_recipients) {
                    printf(",");
                }
                printf("\n");
            }
        }
        printf("%*s]", indent_space + indent_delta, "");
        QCBORError error = QCBORDecode_Finish(&context);
        if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
            result = suit_error_from_qcbor_error(error);
        }
        printf("\n%*s]", indent_space, "");
        for (size_t i = 0; i < Out.uNumUsed; i++) {
            printf(")");
        }
    }
    printf(">>");
    return result;
}

suit_err_t suit_print_version(const suit_version_match_t *version_match,
                              const uint32_t indent_space,
                              const uint32_t indent_delta)
{
    printf("[\n");
    printf("%*s/ comparison-type / %d / %s /,\n", indent_space + indent_delta, "", version_match->type, suit_version_comparison_type_to_str(version_match->type));
    printf("%*s/ comparison-value / [", indent_space + indent_delta, "");
    for (size_t j = 0; j < version_match->value.len; j++) {
        printf(" %ld", version_match->value.int64[j]);
        if (j + 1 != version_match->value.len) {
            printf(",");
        }
    }
    printf(" ]\n%*s]", indent_space, "");

    return SUIT_SUCCESS;
}

suit_err_t suit_print_wait_event(const suit_wait_event_t *wait_event,
                                 const uint32_t indent_space,
                                 const uint32_t indent_delta)
{
    bool comma = false;
    printf("{\n");

    if (wait_event->exists & SUIT_WAIT_EVENT_CONTAINS_AUTHORIZATION) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ authorization / 1: %ld", indent_space + indent_delta, "", wait_event->authorization);
        comma = true;
    }
    if (wait_event->exists & SUIT_WAIT_EVENT_CONTAINS_POWER) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ power / 2: %ld", indent_space + indent_delta, "", wait_event->power);
        comma = true;
    }
    if (wait_event->exists & SUIT_WAIT_EVENT_CONTAINS_NETWORK) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ network / 3: %ld", indent_space + indent_delta, "", wait_event->network);
        comma = true;
    }
    if (wait_event->exists & SUIT_WAIT_EVENT_CONTAINS_OTHER_DEVICE_VERSION) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ other-device-version / 4: [", indent_space + indent_delta, "");
        printf("%*s/ other-device: / ", indent_space + 2 * indent_delta, "");
        suit_print_hex(wait_event->other_device_version.other_device.ptr, wait_event->other_device_version.other_device.len);
        printf(",\n%*s/ version: / [\n", indent_space + 2 * indent_delta, "");
        for (size_t i = 0; i < wait_event->other_device_version.len; i++) {
            printf("%*s", indent_space + 3 * indent_delta, "");
            suit_print_version(&wait_event->other_device_version.versions[i], indent_space + 4 * indent_delta, indent_delta);
            if (i + 1 != wait_event->other_device_version.len) {
                printf(",");
            }
            printf("\n");
        }
        printf("%*s]\n", indent_space + 2 * indent_delta, "");
        printf("%*s]", indent_space + indent_delta, "");
        comma = true;
    }
    if (wait_event->exists & SUIT_WAIT_EVENT_CONTAINS_TIME) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ time / 5: %lu", indent_space + indent_delta, "", wait_event->time);
        comma = true;
    }
    if (wait_event->exists & SUIT_WAIT_EVENT_CONTAINS_TIME_OF_DAY) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ time-of-day / 6: %lu", indent_space + indent_delta, "", wait_event->time_of_day);
        comma = true;
    }
    if (wait_event->exists & SUIT_WAIT_EVENT_CONTAINS_DAY_OF_WEEK) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ day-of-week / 7: %lu", indent_space + indent_delta, "", wait_event->day_of_week);
        comma = true;
    }
    printf("\n%*s} ", indent_space, "");

    return SUIT_SUCCESS;
}

suit_err_t suit_print_wait_event_buf(const suit_buf_t *wait_event_buf,
                                     const uint32_t indent_space,
                                     const uint32_t indent_delta)
{
    if (wait_event_buf == NULL) {
        return SUIT_ERR_FATAL;
    }
    printf("<< ");
    suit_err_t result = SUIT_SUCCESS;
    if (wait_event_buf->ptr != NULL && wait_event_buf->len > 0) {
        suit_wait_event_t wait_event;
        result = suit_decode_wait_event(wait_event_buf, &wait_event);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        result = suit_print_wait_event(&wait_event, indent_space, indent_delta);
    }
    printf(">>");
    return result;
}

char* suit_authentication_value_to_str(cbor_tag_key_t tag)
{
    switch (tag) {
    case COSE_SIGN_TAG:
        return "signatures";
    case COSE_SIGN1_TAG:
        return "signatre";
    case COSE_MAC_TAG:
    case COSE_MAC0_TAG:
        return "tag";
    default:
        return NULL;
    }
}

suit_err_t suit_print_signature(const suit_buf_t *signature,
                                const uint32_t indent_space,
                                const uint32_t indent_delta)
{
    if (signature == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    if (signature->ptr != NULL && signature->len > 0) {
        char *signature_or_tag = NULL;
        QCBORDecodeContext context;
        QCBORItem item;
        QCBORDecode_Init(&context, (UsefulBufC){signature->ptr, signature->len}, QCBOR_DECODE_MODE_NORMAL);

        uint64_t puTags[1];
        QCBORTagListOut Out = {0, 1, puTags};
        QCBORDecode_GetNextWithTags(&context, &item, &Out);
        if (item.uDataType != QCBOR_TYPE_ARRAY) {
            return SUIT_ERR_INVALID_TYPE_OF_VALUE;
        }
        if (Out.uNumUsed > 0) {
            printf("/ %sged = / %ld(", suit_cbor_tag_to_str(puTags[0]), puTags[0]);
            signature_or_tag = suit_authentication_value_to_str(puTags[0]);
        }
        printf("[\n");

        printf("%*s/ protected: / << ", indent_space + indent_delta, "");
        QCBORDecode_EnterBstrWrapped(&context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
        suit_print_cose_header(&context, indent_space + indent_delta, indent_delta);
        QCBORDecode_ExitBstrWrapped(&context);
        printf(" >>,\n");

        printf("%*s/ unprotected: / ", indent_space + indent_delta, "");
        suit_print_cose_header(&context, indent_space + indent_delta, indent_delta);
        printf(",\n");

        result = suit_qcbor_get_next(&context, &item, QCBOR_TYPE_ANY);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s/ payload: / ", indent_space + indent_delta, "");
        if (item.uDataType == QCBOR_TYPE_NULL) {
            printf("null,\n");
        }
        else if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            suit_print_hex(item.val.string.ptr, item.val.string.len);
            printf("\n");
        }
        else {
            return SUIT_ERR_INVALID_TYPE_OF_VALUE;
        }

        result = suit_qcbor_get_next(&context, &item, QCBOR_TYPE_BYTE_STRING);
        if (result != SUIT_SUCCESS) {
            return result;
        }

        printf("%*s", indent_space + indent_delta, "");
        if (signature_or_tag != NULL) {
            printf("/ %s: / ", signature_or_tag);
        }
        suit_print_hex(item.val.string.ptr, item.val.string.len);

        QCBORError error = QCBORDecode_Finish(&context);
        if (error != QCBOR_SUCCESS && result == SUIT_SUCCESS) {
            result = suit_error_from_qcbor_error(error);
        }
        printf("\n%*s]", indent_space, "");
        if (Out.uNumUsed > 0) {
            printf(")");
        }
    }
    return result;
}

suit_err_t suit_print_digest(const suit_digest_t *digest,
                             const uint32_t indent_space,
                             const uint32_t indent_delta)
{
    if (digest == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    if (digest->algorithm_id != SUIT_ALGORITHM_ID_INVALID
        && digest->bytes.len > 0) {
        printf("[\n");
        printf("%*s/ algorithm-id: / %d / %s /,\n", indent_space + indent_delta, "", digest->algorithm_id, suit_cose_alg_to_str(digest->algorithm_id));
        printf("%*s/ digest-bytes: / ", indent_space + indent_delta, "");
        result = suit_print_hex(digest->bytes.ptr, digest->bytes.len);
        printf("\n%*s]", indent_space, "");
    }
    return result;
}

suit_err_t suit_print_suit_parameters_list(const suit_parameters_list_t *params_list,
                                           const uint32_t indent_space,
                                           const uint32_t indent_delta)
{
    suit_err_t result = SUIT_SUCCESS;
    for (size_t i = 0; i < params_list->len; i++) {
        printf("%*s/ %s / %ld: ", indent_space, "", suit_parameter_key_to_str(params_list->params[i].label), params_list->params[i].label);
        switch (params_list->params[i].label) {
        /* int64 */
        case SUIT_PARAMETER_UPDATE_PRIORITY:
            printf("%ld", params_list->params[i].value.int64);
            break;

        /* uint64 */
        case SUIT_PARAMETER_COMPONENT_SLOT:
        case SUIT_PARAMETER_IMAGE_SIZE:
        case SUIT_PARAMETER_SOURCE_COMPONENT:
        case SUIT_PARAMETER_USE_BEFORE:
        case SUIT_PARAMETER_MINIMUM_BATTERY:
            printf("%lu", params_list->params[i].value.uint64);
            break;

        /* tstr */
        case SUIT_PARAMETER_URI:
            if (params_list->params[i].value.string.len > 0) {
                result = suit_print_string(&params_list->params[i].value.string);
            }
            else {
                printf("NULL");
            }
            break;

        /* bstr // UUID */
        case SUIT_PARAMETER_VENDOR_IDENTIFIER:
        case SUIT_PARAMETER_CLASS_IDENTIFIER:
        case SUIT_PARAMETER_DEVICE_IDENTIFIER:
            result = suit_print_hex(params_list->params[i].value.string.ptr,
                                    params_list->params[i].value.string.len);
            if (params_list->params[i].value.string.len == 16) {
                // estimates this value as UUID
                printf(" / ");
                result = suit_print_uuid(&params_list->params[i].value.string);
                if (result != SUIT_SUCCESS) {
                    return result;
                }
                printf(" /");
            }
            break;
        case SUIT_PARAMETER_CONTENT:
        case SUIT_PARAMETER_INVOKE_ARGS:
        case SUIT_PARAMETER_FETCH_ARGS:
            result = suit_print_hex(params_list->params[i].value.string.ptr,
                                    params_list->params[i].value.string.len);
            break;

        /* bstr .cbor SUIT_Encryption_Info */
        case SUIT_PARAMETER_ENCRYPTION_INFO:
            if (params_list->params[i].value.string.len > 0) {
                suit_print_encryption_info(&params_list->params[i].value.string, indent_space, indent_delta);
            }
            break;

        /* bstr .cbor SUIT_Wait_Event */
        case SUIT_PARAMETER_WAIT_INFO:
            if (params_list->params[i].value.string.len > 0) {
                suit_print_wait_event_buf(&params_list->params[i].value.string, indent_space, indent_delta);
            }
            break;

        /* bool */
        case SUIT_PARAMETER_STRICT_ORDER:
        case SUIT_PARAMETER_SOFT_FAILURE:
            printf("%s", (params_list->params[i].value.boolean) ? "true" : "false");
            break;

        /* SUIT_Digest */
        case SUIT_PARAMETER_IMAGE_DIGEST:
            printf("<< ");
            result = suit_print_digest(&params_list->params[i].value.digest, indent_space, indent_delta);
            printf(" >>");
            break;

        /* SUIT_Parameter_Version_Match */
        case SUIT_PARAMETER_VERSION:
            result = suit_print_version(&params_list->params[i].value.version_match, indent_space, indent_delta);
            break;

        default:
            result = SUIT_ERR_NOT_IMPLEMENTED;
            break;
        }
        if (result != SUIT_SUCCESS) {
            return result;
        }
        if (i + 1 != params_list->len) {
            printf(",");
        }
        printf("\n");
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_cmd_seq(const suit_decode_mode_t mode,
                              const suit_command_sequence_t *cmd_seq,
                              const uint32_t indent_space,
                              const uint32_t indent_delta)
{
    suit_err_t result = SUIT_SUCCESS;
    suit_command_sequence_t tmp_cmd_seq;
    for (size_t i = 0; i < cmd_seq->len; i++) {
        printf("%*s/ %s / %ld, ", indent_space, "", suit_command_sequence_key_to_str(cmd_seq->commands[i].label), cmd_seq->commands[i].label);
        switch (cmd_seq->commands[i].label) {
        /* SUIT_Rep_Policy */
        case SUIT_CONDITION_VENDOR_IDENTIFIER:
        case SUIT_CONDITION_CLASS_IDENTIFIER:
        case SUIT_CONDITION_IMAGE_MATCH:
        case SUIT_CONDITION_COMPONENT_SLOT:
        case SUIT_CONDITION_CHECK_CONTENT:
        case SUIT_CONDITION_ABORT:
        case SUIT_CONDITION_DEVICE_IDENTIFIER:

        /* in draft-ietf-suit-trust-comains */
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
            printf("%lu", cmd_seq->commands[i].value.uint64);
            break;

        /* SUIT_Command_Sequence */
        case SUIT_DIRECTIVE_RUN_SEQUENCE:
            result = suit_decode_command_sequence(mode, &cmd_seq->commands[i].value.string, &tmp_cmd_seq);
            if (result != SUIT_SUCCESS) {
                break;
            }
            printf("<< [\n");
            result = suit_print_cmd_seq(mode, &tmp_cmd_seq, indent_space + indent_delta, indent_delta);
            if (result != SUIT_SUCCESS) {
                break;
            }
            printf("%*s] >>", indent_space, "");
            break;

        /* IndexArg = uint // true // [ +uint ] */
        case SUIT_DIRECTIVE_SET_COMPONENT_INDEX:
            if (cmd_seq->commands[i].value.index_arg.len == 0) {
                printf("true");
            }
            else if (cmd_seq->commands[i].value.index_arg.len == 1) {
                printf("%u", cmd_seq->commands[i].value.index_arg.index[0]);
            }
            else if (cmd_seq->commands[i].value.index_arg.len < SUIT_MAX_INDEX_NUM) {
                printf("[");
                for (size_t j = 0; j < cmd_seq->commands[i].value.index_arg.len; j++) {
                    printf(" %u", cmd_seq->commands[i].value.index_arg.index[j]);
                    if (j + 1 != cmd_seq->commands[i].value.index_arg.len) {
                        printf(",");
                    }
                }
                printf(" ]");
            }
            else {
                return SUIT_ERR_INVALID_VALUE;
            }
            break;

        /* $$SUIT_Parameters */
        case SUIT_DIRECTIVE_SET_PARAMETERS:
        case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
            printf("{\n");
            if (cmd_seq->commands[i].value.params_list.len > 0) {
                result = suit_print_suit_parameters_list(&cmd_seq->commands[i].value.params_list, indent_space + indent_delta, indent_delta);
            }
            printf("%*s}", indent_space, "");
            break;

        /* SUIT_Directive_Try_Each_Argument */
        case SUIT_DIRECTIVE_TRY_EACH:
            printf("[\n");
            while (1) {
                result = suit_decode_command_sequence(mode, &cmd_seq->commands[i].value.string, &tmp_cmd_seq);
                if (result != SUIT_SUCCESS) {
                    break;
                }
                printf("%*s<< [\n", indent_space + indent_delta, "");
                result = suit_print_cmd_seq(mode, &tmp_cmd_seq, indent_space + 2 * indent_delta, indent_delta);
                if (result != SUIT_SUCCESS) {
                    break;
                }
                printf("%*s] >>", indent_space + indent_delta, "");
                if (i + 1 < cmd_seq->len && cmd_seq->commands[i + 1].label == SUIT_DIRECTIVE_TRY_EACH) {
                    printf(",\n");
                    i++;
                }
                else {
                    break;
                }
            }
            printf("\n%*s]", indent_space, "");
            break;

        /* SUIT_Directive_Copy_Params */
        case SUIT_DIRECTIVE_COPY_PARAMS:
            printf("{\n");
            while (1) {
                printf("%*s/ src-index / %u: [", indent_space + indent_delta, "", cmd_seq->commands[i].value.copy_params.src_index);
                for (size_t j = 0; j < cmd_seq->commands[i].value.copy_params.int64s.len; j++) {
                    printf(" %ld", cmd_seq->commands[i].value.copy_params.int64s.int64[j]);
                    if (j + 1 != cmd_seq->commands[i].value.copy_params.int64s.len) {
                        printf(",");
                    }
                }
                printf(" ]");

                if (i + 1 < cmd_seq->len && cmd_seq->commands[i + 1].label == SUIT_DIRECTIVE_COPY_PARAMS) {
                    printf(",\n");
                    i++;
                }
                else {
                    break;
                }
            }
            printf("\n%*s}", indent_space, "");
            break;

        /* SUIT_Override_Mult_Arg */
        case SUIT_DIRECTIVE_OVERRIDE_MULTIPLE:
            printf("{\n");
            while (1) {
                printf("%*s/ index / %u: {\n", indent_space + indent_delta, "", cmd_seq->commands[i].value.params_list.index);
                if (cmd_seq->commands[i].value.params_list.len > 0) {
                    result = suit_print_suit_parameters_list(&cmd_seq->commands[i].value.params_list, indent_space + 2 * indent_delta, indent_delta);
                }
                printf("%*s}", indent_space + indent_delta, "");

                if (i + 1 < cmd_seq->len && cmd_seq->commands[i + 1].label == SUIT_DIRECTIVE_OVERRIDE_MULTIPLE) {
                    printf(",\n");
                    i++;
                }
                else {
                    break;
                }
            }
            printf("\n%*s}", indent_space, "");
            break;

        case SUIT_CONDITION_INVALID:
        //default:
            result = SUIT_ERR_NOT_IMPLEMENTED;
            break;
        }
        if (result != SUIT_SUCCESS) {
            return result;
        }
        if (i + 1 != cmd_seq->len) {
            printf(",\n");
        }
        else {
            printf("\n");
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_component_identifier(const suit_component_identifier_t *identifier)
{
    if (identifier == NULL) {
        return SUIT_ERR_FATAL;
    }
    printf("[");
    for (size_t i = 0; i < identifier->len; i++) {
        suit_print_hex(identifier->identifier[i].ptr, identifier->identifier[i].len);
        if (i + 1 != identifier->len) {
            printf(", ");
        }
    }
    printf("]");
    return SUIT_SUCCESS;
}

int32_t suit_print_dependency(const suit_dependency_t *dependency,
                              const uint32_t indent_space,
                              const uint32_t indent_delta)
{
    if (dependency == NULL) {
        return SUIT_ERR_FATAL;
    }
    int32_t result = SUIT_SUCCESS;
    printf("%*s/ component-index / %d: {\n", indent_space, "", dependency->index);
    printf("%*s/ dependency-prefix / %d: ", indent_space + indent_delta, "", SUIT_DEPENDENCY_PREFIX);
    result = suit_print_component_identifier(&dependency->dependency_metadata.prefix);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    /* TODO: SUIT_Dependency-extensions */
    printf("\n%*s}", indent_space, "");

    return SUIT_SUCCESS;
}

bool suit_text_component_have_something_to_print(const suit_text_component_t *text_component)
{
    return (text_component->vendor_name.ptr != NULL ||
            text_component->model_name.ptr != NULL ||
            text_component->vendor_domain.ptr != NULL ||
            text_component->model_info.ptr != NULL ||
            text_component->component_description.ptr != NULL ||
            text_component->component_version.ptr != NULL ||
            text_component->version_required.ptr != NULL);
}

suit_err_t suit_print_text_component(const suit_text_component_t *text_component,
                                     const uint32_t indent_space,
                                     const uint32_t indent_delta)
{
    (void)indent_delta; /* avoiding unused parameter warning */

    if (text_component == NULL) {
        return SUIT_ERR_FATAL;
    }
    if (!suit_text_component_have_something_to_print(text_component)) {
        return SUIT_SUCCESS;
    }
    suit_err_t result = SUIT_SUCCESS;
    bool comma = false;
    if (text_component->vendor_name.ptr != NULL) {
        printf("%*s/ text-vendor-name / %d: ", indent_space, "", SUIT_TEXT_VENDOR_NAME);
        result = suit_print_string(&text_component->vendor_name);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text_component->model_name.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-model-name / %d: ", indent_space, "", SUIT_TEXT_MODEL_NAME);
        result = suit_print_string(&text_component->model_name);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text_component->vendor_domain.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-vendor-domain / %d: ", indent_space, "", SUIT_TEXT_VENDOR_DOMAIN);
        result = suit_print_string(&text_component->vendor_domain);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text_component->model_info.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-model-info / %d: ", indent_space, "", SUIT_TEXT_MODEL_INFO);
        result = suit_print_string(&text_component->model_info);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text_component->component_description.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-component-description / %d: ", indent_space, "", SUIT_TEXT_COMPONENT_DESCRIPTION);
        result = suit_print_string(&text_component->component_description);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text_component->component_version.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-component-version / %d: ", indent_space, "", SUIT_TEXT_COMPONENT_VERSION);
        result = suit_print_string(&text_component->component_version);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    /* in draft-ietf-suit-update-management */
    if (text_component->version_required.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-version-required / %d: ", indent_space, "", SUIT_TEXT_VERSION_REQUIRED);
        result = suit_print_string(&text_component->version_required);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    return SUIT_SUCCESS;
}

bool suit_whether_print_now(bool in_suit_manifest,
                            uint8_t status)
{
    return ((in_suit_manifest && (status & SUIT_SEVERABLE_IN_MANIFEST)) ||
           (!in_suit_manifest && (status & SUIT_SEVERABLE_IN_ENVELOPE)));
}

bool suit_is_severable_manifest_member_verified(uint8_t status)
{
    return (status & SUIT_SEVERABLE_IS_VERIFIED);
}

char *suit_str_verified(bool verified)
{
    return (verified) ? "verified" : "not verified";
}

char *suit_str_member_is_verified(uint8_t status)
{
    return suit_str_verified(suit_is_severable_manifest_member_verified(status));
}

bool suit_text_have_something_to_print(const suit_text_lmap_t *text)
{
    return (text->manifest_description.ptr != NULL ||
            text->update_description.ptr != NULL ||
            text->manifest_json_source.ptr != NULL ||
            text->manifest_yaml_source.ptr != NULL ||
            text->component_len > 0);
}

suit_err_t suit_print_text_lmap(const suit_text_lmap_t *text,
                                const uint32_t indent_space,
                                const uint32_t indent_delta)
{
    if (text == NULL) {
        return SUIT_ERR_FATAL;
    }
    if (!suit_text_have_something_to_print(text)) {
        return SUIT_SUCCESS;
    }
    suit_err_t result = SUIT_SUCCESS;
    bool comma = false;
    if (text->manifest_description.ptr != NULL) {
        printf("%*s/ text-manifest-description / %d: ", indent_space + indent_delta, "", SUIT_TEXT_MANIFEST_DESCRIPTION);
        result = suit_print_string(&text->manifest_description);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text->update_description.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-update-description / %d: ", indent_space + indent_delta, "", SUIT_TEXT_UPDATE_DESCRIPTION);
        result = suit_print_string(&text->update_description);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text->manifest_json_source.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text-manifest-json-source / %d: ", indent_space + indent_delta, "", SUIT_TEXT_MANIFEST_JSON_SOURCE);
        result = suit_print_string(&text->manifest_json_source);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    if (text->manifest_yaml_source.ptr != NULL) {
        if (comma) {
            printf(",\n");
        }
        printf("%*stext-manifest-yaml-source : ", indent_space + indent_delta, "");
        result = suit_print_string(&text->manifest_yaml_source);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    for (size_t i = 0; i < text->component_len; i++) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s", indent_space + indent_delta, "");
        result = suit_print_component_identifier(&text->component[i].key);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf(": {\n");
        result = suit_print_text_component(&text->component[i].text_component, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("\n%*s}\n", indent_space + indent_delta, "");
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_text(const suit_text_map_t *text,
                           const uint32_t indent_space,
                           const uint32_t indent_delta)
{
    bool comma = false;
    for (size_t i = 0; i < text->text_lmaps_len; i++) {
        const suit_text_lmap_t *lmap = &text->text_lmaps[i];
        if (comma) {
            printf(",\n");
        }

        printf("%*s\"%.*s\": {\n", indent_space + indent_delta, "", (int)lmap->tag38_ltag.len, lmap->tag38_ltag.ptr);
        suit_err_t result = suit_print_text_lmap(lmap, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s}", indent_space + indent_delta, "");
    }
    printf("\n");
    return SUIT_SUCCESS;
}

suit_err_t suit_print_manifest(const suit_decode_mode_t mode,
                               const suit_manifest_t *manifest,
                               const uint32_t indent_space,
                               const uint32_t indent_delta)
{
    if (manifest == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    printf("%*s/ manifest(%s) / 3: << {\n", indent_space, "", suit_str_verified(manifest->is_verified));
    printf("%*s/ manifest-version / 1: %lu,\n", indent_space + indent_delta, "", manifest->version);
    printf("%*s/ manifest-sequence-number / 2: %lu,\n", indent_space + indent_delta, "", manifest->sequence_number);

    printf("%*s/ common / 3: << {\n", indent_space + indent_delta, "");
    bool comma = false;
#if !defined(LIBCSUIT_DISABLE_COMMON_DEPENDENCIES)
    if (manifest->common.dependencies.len > 0) {
        printf("%*s/ dependencies / 1: {\n", indent_space + 2 * indent_delta, "");
        bool l1_comma = false;
        for (size_t i = 0; i < manifest->common.dependencies.len; i++) {
            if (l1_comma) {
                printf(",\n");
            }
            result = suit_print_dependency(&manifest->common.dependencies.dependency[i], indent_space + 3 * indent_delta, indent_delta);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            printf("\n");
            l1_comma = true;
        }
        printf("%*s}", indent_space + 2 * indent_delta, "");
        comma = true;
    }
#endif /* LIBCSUIT_DISABLE_COMMON_DEPENDENCIES */

    if (manifest->common.components_len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ components / 2: [", indent_space + 2 * indent_delta, "");
        for (size_t i = 0; i < manifest->common.components_len; i++) {
            printf("\n%*s", indent_space + 3 * indent_delta, "");
            result = suit_print_component_identifier(&manifest->common.components[i].component);
            if (result != SUIT_SUCCESS) {
                return result;
            }
            if (i + 1 != manifest->common.components_len) {
                printf(",");
            }
        }
        printf("\n%*s]", indent_space + 2 * indent_delta, "");
        comma = true;
    }
    if (manifest->common.shared_seq.len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ shared-sequence / 4: << [\n", indent_space + 2 * indent_delta, "");
        result = suit_print_cmd_seq(mode, &manifest->common.shared_seq, indent_space + 3 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + 2 * indent_delta, "");
        comma = true;
    }
    printf("\n%*s} >>", indent_space + indent_delta, "");

    if (manifest->manifest_component_id.len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ manifest-component-id / 5: ", indent_space + indent_delta, "");
        result = suit_print_component_identifier(&manifest->manifest_component_id);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    if (manifest->unsev_mem.validate.len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ validate / 7: << [\n", indent_space + indent_delta, "");
        result = suit_print_cmd_seq(mode, &manifest->unsev_mem.validate, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }
    if (manifest->unsev_mem.load.len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ load / 8: << [\n", indent_space + indent_delta, "");
        result = suit_print_cmd_seq(mode, &manifest->unsev_mem.load, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }

    if (manifest->unsev_mem.invoke.len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ invoke / 9: << [\n", indent_space + indent_delta, "");
        result = suit_print_cmd_seq(mode, &manifest->unsev_mem.invoke, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }

    if (manifest->sev_man_mem.dependency_resolution_status & SUIT_SEVERABLE_IN_MANIFEST) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ dependency-resolution(%s) / %d: << [\n", indent_space + indent_delta, "", suit_str_member_is_verified(manifest->sev_man_mem.dependency_resolution_status), SUIT_DEPENDENCY_RESOLUTION);
        result = suit_print_cmd_seq(mode, &manifest->sev_man_mem.dependency_resolution, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }
    else if (manifest->sev_mem_dig.dependency_resolution.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ dependency-resolution / %d: ", indent_space + indent_delta, "", SUIT_DEPENDENCY_RESOLUTION);
        result = suit_print_digest(&manifest->sev_mem_dig.dependency_resolution, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    if (manifest->sev_man_mem.payload_fetch_status & SUIT_SEVERABLE_IN_MANIFEST) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ payload-fetch(%s) / %d: << [\n", indent_space + indent_delta, "", suit_str_member_is_verified(manifest->sev_man_mem.payload_fetch_status), SUIT_PAYLOAD_FETCH);
        result = suit_print_cmd_seq(mode, &manifest->sev_man_mem.payload_fetch, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }
    else if (manifest->sev_mem_dig.payload_fetch.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ payload-fetch / %d: ", indent_space + indent_delta, "", SUIT_PAYLOAD_FETCH);
        result = suit_print_digest(&manifest->sev_mem_dig.payload_fetch, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    if (manifest->sev_man_mem.install_status & SUIT_SEVERABLE_IN_MANIFEST) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ install(%s) / %d: << [\n", indent_space + indent_delta, "", suit_str_member_is_verified(manifest->sev_man_mem.install_status), SUIT_INSTALL);
        result = suit_print_cmd_seq(mode, &manifest->sev_man_mem.install, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }
    else if (manifest->sev_mem_dig.install.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ install / %d: ", indent_space + indent_delta, "", SUIT_INSTALL);
        result = suit_print_digest(&manifest->sev_mem_dig.install, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    if (manifest->sev_man_mem.text_status & SUIT_SEVERABLE_IN_MANIFEST) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text(%s) / %d: << {\n", indent_space + indent_delta, "", suit_str_member_is_verified(manifest->sev_man_mem.text_status), SUIT_TEXT);
        result = suit_print_text(&manifest->sev_man_mem.text, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s} >>", indent_space + indent_delta, "");
        comma = true;
    }
    else if (manifest->sev_mem_dig.text.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text / %d: ", indent_space + indent_delta, "", SUIT_TEXT);
        result = suit_print_digest(&manifest->sev_mem_dig.text, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    if (manifest->unsev_mem.uninstall.len > 0) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ uninstall / 24: << [\n", indent_space + indent_delta, "");
        result = suit_print_cmd_seq(mode, &manifest->unsev_mem.uninstall, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }

    if (manifest->sev_man_mem.coswid_status & SUIT_SEVERABLE_IN_MANIFEST) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ coswid(%s) / %d: ", indent_space + indent_delta, "", suit_str_member_is_verified(manifest->sev_man_mem.coswid_status), SUIT_COSWID);
        result = suit_print_hex(manifest->sev_man_mem.coswid.ptr, manifest->sev_man_mem.coswid.len);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }
    else if (manifest->sev_mem_dig.coswid.algorithm_id != SUIT_ALGORITHM_ID_INVALID) {
        printf("%*s/ coswid / %d: ", indent_space + indent_delta, "", SUIT_COSWID);
        result = suit_print_digest(&manifest->sev_mem_dig.coswid, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    printf("\n%*s} >>", indent_space, "");
    return SUIT_SUCCESS;
}

suit_err_t suit_print_integrated_payload(const suit_payloads_t *payloads,
                                         const uint32_t indent_space,
                                         const uint32_t indent_delta)
{
    (void)indent_delta; /* avoiding unused parameter warning */

    for (size_t i = 0; i < payloads->len; i++) {
        printf("%*s\"%.*s\" : ", indent_space, "", (int)payloads->payload[i].key.len, (char *)payloads->payload[i].key.ptr);
        suit_print_hex_in_max(payloads->payload[i].bytes.ptr, payloads->payload[i].bytes.len, SUIT_MAX_PRINT_BYTE_COUNT);
        if (i + 1 < payloads->len) {
            printf(",\n");
        }
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_delegation(const suit_delegation_t *delegation,
                                 const uint32_t indent_space,
                                 const uint32_t indent_delta)
{
    (void)indent_delta; /* avoiding unused parameter warning */

    if (delegation == NULL) {
        return SUIT_ERR_FATAL;
    }
    for (size_t i = 0; i < delegation->delegation_chain_num; i++) {
        printf("%*s[ ", indent_space, "");
        for (size_t j = 0; j < delegation->delegation_chains[i].len; j++) {
            suit_print_hex(delegation->delegation_chains[i].chain[j].ptr, delegation->delegation_chains[i].chain[j].len);
            if (j + 1 != delegation->delegation_chains[i].len) {
                printf(", ");
            }
        }
        printf(" ]");
        if (i + 1 != delegation->delegation_chain_num) {
            printf(",");
        }
        printf("\n");
    }
    return SUIT_SUCCESS;
}

suit_err_t suit_print_envelope(const suit_decode_mode_t mode,
                               const suit_envelope_t *envelope,
                               const uint32_t indent_space,
                               const uint32_t indent_delta)
{
    if (envelope == NULL) {
        return SUIT_ERR_FATAL;
    }
    suit_err_t result = SUIT_SUCCESS;
    bool comma = false;
    printf("%*s/ SUIT_Envelope%s = / %s{\n", indent_space, "", envelope->tagged ? "_Tagged" : "", envelope->tagged ? "107(" : "");
    // delegation
    if (envelope->delegation.delegation_chain_num > 0) {
        printf("%*s/ delegation / 1: << [\n", indent_space + indent_delta, "");
        result = suit_print_delegation(&envelope->delegation, indent_space + 2 * indent_delta, indent_delta);
        printf("%*s] >>,\n", indent_space + indent_delta, "");
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }
    // authentication-wrapper
    printf("%*s/ authentication-wrapper /", indent_space + indent_delta, "");
    if (envelope->wrapper.digest.algorithm_id != SUIT_ALGORITHM_ID_INVALID &&
        envelope->wrapper.digest.bytes.len > 0) {
        printf(" 2: << [\n");
        printf("%*s/ digest: / << ", indent_space + 2 * indent_delta, "");
        result = suit_print_digest(&envelope->wrapper.digest, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf(" >>,\n");
        for (size_t i = 0; i < envelope->wrapper.signatures_len; i++) {
            printf("%*s/ signatures: / << ", indent_space + 2 * indent_delta, "");
            result = suit_print_signature(&envelope->wrapper.signatures[i], indent_space + 2 * indent_delta, indent_delta);
            printf(" >>\n");
        }
        printf("%*s] >>,", indent_space + indent_delta, "");
    }
    printf("\n");

    // manifest
    result = suit_print_manifest(mode, &envelope->manifest, indent_space + indent_delta, indent_delta);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    comma = true;
    /* SUIT_Severable_Manifest_Members */
    if (envelope->manifest.sev_man_mem.dependency_resolution_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ dependency-resolution(%s) / %d: << [\n", indent_space, "", suit_str_member_is_verified(envelope->manifest.sev_man_mem.dependency_resolution_status), SUIT_DEPENDENCY_RESOLUTION);
        result = suit_print_cmd_seq(mode, &envelope->manifest.sev_man_mem.dependency_resolution, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space, "");
        comma = true;
    }

    if (envelope->manifest.sev_man_mem.payload_fetch_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ payload-fetch(%s)/ %d: << [\n", indent_space, "", suit_str_member_is_verified(envelope->manifest.sev_man_mem.payload_fetch_status), SUIT_PAYLOAD_FETCH);
        result = suit_print_cmd_seq(mode, &envelope->manifest.sev_man_mem.payload_fetch, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space, "");
        comma = true;
    }

    if (envelope->manifest.sev_man_mem.install_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ install(%s) / %d: << [\n", indent_space + indent_delta, "", suit_str_member_is_verified(envelope->manifest.sev_man_mem.install_status), SUIT_INSTALL);
        result = suit_print_cmd_seq(mode, &envelope->manifest.sev_man_mem.install, indent_space + 2 * indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s] >>", indent_space + indent_delta, "");
        comma = true;
    }

    if (envelope->manifest.sev_man_mem.text_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ text(%s) / %d: << {\n", indent_space + indent_delta, "", suit_str_member_is_verified(envelope->manifest.sev_man_mem.text_status), SUIT_TEXT);
        result = suit_print_text(&envelope->manifest.sev_man_mem.text, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        printf("%*s} >>", indent_space + indent_delta, "");
        comma = true;
    }

    if (envelope->manifest.sev_man_mem.coswid_status & SUIT_SEVERABLE_IN_ENVELOPE) {
        if (comma) {
            printf(",\n");
        }
        printf("%*s/ coswid(%s) / %d: ", indent_space + indent_delta, "", suit_str_member_is_verified(envelope->manifest.sev_man_mem.coswid_status), SUIT_COSWID);
        result = suit_print_hex_in_max(envelope->manifest.sev_man_mem.coswid.ptr, envelope->manifest.sev_man_mem.coswid.len, SUIT_MAX_PRINT_BYTE_COUNT);
        if (result != SUIT_SUCCESS) {
            return result;
        }
        comma = true;
    }

    // integrated-payload
    if (envelope->payloads.len > 0) {
        if (comma) {
            printf(",\n");
        }
        result = suit_print_integrated_payload(&envelope->payloads, indent_space + indent_delta, indent_delta);
        if (result != SUIT_SUCCESS) {
            return result;
        }
    }

    // TODO: $$SUIT_Envelope_Extensions

    printf("\n%*s}%s", indent_space, "", envelope->tagged ? ")" : "");

    return SUIT_SUCCESS;
}

suit_err_t suit_print_invoke(suit_invoke_args_t invoke_args)
{
    printf("invoke callback : {\n");
    printf("  component-identifier : ");
    suit_print_component_identifier(&invoke_args.component_identifier);
    printf("\n");
    printf("  argument(len=%ld) : ", invoke_args.args_len);
    suit_print_hex(invoke_args.args, invoke_args.args_len);
    printf("\n");
    printf("  suit_rep_policy_t : RecPass%x RecFail%x SysPass%x SysFail%x\n", invoke_args.report.record_on_success, invoke_args.report.record_on_failure, invoke_args.report.sysinfo_success, invoke_args.report.sysinfo_failure);
    printf("}\n\n");
    return SUIT_SUCCESS;
}

char* suit_store_key_to_str(suit_store_key_t operation)
{
    switch (operation) {
    case SUIT_STORE: return "store";
    case SUIT_COPY: return "copy";
    case SUIT_SWAP: return "swap";
    case SUIT_UNLINK: return "unlink";
    default: return NULL;
    }
}

suit_err_t suit_print_store(suit_store_args_t store_args)
{
    suit_err_t ret = SUIT_SUCCESS;
    printf("store callback : {\n");
    printf("  operation : %s\n", suit_store_key_to_str(store_args.operation));
    printf("  dst-component-identifier : ");
    suit_print_component_identifier(&store_args.dst);
    printf("\n");
    if (store_args.operation == SUIT_COPY || store_args.operation == SUIT_SWAP) {
        printf("  src-component-identifier : ");
        suit_print_component_identifier(&store_args.src);
        printf("\n");
    }
    printf("  src-buf : ");
    suit_print_hex_in_max(store_args.src_buf.ptr, store_args.src_buf.len, SUIT_MAX_PRINT_BYTE_COUNT);
    printf("\n");
    if (!UsefulBuf_IsNULLOrEmptyC(store_args.encryption_info)) {
        printf("  encryption-info : ");
        suit_print_hex_string(store_args.encryption_info.ptr, store_args.encryption_info.len);
        printf("\n");
    }
    printf("  fetch-args : ");
    suit_print_hex(store_args.fetch_args.ptr, store_args.fetch_args.len);
    printf("\n");

    printf("  ptr : %p (%ld)\n", store_args.src_buf.ptr, store_args.src_buf.len);
    printf("  suit_rep_policy_t : RecPass%x RecFail%x SysPass%x SysFail%x\n", store_args.report.record_on_success, store_args.report.record_on_failure, store_args.report.sysinfo_success, store_args.report.sysinfo_failure);
    printf("}\n\n");
    return ret;
}

suit_err_t suit_print_fetch(suit_fetch_args_t fetch_args,
                            suit_fetch_ret_t *fetch_ret)
{
    (void)fetch_ret; /* avoiding unused parameter warning */

    suit_err_t ret = SUIT_SUCCESS;
    printf("fetch callback : {\n");
    printf("  uri : ");
    suit_print_tstr_in_max(fetch_args.uri, fetch_args.uri_len, SUIT_MAX_PRINT_URI_COUNT);
    printf(" (%ld)\n", fetch_args.uri_len);
    printf("  fetch-args : ");
    suit_print_hex(fetch_args.args.ptr, fetch_args.args.len);
    printf("\n");
    printf("  dst-component-identifier : ");
    suit_print_component_identifier(&fetch_args.dst);
    printf("\n");

    printf("  fetch buf : %p(%ld)\n", fetch_args.ptr, fetch_args.buf_len);
    printf("  suit_rep_policy_t : RecPass%x RecFail%x SysPass%x SysFail%x\n", fetch_args.report.record_on_success, fetch_args.report.record_on_failure, fetch_args.report.sysinfo_success, fetch_args.report.sysinfo_failure);
    printf("}\n\n");

    return ret;
}

suit_err_t suit_print_condition(suit_condition_args_t condition_args)
{
    suit_err_t result = SUIT_SUCCESS;

    printf("condition callback : {\n");
    printf("  operation : %s\n", suit_command_sequence_key_to_str(condition_args.condition));
    switch (condition_args.condition) {
    case SUIT_CONDITION_COMPONENT_SLOT:
    case SUIT_CONDITION_CHECK_CONTENT:
    case SUIT_CONDITION_IMAGE_MATCH:
    case SUIT_CONDITION_IMAGE_NOT_MATCH:
        printf("  dst-component-identifier : ");
        suit_print_component_identifier(&condition_args.dst);
        printf("\n");
        break;
    default:
        break;
    }

    printf("  expected : ");
    switch (condition_args.condition) {
    /* int64 */
    case SUIT_CONDITION_UPDATE_AUTHORIZED:
        printf("%ld\n", condition_args.expected.i64);
        break;

    /* uint64 */
    case SUIT_CONDITION_COMPONENT_SLOT:
    case SUIT_CONDITION_USE_BEFORE:
    case SUIT_CONDITION_MINIMUM_BATTERY:
        printf("%lu\n", condition_args.expected.u64);
        break;

    /* bstr */
    case SUIT_CONDITION_VENDOR_IDENTIFIER:
    case SUIT_CONDITION_CLASS_IDENTIFIER:
    case SUIT_CONDITION_DEVICE_IDENTIFIER:
    case SUIT_CONDITION_CHECK_CONTENT:
        suit_print_hex(condition_args.expected.str.ptr, condition_args.expected.str.len);
        printf("\n");
        break;

    /* uint64 image_size and suit-digest */
    case SUIT_CONDITION_IMAGE_MATCH:
    case SUIT_CONDITION_IMAGE_NOT_MATCH:
        printf("{\n    image_size : %lu\n    image_digest : ", condition_args.expected.image_size);
        suit_print_digest(&condition_args.expected.image_digest, 4, 2);
        printf("\n%*s}\n", 2, "");
        break;

    /* must be handled in the library */
    case SUIT_CONDITION_IS_DEPENDENCY:
    case SUIT_CONDITION_ABORT:
        result = SUIT_ERR_INVALID_KEY;
        break;

    /* SUIT_Parameter_Version_Match */
    case SUIT_CONDITION_VERSION:
        suit_print_version(&condition_args.expected.version_match, 2, 2);
        printf("\n");
        break;

    /* not implemented */
    case SUIT_CONDITION_DEPENDENCY_INTEGRITY:
    default:
        result = SUIT_ERR_NOT_IMPLEMENTED;
    }

    printf("  suit_rep_policy_t : RecPass%x RecFail%x SysPass%x SysFail%x\n", condition_args.report.record_on_success, condition_args.report.record_on_failure, condition_args.report.sysinfo_success, condition_args.report.sysinfo_failure);
    printf("}\n\n");

    return result;
}

suit_err_t suit_print_wait(suit_wait_args_t wait_args)
{
    suit_err_t ret = SUIT_SUCCESS;

    printf("wait callback : {\n");
    printf("  dst-component-identifier : ");
    suit_print_component_identifier(&wait_args.dst);
    printf("\n");
    printf("  wait-info : ");
    suit_print_wait_event(&wait_args.wait_info, 2, 2);
    printf("\n  suit_rep_policy_t : RecPass%x RecFail%x SysPass%x SysFail%x\n", wait_args.report.record_on_success, wait_args.report.record_on_failure, wait_args.report.sysinfo_success, wait_args.report.sysinfo_failure);
    printf("}\n\n");

    return ret;
}

suit_err_t suit_print_report(suit_report_args_t report_args)
{
    printf("report callback : {\n");
    printf("  at: %d(%s)", report_args.level0, suit_envelope_key_to_str(report_args.level0));

    switch (report_args.level0) {
    case SUIT_DELEGATION:
        break;
    case SUIT_AUTHENTICATION:
        break;
    case SUIT_MANIFEST:
        printf(", %d(%s)", report_args.level1.manifest_key, suit_manifest_key_to_str(report_args.level1.manifest_key));
        switch (report_args.level1.manifest_key) {
        case SUIT_COMMON:
            printf(", %d(%s)", report_args.level2.common_key, suit_common_key_to_str(report_args.level2.common_key));
            if (report_args.level2.common_key == SUIT_SHARED_SEQUENCE) {
                printf(", %d(%s)", report_args.level3.condition_directive, suit_command_sequence_key_to_str(report_args.level3.condition_directive));
                switch (report_args.level3.condition_directive) {
                case SUIT_DIRECTIVE_SET_PARAMETERS:
                case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                    printf(", %d(%s)", report_args.level4.parameter, suit_parameter_key_to_str(report_args.level4.parameter));
                    break;
                default:
                    break;
                }
            }
            break;
        case SUIT_INSTALL:
        case SUIT_VALIDATE:
        case SUIT_INVOKE:
            printf(", %d(%s)", report_args.level2.condition_directive, suit_command_sequence_key_to_str(report_args.level2.condition_directive));
            switch (report_args.level2.condition_directive) {
            case SUIT_DIRECTIVE_SET_PARAMETERS:
            case SUIT_DIRECTIVE_OVERRIDE_PARAMETERS:
                printf(", %d(%s)", report_args.level3.parameter, suit_parameter_key_to_str(report_args.level3.parameter));
                break;
            default:
                break;
            }
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
    printf("\n");

    printf("  QCBORError:    %d(%s)\n", report_args.qcbor_error, qcbor_err_to_str(report_args.qcbor_error));
    printf("  suit_err_t:    %d(%s)\n", report_args.suit_error, suit_err_to_str(report_args.suit_error));
    printf("  suit_rep_policy_t: RecPass%x RecFail%x SysPass%x SysFail%x\n", report_args.report.record_on_success, report_args.report.record_on_failure, report_args.report.sysinfo_success, report_args.report.sysinfo_failure);

    printf("}\n\n");

    return SUIT_ERR_FATAL;
}

