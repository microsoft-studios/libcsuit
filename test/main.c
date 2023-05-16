/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include "csuit/csuit.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "../examples/inc/trust_anchor_prime256v1_cose_key_private.h"

void test_csuit_rollback(void);
void test_csuit_get_digest(void);
void test_component_identifier_to_filename(void);
void test_csuit_suit_encode_buf(void);
void test_csuit_canonical_cbor(void);
void test_csuit_without_authentication_wrapper(void);
void test_csuit_cose_key(void);


int main(int argc, char *argv[])
{
    CU_pSuite suite;
    CU_initialize_registry();
    suite = CU_add_suite("SUIT", NULL, NULL);
    CU_add_test(suite, "test_csuit_rollback", test_csuit_rollback);
    CU_add_test(suite, "test_csuit_get_digest", test_csuit_get_digest);
    CU_add_test(suite, "test_component_identifier_to_filename", test_component_identifier_to_filename);
    CU_add_test(suite, "test_csuit_suit_encode_buf", test_csuit_suit_encode_buf);
    CU_add_test(suite, "test_csuit_without_authentication_wrapper", test_csuit_without_authentication_wrapper);
    CU_add_test(suite, "test_csuit_canonical_cbor", test_csuit_canonical_cbor);
    CU_add_test(suite, "test_csuit_cose_key", test_csuit_cose_key);
    CU_basic_set_mode(CU_BRM_SILENT);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}

size_t test_csuit_rollback_buf(const uint8_t *buf, const size_t len)
{
    QCBORDecodeContext context;
    QCBORItem item;
    QCBORDecode_Init(&context, (UsefulBufC){buf, len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_qcbor_get_next(&context, &item, QCBOR_TYPE_ANY);
    size_t cursor = UsefulInputBuf_Tell(&context.InBuf);
    QCBORDecode_Finish(&context);
    CU_ASSERT(result == SUIT_SUCCESS);
    return suit_qcbor_calc_rollback(&item) - cursor;
}

void test_csuit_rollback(void)
{
    uint8_t bufu0[] = {0x17}; // unsigned(23)
    CU_ASSERT(test_csuit_rollback_buf(bufu0, sizeof(bufu0)) == 0);
    uint8_t bufu1[] = {0x18, 0x18}; // unsigned(24)
    CU_ASSERT(test_csuit_rollback_buf(bufu1, sizeof(bufu1)) == 0);
    uint8_t bufu2[] = {0x18, 0xFF}; // unsigned(255)
    CU_ASSERT(test_csuit_rollback_buf(bufu2, sizeof(bufu2)) == 0);
    uint8_t bufu3[] = {0x19, 0x01, 0x00}; // unsigned(256)
    CU_ASSERT(test_csuit_rollback_buf(bufu3, sizeof(bufu3)) == 0);
    uint8_t bufu4[] = {0x19, 0xFF, 0xFF}; // unsigned(65535)
    CU_ASSERT(test_csuit_rollback_buf(bufu4, sizeof(bufu4)) == 0);
    uint8_t bufu5[] = {0x1A, 0x00, 0x01, 0x00, 0x00}; // unsigned(65536)
    CU_ASSERT(test_csuit_rollback_buf(bufu5, sizeof(bufu5)) == 0);
    uint8_t bufu6[] = {0x1A, 0xFF, 0xFF, 0xFF, 0xFF}; // unsigned(4294967295)
    CU_ASSERT(test_csuit_rollback_buf(bufu6, sizeof(bufu6)) == 0);
    uint8_t bufu7[] = {0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    CU_ASSERT(test_csuit_rollback_buf(bufu7, sizeof(bufu7)) == 0);
    uint8_t bufu8[] = {0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // unsigned(18446744073709551615)
    CU_ASSERT(test_csuit_rollback_buf(bufu8, sizeof(bufu8)) == 0);

    uint8_t bufn0[] = {0x37}; // negative(23) = -24
    CU_ASSERT(test_csuit_rollback_buf(bufn0, sizeof(bufn0)) == 0);
    uint8_t bufn1[] = {0x38, 0x18}; // negative(24) = -25
    CU_ASSERT(test_csuit_rollback_buf(bufn1, sizeof(bufn1)) == 0);
    uint8_t bufn2[] = {0x38, 0xFF}; // negative(255) = -256
    CU_ASSERT(test_csuit_rollback_buf(bufn2, sizeof(bufn2)) == 0);
    uint8_t bufn3[] = {0x39, 0x01, 0x00}; // negative(256) = -257
    CU_ASSERT(test_csuit_rollback_buf(bufn3, sizeof(bufn3)) == 0);
    uint8_t bufn4[] = {0x39, 0xFF, 0xFF}; // negative(65535) = -65536
    CU_ASSERT(test_csuit_rollback_buf(bufn4, sizeof(bufn4)) == 0);
    uint8_t bufn5[] = {0x3A, 0x00, 0x01, 0x00, 0x00}; // negative(65536) = -65537
    CU_ASSERT(test_csuit_rollback_buf(bufn5, sizeof(bufn5)) == 0);
    uint8_t bufn6[] = {0x3A, 0xFF, 0xFF, 0xFF, 0xFF}; // negative(4294967295) = -4294967296
    CU_ASSERT(test_csuit_rollback_buf(bufn6, sizeof(bufn6)) == 0);
    uint8_t bufn7[] = {0x3B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}; // negative(4294967296)
    CU_ASSERT(test_csuit_rollback_buf(bufn7, sizeof(bufn7)) == 0);
    uint8_t bufn8[] = {0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // negative(9223372036854775807) = -9223372036854775808
    CU_ASSERT(test_csuit_rollback_buf(bufn8, sizeof(bufn8)) == 0);

    uint8_t buft0[] = {0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77};
    CU_ASSERT(test_csuit_rollback_buf(buft0, sizeof(buft0)) == 0);
    uint8_t buft1[] = {0x78, 0x18, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78};
    CU_ASSERT(test_csuit_rollback_buf(buft1, sizeof(buft1)) == 0);
    uint8_t buft2[259]; // text(255)
    buft2[0] = 0x78;
    buft2[1] = 0xFF;
    memset(&buft2[2], 'a', 259 - 2);
    CU_ASSERT(test_csuit_rollback_buf(buft2, 2 + 255) == 0);
    buft2[0] = 0x79; // text(256)
    buft2[1] = 0x01;
    buft2[2] = 0x00;
    CU_ASSERT(test_csuit_rollback_buf(buft2, 259) == 0);
    uint8_t *buft3 = (uint8_t *)malloc(UINT16_MAX + 6);
    buft3[0] = 0x79;
    buft3[1] = 0xFF;
    buft3[2] = 0xFF;
    memset(&buft3[3], 'a', UINT16_MAX + 6 - 3);
    CU_ASSERT(test_csuit_rollback_buf(buft3, UINT16_MAX + 3) == 0);
    buft3[0] = 0x7A;
    buft3[1] = 0x00;
    buft3[2] = 0x01;
    buft3[3] = 0x00;
    buft3[4] = 0x00;
    CU_ASSERT(test_csuit_rollback_buf(buft3, UINT16_MAX + 6) == 0);
    free(buft3);

    uint8_t bufa0[26];
    bufa0[0] = 0x97; // array(23)
    memset(&bufa0[1], 0, 26 - 1);
    CU_ASSERT(test_csuit_rollback_buf(bufa0, 24) == 0);
    bufa0[0] = 0x98; // array(24)
    bufa0[1] = 0x18;
    CU_ASSERT(test_csuit_rollback_buf(bufa0, 26) == 0);
}

void test_csuit_get_digest(void)
{
    QCBORDecodeContext context;
    QCBORError error;
    suit_digest_t digest;

    uint8_t bstr_wrapped_array[] = {
        0x41, 0x80
    };
    QCBORDecode_Init(&context, (UsefulBufC){.ptr = bstr_wrapped_array, .len = sizeof(bstr_wrapped_array)}, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterBstrWrapped(&context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterArray(&context, NULL);
    QCBORDecode_ExitArray(&context);
    QCBORDecode_ExitBstrWrapped(&context);
    error = QCBORDecode_Finish(&context);
    CU_ASSERT_EQUAL(error, QCBOR_SUCCESS);

    uint8_t suit_digest_buf[] = {
        0x58, 0x24, 0x82, 0x02, 0x58, 0x20, 0x5C, 0x09, 0x7E, 0xF6,
        0x4B, 0xF3, 0xBB, 0x9B, 0x49, 0x4E, 0x71, 0xE1, 0xF2, 0x41,
        0x8E, 0xEF, 0x8D, 0x46, 0x6C, 0xC9, 0x02, 0xF6, 0x39, 0xA8,
        0x55, 0xEC, 0x9A, 0xF3, 0xE9, 0xED, 0xDB, 0x99
    };
    QCBORDecode_Init(&context, (UsefulBufC){.ptr = suit_digest_buf, .len = sizeof(suit_digest_buf)}, QCBOR_DECODE_MODE_NORMAL);
    suit_process_digest(&context, &digest, NULL);
    error = QCBORDecode_Finish(&context);
    CU_ASSERT_EQUAL(error, QCBOR_SUCCESS);
    CU_ASSERT_EQUAL(digest.bytes.len, 32);

    uint8_t suit_authentication_buf[] = {
        0x58, 0x73, 0x82, 0x58, 0x24, 0x82, 0x02, 0x58, 0x20, 0x5C,
        0x09, 0x7E, 0xF6, 0x4B, 0xF3, 0xBB, 0x9B, 0x49, 0x4E, 0x71,
        0xE1, 0xF2, 0x41, 0x8E, 0xEF, 0x8D, 0x46, 0x6C, 0xC9, 0x02,
        0xF6, 0x39, 0xA8, 0x55, 0xEC, 0x9A, 0xF3, 0xE9, 0xED, 0xDB,
        0x99, 0x58, 0x4A, 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0,
        0xF6, 0x58, 0x40, 0xA1, 0x9F, 0xD1, 0xF2, 0x3B, 0x17, 0xBE,
        0xED, 0x32, 0x1C, 0xEC, 0xE7, 0x42, 0x3D, 0xFB, 0x48, 0xC4,
        0x57, 0xB8, 0xF1, 0xF6, 0xAC, 0x83, 0x57, 0x7A, 0x3C, 0x10,
        0xC6, 0x77, 0x3F, 0x6F, 0x3A, 0x79, 0x02, 0x37, 0x6B, 0x59,
        0x54, 0x09, 0x20, 0xB6, 0xC5, 0xF5, 0x7B, 0xAC, 0x5F, 0xC8,
        0x54, 0x3D, 0x8F, 0x5D, 0x3D, 0x97, 0x4F, 0xAA, 0x2E, 0x6D,
        0x03, 0xDA, 0xA5, 0x34, 0xB4, 0x43, 0xA7
    };
    UsefulBufC tmp;

    QCBORDecode_Init(&context, (UsefulBufC){.ptr = suit_authentication_buf, .len = sizeof(suit_authentication_buf)}, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterBstrWrapped(&context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterArray(&context, NULL);
    //QCBORDecode_GetByteString(&context, &tmp);
    /*
    QCBORDecode_EnterBstrWrapped(&context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterArray(&context, NULL);
    QCBORDecode_GetNext(&context, &item);
    QCBORDecode_GetNext(&context, &item);
    QCBORDecode_ExitArray(&context);
    QCBORDecode_ExitBstrWrapped(&context);
    */
    suit_process_digest(&context, &digest, NULL);

    QCBORDecode_GetByteString(&context, &tmp);
    QCBORDecode_ExitArray(&context);
    QCBORDecode_ExitBstrWrapped(&context);
    //suit_process_authentication_wrapper(&context, NULL, &digest);
    error = QCBORDecode_Finish(&context);
    CU_ASSERT_EQUAL(error, QCBOR_SUCCESS);
    CU_ASSERT_EQUAL(digest.bytes.len, 32);
}

void test_component_identifier_to_filename(void)
{
    char c0[] = "TEEP-Device";
    char c1[] = "SecureFS";
    uint8_t c2[] = {0x8D, 0x82, 0x57, 0x3A, 0x92, 0x6D, 0x47, 0x54, 0x93, 0x53, 0x32, 0xDC, 0x29, 0x99, 0x7F, 0x74};
    char c3[] = "ta";

    suit_component_identifier_t c;
    c.len = 4;
    c.identifier[0].ptr = (uint8_t *)c0;
    c.identifier[0].len = strlen(c0);
    c.identifier[1].ptr = (uint8_t *)c1;
    c.identifier[1].len = strlen(c1);
    c.identifier[2].ptr = c2;
    c.identifier[2].len = sizeof(c2);
    c.identifier[3].ptr = (uint8_t *)c3;
    c.identifier[3].len = strlen(c3);

    char filename[SUIT_MAX_NAME_LENGTH];
    suit_err_t result = suit_component_identifier_to_filename(&c, SUIT_MAX_NAME_LENGTH, filename);

    char expected_filename[] = "./tmp/TEEP-Device/SecureFS/8d82573a926d4754935332dc29997f74/ta";
    CU_ASSERT_EQUAL(result, SUIT_SUCCESS);
    CU_ASSERT_STRING_EQUAL(filename, expected_filename);
}

void test_csuit_suit_encode_buf(void)
{
    suit_err_t result;
    UsefulBuf_MAKE_STACK_UB(buf, 16);
    suit_encode_t suit_encode = {
        .max_pos = buf.len,
        .buf = buf.ptr,
    };

    /* memory usage layout test */
    UsefulBuf buf1;
    suit_use_suit_encode_buf(&suit_encode, 2, &buf1);
    memset(buf1.ptr, '1', sizeof(char) * buf1.len);
    suit_fix_suit_encode_buf(&suit_encode, buf1.len);
    UsefulBuf buf2;
    suit_use_suit_encode_buf(&suit_encode, 3, &buf2);
    memset(buf2.ptr, '2', sizeof(char) * buf2.len);
    suit_fix_suit_encode_buf(&suit_encode, buf2.len);
    CU_ASSERT_NSTRING_EQUAL(buf.ptr, "11222", 5);

    /* cause SUIT_ERR_NO_MEMORY on double allocate buf */
    suit_use_suit_encode_buf(&suit_encode, 2, &buf1);
    result = suit_use_suit_encode_buf(&suit_encode, 3, &buf2);
    CU_ASSERT_EQUAL(result, SUIT_ERR_NO_MEMORY);
    result = suit_fix_suit_encode_buf(&suit_encode, buf1.len);
    CU_ASSERT_EQUAL(result, SUIT_SUCCESS);

    /* cause SUIT_ERR_NO_MEMORY on buffer overflow */
    // NOTE: cur_pos == pos == 7
    UsefulBuf buf3;
    result = suit_use_suit_encode_buf(&suit_encode, 10, &buf3);
    CU_ASSERT_EQUAL(result, SUIT_ERR_NO_MEMORY);
    result = suit_use_suit_encode_buf(&suit_encode, 9, &buf3);
    CU_ASSERT_EQUAL(result, SUIT_SUCCESS);
    result = suit_fix_suit_encode_buf(&suit_encode, buf3.len);
    CU_ASSERT_EQUAL(result, SUIT_SUCCESS);
}

void test_csuit_without_authentication_wrapper(void)
{
    uint8_t mini_manifest[] = {
        0xd8, 0x6b,                                                     // 107(
              0xa1,                                                     // map(1){
                    0x03,                                               // manifest 3
                    0x4d,                                               // bytes <<
                          0xa3,                                         // map(3){
                                0x01,                                   // manifest-version 1
                                0x01,                                   // 1
                                0x02,                                   // manifest-sequence-number 2
                                0x00,                                   // 0
                                0x03,                                   // common
                                0x46,                                   // bytes <<
                                      0xa1,                             // map(1){
                                            0x02,                       // components 2
                                            0x81,                       // array(1)[
                                                  0x81, 0x41, 0x00      // [h'00']
    };
    suit_err_t result;
    suit_buf_t buf;
    buf.ptr = mini_manifest;
    buf.len = sizeof(mini_manifest);
    suit_envelope_t envelope = {0};
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM] = {0};

    result = suit_decode_envelope(SUIT_DECODE_MODE_STRICT, &buf, &envelope, mechanisms);
    CU_ASSERT_EQUAL(result, SUIT_ERR_AUTHENTICATION_NOT_FOUND);

    suit_decode_mode_t mode = SUIT_DECODE_MODE_STRICT;
    mode.SKIP_AUTHENTICATION_FAILURE = 1;
    envelope = (suit_envelope_t) {0};
    result = suit_decode_envelope(mode, &buf, &envelope, mechanisms);
    CU_ASSERT_EQUAL(result, SUIT_SUCCESS);
}

void test_csuit_canonical_cbor(void)
{
    uint8_t mini_manifest[] = {
        0xd8, 0x6b,                                                     // 107(
              0xa1,                                                     // map(1){
                    0x03,                                               // manifest 3
                    0x4d,                                               // bytes <<
                          0xa3,                                         // map(3){
                                0x02,                                   // manifest-sequence-number 2
                                0x00,                                   // 0
                                0x01,                                   // manifest-version 1
                                0x01,                                   // 1
                                0x03,                                   // common
                                0x46,                                   // bytes <<
                                      0xa1,                             // map(1){
                                            0x02,                       // components 2
                                            0x81,                       // array(1)[
                                                  0x81, 0x41, 0x00      // [h'00']
    };
    suit_err_t result;
    suit_buf_t buf;
    buf.ptr = mini_manifest;
    buf.len = sizeof(mini_manifest);
    suit_envelope_t envelope = {0};
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM] = {0};

    suit_decode_mode_t mode = SUIT_DECODE_MODE_STRICT;
    mode.SKIP_AUTHENTICATION_FAILURE = 1;
    result = suit_decode_envelope(mode, &buf, &envelope, mechanisms);
    CU_ASSERT_EQUAL(result, SUIT_ERR_NOT_CANONICAL_CBOR);

    envelope = (suit_envelope_t) {0};
    mode.SKIP_AUTHENTICATION_FAILURE = 1;
    mode.ALLOW_NOT_CANONICAL_CBOR = 1;
    result = suit_decode_envelope(mode, &buf, &envelope, mechanisms);
    CU_ASSERT_EQUAL(result, SUIT_SUCCESS);
}

void test_csuit_cose_key(void)
{
    suit_err_t result = SUIT_SUCCESS;
    suit_mechanism_t mechanism;

    uint8_t cose_key_buf[] = {
        0xA5,                                 //# map(5)
           0x01,                              //# unsigned(1) / 1 = kty /
           0x02,                              //# unsigned(2) / 2 = EC2 /
           0x20,                              //# negative(0) / -1 = crv /
           0x01,                              //# unsigned(1) / 1 = P-256 /
           0x21,                              //# negative(1) / -2 = x /
           0x58, 0x20,                        //# bytes(32)
              0x84, 0x96, 0x81, 0x1A, 0xAE, 0x0B, 0xAA, 0xAB,
              0xD2, 0x61, 0x57, 0x18, 0x9E, 0xEC, 0xDA, 0x26,
              0xBE, 0xAA, 0x8B, 0xF1, 0x1B, 0x6F, 0x3F, 0xE6,
              0xE2, 0xB5, 0x65, 0x9C, 0x85, 0xDB, 0xC0, 0xAD,
           0x22,                              //# negative(2) / -3 = y /
           0x58, 0x20,                        //# bytes(32)
              0x3B, 0x1F, 0x2A, 0x4B, 0x6C, 0x09, 0x81, 0x31,
              0xC0, 0xA3, 0x6D, 0xAC, 0xD1, 0xD7, 0x8B, 0xD3,
              0x81, 0xDC, 0xDF, 0xB0, 0x9C, 0x05, 0x2D, 0xB3,
              0x39, 0x91, 0xDB, 0x73, 0x38, 0xB4, 0xA8, 0x96,
           0x23,                              //# negative(3) / -4 = d /
           0x58, 0x20,                        //# bytes(32)
              0x02, 0x96, 0x58, 0x8D, 0x90, 0x94, 0x18, 0xB3,
              0x39, 0xD1, 0x50, 0x42, 0x0A, 0x36, 0x12, 0xB5,
              0x7F, 0xB4, 0xF6, 0x31, 0xA6, 0x9F, 0x22, 0x4F,
              0xAE, 0x90, 0xCB, 0x4F, 0x3F, 0xE1, 0x89, 0x73,
    };
    UsefulBufC cose_key = {
        .ptr = cose_key_buf,
        .len = sizeof(cose_key_buf)
    };
    result = suit_set_mechanism_from_cose_key(cose_key, &mechanism);
    CU_ASSERT_EQUAL(result, SUIT_SUCCESS);
    CU_ASSERT_EQUAL(mechanism.key.private_key_len, 32);
    CU_ASSERT_EQUAL(mechanism.key.public_key_len, 65);

    uint8_t cwt_payload_buf[] = {
        0xA1,                                       //# map(1)
           0x08,                                    //# unsigned(8) / 8 = cnf /
           0xA1,                                    //# map(1)
              0x01,                                 //# unsigned(1) / 1 = COSE_Key /
              0xA4,                                 //# map(4)
                 0x01,                              //# unsigned(1) / 1 = kty /
                 0x02,                              //# unsigned(2) / 2 = EC2 /
                 0x20,                              //# negative(0) / -1 = crv /
                 0x01,                              //# unsigned(1) / 1 = P-256 /
                 0x21,                              //# negative(1) / -2 = x /
                 0x58, 0x20,                        //# bytes(32)
                    0x84, 0x96, 0x81, 0x1A, 0xAE, 0x0B, 0xAA, 0xAB,
                    0xD2, 0x61, 0x57, 0x18, 0x9E, 0xEC, 0xDA, 0x26,
                    0xBE, 0xAA, 0x8B, 0xF1, 0x1B, 0x6F, 0x3F, 0xE6,
                    0xE2, 0xB5, 0x65, 0x9C, 0x85, 0xDB, 0xC0, 0xAD,
                 0x22,                              //# negative(2) / -3 = y /
                 0x58, 0x20,                        //# bytes(32)
                    0x3B, 0x1F, 0x2A, 0x4B, 0x6C, 0x09, 0x81, 0x31,
                    0xC0, 0xA3, 0x6D, 0xAC, 0xD1, 0xD7, 0x8B, 0xD3,
                    0x81, 0xDC, 0xDF, 0xB0, 0x9C, 0x05, 0x2D, 0xB3,
                    0x39, 0x91, 0xDB, 0x73, 0x38, 0xB4, 0xA8, 0x96,
    };
    UsefulBufC cwt_payload = {
        .ptr = cwt_payload_buf,
        .len = sizeof(cwt_payload_buf)
    };

    result = suit_set_mechanism_from_cwt_payload(cwt_payload, &mechanism);
    CU_ASSERT_EQUAL(result, SUIT_SUCCESS);
    CU_ASSERT_EQUAL(mechanism.key.private_key_len, 0);
    CU_ASSERT_EQUAL(mechanism.key.public_key_len, 65);
}
