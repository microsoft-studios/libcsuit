/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*!
    \file   suit_manifest_process_main.c

    \brief  A sample to use libcsuit processing
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h> // pid_t
#include <sys/wait.h> // waitpid
#include <unistd.h> // fork, getopt, optarg
#include <fcntl.h> // AT_FDCWD
#include "csuit/suit_manifest_process.h"
#include "csuit/suit_manifest_print.h"
#include "csuit/suit_cose.h"
#include "csuit/suit_digest.h"
#include "suit_examples_common.h"
#include "trust_anchor_prime256v1_cose_key_public.h"
#include "delegated_authority_cose_key_public.h"
#include "trust_anchor_hmac256_cose_key_secret.h"
#include "trust_anchor_a128_cose_key_secret.h"
#include "device_es256_cose_key_private.h"

typedef struct {
    char *url;
    char *filename;
} UrlFilenamePair;
UrlFilenamePair pairs[SUIT_MAX_ARRAY_LENGTH] = {0};

suit_err_t __real_suit_fetch_callback(suit_fetch_args_t fetch_args, suit_fetch_ret_t *fetch_ret);
suit_err_t __wrap_suit_fetch_callback(suit_fetch_args_t fetch_args, suit_fetch_ret_t *fetch_ret)
{
    suit_err_t result = __real_suit_fetch_callback(fetch_args, fetch_ret);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    char filename[SUIT_MAX_NAME_LENGTH];
    result = suit_component_identifier_to_filename(&fetch_args.dst, SUIT_MAX_NAME_LENGTH, filename);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    size_t i = 0;
    for (i = 0; i < SUIT_MAX_ARRAY_LENGTH; i++) {
        if (pairs[i].url == NULL) {
            continue;
        }
        if (memcmp(pairs[i].url, fetch_args.uri, fetch_args.uri_len) == 0) {
            FILE *f = fopen(pairs[i].filename, "r");
            if (f == NULL) {
                return SUIT_ERR_NOT_FOUND;
            }
            fseek(f, 0, SEEK_END);
            long size = ftell(f);
            if (size < 0 || fetch_args.buf_len < size) {
                fclose(f);
                return SUIT_ERR_NO_MEMORY;
            }
            fseek(f, 0, SEEK_SET);
            if (fetch_args.ptr != NULL) {
                size_t num_read = fread(fetch_args.ptr, 1, size, f);
                if (num_read != size) {
                    fclose(f);
                    return SUIT_ERR_NO_MEMORY;
                }
                fetch_ret->buf_len = size;
            }
            fclose(f);
            write_to_file(filename, fetch_args.ptr, size);
            printf("fetched from %s as %s (%ld bytes)\n\n", pairs[i].filename, pairs[i].url, size);
            break;
        }
    }
    if (i == SUIT_MAX_ARRAY_LENGTH) {
        /* not found */
        /* ignore this for testing example 0-5 only */
        //return SUIT_ERR_NOT_FOUND;
        fetch_ret->buf_len = fetch_args.buf_len;
    }

    if (result != SUIT_SUCCESS) {
        printf("callback : error = %s(%d)\n", suit_err_to_str(result), result);
    }
    else {
        printf("fetched : ");
        suit_print_hex_in_max(fetch_args.ptr, fetch_ret->buf_len, 32);
        printf("\ncallback : %s SUCCESS\n\n", suit_command_sequence_key_to_str(SUIT_DIRECTIVE_FETCH));
    }
    return result;
}

suit_err_t suit_condition_check_content(const suit_component_identifier_t *dst,
                                        UsefulBufC content)
{
    char filename[SUIT_MAX_NAME_LENGTH];
    suit_err_t result = suit_component_identifier_to_filename(dst, SUIT_MAX_NAME_LENGTH, filename);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    UsefulBuf buf;
    buf.ptr = malloc(content.len + 1);
    if (buf.ptr == NULL) {
        return SUIT_ERR_NO_MEMORY;
    }
    buf.len = read_from_file(filename, buf.ptr, content.len + 1);

    /* see https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest-22#name-suit-condition-check-conten */
    uint8_t residual = 0;
    for (size_t i = 0; i < content.len; i++) {
        residual |= ((uint8_t *)content.ptr)[i] ^ ((uint8_t *)buf.ptr)[i];
    }
    return (residual == 0) ? SUIT_SUCCESS : SUIT_ERR_CONDITION_MISMATCH;
}

suit_err_t suit_condition_image_match(const suit_component_identifier_t *dst,
                                      const suit_digest_t *image_digest,
                                      const uint64_t image_size,
                                      bool condition_match)
{
    char filename[SUIT_MAX_NAME_LENGTH];
    suit_err_t result = suit_component_identifier_to_filename(dst, SUIT_MAX_NAME_LENGTH, filename);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    suit_buf_t buf;
    if (image_size == 0) {
        buf.ptr = malloc(SUIT_MAX_DATA_SIZE);
        if (buf.ptr == NULL) {
            return SUIT_ERR_NO_MEMORY;
        }
        buf.len = read_from_file(filename, buf.ptr, SUIT_MAX_DATA_SIZE);
    }
    else {
        buf.ptr = malloc(image_size + 1);
        if (buf.ptr == NULL) {
            return SUIT_ERR_NO_MEMORY;
        }
        buf.len = read_from_file(filename, buf.ptr, image_size + 1);
        if (buf.len != image_size) {
            return SUIT_ERR_CONDITION_MISMATCH;
        }
    }
    result = suit_verify_digest(&buf, image_digest);
    free(buf.ptr);
    if (result == SUIT_ERR_FAILED_TO_VERIFY) {
        result = SUIT_ERR_CONDITION_MISMATCH;
    }
    return result;
}

suit_err_t __real_suit_condition_callback(suit_condition_args_t condition_args);
suit_err_t __wrap_suit_condition_callback(suit_condition_args_t condition_args)
{
    suit_err_t result = __real_suit_condition_callback(condition_args);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    bool match = true;
    switch (condition_args.condition) {
    /* bstr */
    case SUIT_CONDITION_VENDOR_IDENTIFIER:
    case SUIT_CONDITION_CLASS_IDENTIFIER:
    case SUIT_CONDITION_DEVICE_IDENTIFIER:
        result = SUIT_ERR_NOT_IMPLEMENTED;
    case SUIT_CONDITION_CHECK_CONTENT:
        result = suit_condition_check_content(&condition_args.dst, condition_args.expected.str);
        break;

    /* SUIT_Digest */
    case SUIT_CONDITION_IMAGE_NOT_MATCH:
        match = false;
    case SUIT_CONDITION_IMAGE_MATCH:
        result = suit_condition_image_match(&condition_args.dst, &condition_args.expected.image_digest, condition_args.expected.image_size, match);
        break;

    case SUIT_CONDITION_COMPONENT_SLOT:
    case SUIT_CONDITION_ABORT:
    case SUIT_CONDITION_DEPENDENCY_INTEGRITY:
    case SUIT_CONDITION_IS_DEPENDENCY:
    case SUIT_CONDITION_USE_BEFORE:
    case SUIT_CONDITION_MINIMUM_BATTERY:
    case SUIT_CONDITION_UPDATE_AUTHORIZED:
    case SUIT_CONDITION_VERSION:
    default:
        result = SUIT_ERR_NOT_IMPLEMENTED;
    }

    if (result != SUIT_SUCCESS) {
        printf("callback : error = %s(%d)\n", suit_err_to_str(result), result);
        printf("callback : suppress it for testing.\n\n");
        result = SUIT_SUCCESS;
    }
    else {
        printf("callback : %s SUCCESS\n\n", suit_command_sequence_key_to_str(condition_args.condition));
    }
    return result;
}

suit_err_t __real_suit_invoke_callback(suit_invoke_args_t invoke_args);
suit_err_t __wrap_suit_invoke_callback(suit_invoke_args_t invoke_args)
{
    suit_err_t result = __real_suit_invoke_callback(invoke_args);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    char cd[] = "./tmp";
    char command[SUIT_MAX_NAME_LENGTH];
    snprintf(command, invoke_args.args_len + 1, "%s", (char *)invoke_args.args);

    pid_t pid = fork();
    if (pid == 0) {
        /* child */
        int ret;
        ret = chdir(cd);
        if (ret != 0) {
            printf("(callback) Failed to set working directory at \"%s\"\n", cd);
            return SUIT_ERR_FATAL;
        }
        printf("<callback>$ cd %s\n", cd);
        printf("<callback>$ %s\n", command);
        ret = system(command);
        printf("\n");
        fflush(stdout);
        exit(ret);
    }
    else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("<callback> Command exited with %d\n", WEXITSTATUS(status));
            return SUIT_SUCCESS;
        }
        else {
            printf("<callback> Command terminated %u\n", status);
            return SUIT_ERR_FATAL;
        }
    }
    /* XXX: DO NOT REACH HERE */
    return SUIT_ERR_FATAL;
}

suit_err_t store_component(const char *dst,
                           UsefulBufC src,
                           UsefulBufC encryption_info,
                           suit_mechanism_t mechanisms[])
{
    suit_err_t result = SUIT_SUCCESS;
    UsefulBuf decrypted_payload_buf = NULLUsefulBuf;

    if (!UsefulBuf_IsNULLOrEmptyC(encryption_info)) {
#ifndef LIBCSUIT_DISABLE_ENCRYPTION
        decrypted_payload_buf.ptr = malloc(SUIT_MAX_DATA_SIZE);
        decrypted_payload_buf.len = SUIT_MAX_DATA_SIZE;
        UsefulBufC tmp = NULLUsefulBufC;
        for (size_t i = 0; i < SUIT_MAX_KEY_NUM; i++) {
            result = suit_decrypt_cose_encrypt(src, encryption_info, decrypted_payload_buf, &mechanisms[i], &tmp);
            if (result == SUIT_SUCCESS) {
                break;
            }
        }
        if (result != SUIT_SUCCESS || UsefulBuf_IsNULLOrEmptyC(tmp)) {
            result = SUIT_ERR_FAILED_TO_DECRYPT;
            goto out;
        }
        src = tmp;
#else
        return SUIT_ERR_NOT_IMPLEMENTED;
#endif /* LIBCSUIT_DISABLE_ENCRYPTION */
    }

    size_t len = write_to_file(dst, src.ptr, src.len);
    if (len != src.len) {
        result = SUIT_ERR_FATAL;
        goto out;
    }
out:
    if (decrypted_payload_buf.ptr != NULL) {
        free(decrypted_payload_buf.ptr);
    }
    return result;
}

suit_err_t copy_component(const char *dst,
                          const char *src,
                          UsefulBufC encryption_info,
                          suit_mechanism_t mechanisms[])
{
    UsefulBuf buf;
    buf.ptr = malloc(SUIT_MAX_DATA_SIZE);
    if (buf.ptr == NULL) {
        return SUIT_ERR_NO_MEMORY;
    }
    buf.len = SUIT_MAX_DATA_SIZE;
    size_t len = read_from_file(src, buf.ptr, buf.len);
    if (len >= buf.len) {
        return SUIT_ERR_NO_MEMORY;
    }
    buf.len = len;
    suit_err_t result = store_component(dst, UsefulBuf_Const(buf), encryption_info, mechanisms);
    free(buf.ptr);
    return result;
}

suit_err_t swap_component(const char *dst,
                          const char *src)
{
    char tmp[SUIT_MAX_NAME_LENGTH];
    size_t len = snprintf(tmp, SUIT_MAX_NAME_LENGTH, "%s.tmp", dst);
    if (len == SUIT_MAX_NAME_LENGTH) {
        return SUIT_ERR_NO_MEMORY;
    }
    if (rename(tmp, dst) != 0 || rename(dst, src) != 0 || rename(src, tmp)) {
        return SUIT_ERR_FATAL;
    }
    return SUIT_SUCCESS;
}

suit_err_t __real_suit_store_callback(suit_store_args_t store_args);
suit_err_t __wrap_suit_store_callback(suit_store_args_t store_args)
{
    suit_err_t result = __real_suit_store_callback(store_args);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    char dst[SUIT_MAX_NAME_LENGTH];
    char src[SUIT_MAX_NAME_LENGTH];
    result = suit_component_identifier_to_filename(&store_args.dst, SUIT_MAX_NAME_LENGTH, dst);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    switch (store_args.operation) {
    case SUIT_STORE:
        result = store_component(dst, store_args.src_buf, store_args.encryption_info, store_args.mechanisms);
        break;
    case SUIT_COPY:
        result = suit_component_identifier_to_filename(&store_args.src, SUIT_MAX_NAME_LENGTH, src);
        if (result == SUIT_SUCCESS) {
            result = copy_component(dst, src, store_args.encryption_info, store_args.mechanisms);
        }
        break;
    case SUIT_SWAP:
        result = suit_component_identifier_to_filename(&store_args.src, SUIT_MAX_NAME_LENGTH, src);
        if (result == SUIT_SUCCESS) {
            result = swap_component(dst, src);
            //result = (renameat2(AT_FDCWD, dst, AT_FDCWD, src, RENAME_EXCHANGE) == 0) ? SUIT_SUCCESS : SUIT_ERR_FATAL;
        }
        break;
    case SUIT_UNLINK:
        result = (unlink(dst) == 0) ? SUIT_SUCCESS : SUIT_ERR_FATAL;
        break;
    }
    if (result != SUIT_SUCCESS) {
        printf("callback : error = %s(%d)\n", suit_err_to_str(result), result);
    }
    else {
        printf("callback : %s SUCCESS\n\n", suit_store_key_to_str(store_args.operation));
    }
    return result;
}

void display_help(const char *argv0, bool on_error)
{
    if (on_error) {
        fprintf(stderr, "Usage: %s <manifest_filename> [-u <URL> -f <filename> ...]\n", argv0);
        exit(EXIT_FAILURE);
    }
    printf("Usage: %s <manifest_filename> [-u <URL> -f <filename> ...]\n", argv0);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    int opt;
    int pair_count = 0;

    while ((opt = getopt(argc, argv, "u:f:h")) != -1) {
        switch (opt) {
        case 'u':
            if (pair_count < SUIT_MAX_ARRAY_LENGTH) {
                pairs[pair_count].url = optarg;
            }
            break;
        case 'f':
            if (pair_count < SUIT_MAX_ARRAY_LENGTH) {
                if (pairs[pair_count].url == NULL) {
                    display_help(argv[0], true);
                }
                pairs[pair_count].filename = optarg;
                pair_count++;
            }
            break;
        case 'h':
            display_help(argv[0], false);
            break;
        default:
            display_help(argv[0], true);
            break;
        }
    }

    suit_err_t result = 0;

    int num_key = 0;
    #define NUM_PUBLIC_KEYS_FOR_ECDH        2
    UsefulBufC public_keys_for_ecdh[NUM_PUBLIC_KEYS_FOR_ECDH] = {
        trust_anchor_prime256v1_cose_key_public,
        delegated_authority_es256_cose_key_public,
    };
    #define NUM_SECRET_KEYS_FOR_MAC         1
    UsefulBufC secret_keys_for_mac[NUM_SECRET_KEYS_FOR_MAC] = {
        trust_anchor_hmac256_cose_key_secret,
    };
    #define NUM_SECRET_KEYS_FOR_AESKW       1
    UsefulBufC secret_keys_for_aeskw[NUM_SECRET_KEYS_FOR_AESKW] = {
        trust_anchor_a128_cose_key_secret,
    };
    #define NUM_PRIVATE_KEYS_FOR_ESDH       1
    UsefulBufC private_keys_for_esdh[NUM_PRIVATE_KEYS_FOR_ESDH] = {
        device_es256_cose_key_private,
    };

    suit_inputs_t *suit_inputs = calloc(1, sizeof(suit_inputs_t) + SUIT_MAX_DATA_SIZE);
    if (suit_inputs == NULL) {
        printf("main : Failed to allocate memory for suit_inputs\n");
        return EXIT_FAILURE;
    }
    suit_inputs->left_len = SUIT_MAX_DATA_SIZE;
    suit_inputs->ptr = suit_inputs->buf;

    printf("\nmain : Read public keys.\n");
    for (int i = 0; i < NUM_PUBLIC_KEYS_FOR_ECDH; i++) {
        suit_inputs->mechanisms[num_key].key.cose_algorithm_id = T_COSE_ALGORITHM_ES256;
        result = suit_set_suit_key_from_cose_key(public_keys_for_ecdh[i], &suit_inputs->mechanisms[num_key].key);
        if (result != SUIT_SUCCESS) {
            printf("\nmain : Failed to initialize public key. %s(%d)\n", suit_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        suit_inputs->mechanisms[num_key].use = true;
        suit_inputs->mechanisms[num_key].cose_tag = CBOR_TAG_COSE_SIGN1;
        num_key++;
    }

#ifndef LIBCSUIT_DISABLE_MAC
    printf("\nmain : Read secret keys.\n");
    for (int i = 0; i < NUM_SECRET_KEYS_FOR_MAC; i++) {
        suit_inputs->mechanisms[num_key].key.cose_algorithm_id = T_COSE_ALGORITHM_HMAC256;
        result = suit_set_suit_key_from_cose_key(secret_keys_for_mac[i], &suit_inputs->mechanisms[num_key].key);
        if (result != SUIT_SUCCESS) {
            printf("\nmain : Failed to initialize secret key. %s(%d)\n", suit_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        suit_inputs->mechanisms[num_key].use = true;
        suit_inputs->mechanisms[num_key].cose_tag = CBOR_TAG_COSE_MAC0;
        num_key++;
    }
#endif /* LIBCSUIT_DISABLE_MAC */

#ifndef LIBCSUIT_DISABLE_ENCRYPTION
    printf("\nmain : Read secret keys for AES-KW.\n");
    for (size_t i = 0; i < NUM_SECRET_KEYS_FOR_AESKW; i++) {
        suit_inputs->mechanisms[num_key].key.cose_algorithm_id = T_COSE_ALGORITHM_A128KW;
        result = suit_set_suit_key_from_cose_key(secret_keys_for_aeskw[i], &suit_inputs->mechanisms[num_key].key);
        if (result != SUIT_SUCCESS) {
            printf("\nmain : Failed to initialize sycret key. %s(%d)\n", suit_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        suit_inputs->mechanisms[num_key].use = true;
        suit_inputs->mechanisms[num_key].cose_tag = CBOR_TAG_COSE_ENCRYPT;
        num_key++;
    }
    printf("\nmain : Load private keys for ES-ECDH.\n");
    for (size_t i = 0; i < NUM_PRIVATE_KEYS_FOR_ESDH; i++) {
        suit_inputs->mechanisms[num_key].key.cose_algorithm_id = T_COSE_ALGORITHM_ECDH_ES_A128KW;
        result = suit_set_suit_key_from_cose_key(private_keys_for_esdh[i], &suit_inputs->mechanisms[num_key].key);
        if (result != SUIT_SUCCESS) {
            printf("\nmain : Failed to initialize public key. %s(%d)\n", suit_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        suit_inputs->mechanisms[num_key].use = true;
        suit_inputs->mechanisms[num_key].cose_tag = CBOR_TAG_COSE_ENCRYPT;
        num_key++;
    }
#endif

    suit_inputs->key_len = num_key;

    // Read manifest file.
    printf("\nmain : Read Manifest file.\n");
    suit_inputs->manifest.ptr = suit_inputs->buf;
    suit_inputs->manifest.len = read_from_file(argv[optind], suit_inputs->buf, SUIT_MAX_DATA_SIZE);
    if (suit_inputs->manifest.len <= 0) {
        printf("main : Failed to read Manifest file. (%s)\n", argv[1]);
        return EXIT_FAILURE;
    }
    suit_inputs->left_len -= suit_inputs->manifest.len;

    // Process manifest file.
    printf("\nmain : Process Manifest file.\n");
    suit_inputs->process_flags.all = UINT16_MAX;
    suit_inputs->process_flags.uninstall = 0;
    result = suit_process_envelope(suit_inputs);
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to install and invoke a Manifest file. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    free(suit_inputs);

    return EXIT_SUCCESS;
}
