/*
 * Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include "csuit/suit_manifest_print.h"
#include "suit_examples_common.h"

#define BUFFER_SIZE 1024

int main(int argc, const char *argv[])
{
    const char *cose_file_name = NULL;

    if (argc < 2) {
        printf("%s <COSE file path>\n", argv[0]);
        return EXIT_FAILURE;
    }
    cose_file_name = argv[1];

    // Read cose file.
    uint8_t buf[BUFFER_SIZE];
    suit_buf_t cose_buf = {
        .ptr = buf,
        .len = BUFFER_SIZE
    };

    printf("main : Read CBOR file.\n");
    cose_buf.len = read_from_file(cose_file_name, cose_buf.ptr, cose_buf.len);
    if (cose_buf.len == 0) {
        printf("main : Failed to read CBOR file.\n");
        return EXIT_FAILURE;
    }
    suit_print_hex_in_max(cose_buf.ptr, cose_buf.len, 512);
    printf("\n");

    // Print cose file.
    printf("main : Print COSE file.\n");
    suit_err_t result = suit_print_encryption_info(&cose_buf, 0, 2);
    printf("\n");
    if (result != SUIT_SUCCESS) {
        printf("main : Failed to print COSE. %s(%d)\n", suit_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
