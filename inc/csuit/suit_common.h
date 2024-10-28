/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*!
    \file   suit_common.h
    \brief  Declarations of common parameters and functions.
 */

#ifndef SUIT_COMMON_H
#define SUIT_COMMON_H

#include "csuit/config.h"

#include "qcbor/qcbor.h"
#include "qcbor/qcbor_spiffy_decode.h"

#if defined(LIBCSUIT_USE_T_COSE_1)
#include "t_cose/t_cose_common.h"
#else
#include "t_cose/t_cose_key.h"
#endif /* LIBCSUIT_USE_T_COSE_1 */

#ifdef __cplusplus
extern "C" {
#endif

#define BIT(nr) (1UL << (nr))

extern uint64_t LIBCSUIT_SUPPORTED_VERSIONS[];
extern size_t LIBCSUIT_SUPPORTED_VERSIONS_LEN;

/*!
    \brief  libcsuit SUCCESS/ERROR result
 */
typedef enum {
    SUIT_SUCCESS = 0,                   /*! success */

    SUIT_ERR_FATAL,                     /*! unknown error, e.g. occurred out of SUIT */

    SUIT_ERR_NOT_A_SUIT_MANIFEST,       /*! the input data is tagged but not SUIT_Manifest_Tagged */

    SUIT_ERR_NO_MEMORY,                 /*! exceed the allocated memory */
    SUIT_ERR_NOT_FOUND,                 /*! the specified content does not exist or unaccessible */
    SUIT_ERR_PARAMETER_NOT_FOUND,       /*! required suit-parameter does not exist */
    SUIT_ERR_AUTHENTICATION_NOT_FOUND,  /*! suit-authentication-wrapper does not exist */
    SUIT_ERR_MANIFEST_KEY_NOT_FOUND,    /*! other SUIT_Envelope key does not exist */

    SUIT_ERR_INVALID_TYPE_OF_VALUE,     /*! type of an item is not expected */
    SUIT_ERR_INVALID_VALUE,             /*! the input value is invalid */
    SUIT_ERR_INVALID_TYPE_OF_KEY,       /*! type of a key is not expected */
    SUIT_ERR_INVALID_KEY,               /*! invalid map key */
    SUIT_ERR_NO_MORE_ITEMS,             /*! mandatory items in array did not appeare */
    SUIT_ERR_NOT_IMPLEMENTED,           /*! parser is not implemented */
    SUIT_ERR_FAILED_TO_VERIFY,          /*! COSE or hash digest verification failure */
    SUIT_ERR_FAILED_TO_SIGN,            /*! COSE signing failure */
    SUIT_ERR_FAILED_TO_DECRYPT,         /*! COSE decryption failure */
    SUIT_ERR_FAILED_TO_ENCRYPT,         /*! COSE encryption failure */
    SUIT_ERR_FAILED_TO_VERIFY_DELEGATION,   /*! suit-delegation is not signed by trust-anchor */
    SUIT_ERR_CONDITION_MISMATCH,        /*! suit-condition-* failed */

    SUIT_ERR_REDUNDANT,                 /*! same key appears, e.g. suit-install exists in both suit-manifest and suit-envelope */
    SUIT_ERR_NOT_CANONICAL_CBOR,        /*! not encoded with canonical CBOR */
    SUIT_ERR_INVALID_MANIFEST_VERSION,  /*! does not support SUIT Manifest version specified by suit-manifest-version */
    SUIT_ERR_TRY_OUT,                   /*! all command_sequence in try-each section failed */
    SUIT_ERR_ABORT,                     /*! abort to execute, mainly for libcsuit internal */
} suit_err_t;

/*! \brief abort immediately on any error */

typedef union {
    uint8_t val;
    struct {
        /*! \brief through but report on verification failure */
        uint8_t SKIP_SIGN_FAILURE: 1;
        /*! \brief through unknown or unimplemented element(key or value) */
        uint8_t SKIP_UNKNOWN_ELEMENT: 1;
        /*! \brief ignore missing authentication-wrapper */
        uint8_t SKIP_AUTHENTICATION_FAILURE: 1;
        /*! \brief allow not well-formed SUIT Manifest */
        uint8_t ALLOW_NOT_CANONICAL_CBOR: 1;
    };
} suit_decode_mode_t;
#define SUIT_DECODE_MODE_STRICT ((suit_decode_mode_t){0})
#define SUIT_DECODE_MODE_SKIP_ANY_ERROR ((suit_decode_mode_t){(uint8_t)UINT8_MAX})

#ifndef SUIT_MAX_ARRAY_LENGTH
#define SUIT_MAX_ARRAY_LENGTH           20
#endif

#ifndef SUIT_MAX_KEY_NUM
#define SUIT_MAX_KEY_NUM                6 /* must be <=64 */
#endif

#ifndef SUIT_MAX_NAME_LENGTH
#define SUIT_MAX_NAME_LENGTH            256 /* the length of path or name such as component_identifier */
#endif

#ifndef SUIT_MAX_URI_LENGTH
#define SUIT_MAX_URI_LENGTH             256 /* the length of uri to fetch something */
#endif

#ifndef SUIT_MAX_COMPONENT_NUM
#define SUIT_MAX_COMPONENT_NUM          3
#endif

#ifndef SUIT_MAX_DEPENDENCY_NUM
#define SUIT_MAX_DEPENDENCY_NUM         1
#endif

#define SUIT_MAX_INDEX_NUM (SUIT_MAX_COMPONENT_NUM + SUIT_MAX_DEPENDENCY_NUM)

#ifndef SUIT_MAX_ARGS_LENGTH
#define SUIT_MAX_ARGS_LENGTH            64
#endif

#ifndef SUIT_MAX_DATA_SIZE
#define SUIT_MAX_DATA_SIZE              (8 * 1024 * 1024)
#endif

typedef enum cbor_tag_key {
    COSE_TAG_INVALID        = 0,
    COSE_SIGN_TAG           = 98,
    COSE_SIGN1_TAG          = 18,
    COSE_ENCRYPT_TAG        = 96,
    COSE_ENCRYPT0_TAG       = 16,
    COSE_MAC_TAG            = 97,
    COSE_MAC0_TAG           = 17,
    COSE_KEY_TAG            = 101,
    COSE_KEY_SET_TAG        = 102,
    SUIT_ENVELOPE_TAG       = 107,
} cbor_tag_key_t;

/*!
    \brief      Distinguish the TAG of the COSE binary.

    \param[in]  signed_cose     Pointer and length of COSE signed cbor.

    \return     This returns one of the error codes defined by \ref cose_tag_key_t.
 */
cbor_tag_key_t suit_judge_cose_tag_from_buf(const UsefulBufC signed_cose);

typedef struct suit_key {
    const unsigned char *private_key;
    size_t private_key_len;
    const unsigned char *public_key;
    size_t public_key_len;
    int cose_algorithm_id;
    struct t_cose_key cose_key;
} suit_key_t;

typedef struct suit_mechanism {
    cbor_tag_key_t cose_tag; // COSE_Sign1, COSE_Sign, COSE_Encrypt0, COSE_Encrypt, etc.
    suit_key_t key;
    UsefulBufC kid;
    suit_key_t rkey; // receiver's key, e.g. ECDH
    UsefulBufC rkid;
    bool use;
} suit_mechanism_t;


typedef enum suit_envelope_key {
    SUIT_INTEGRATED_PAYLOAD             = -1,
    SUIT_ENVELOPE_KEY_INVALID           = 0,
    SUIT_DELEGATION                     = 1,
    SUIT_AUTHENTICATION                 = 2,
    SUIT_MANIFEST                       = 3,
    SUIT_SEVERED_PAYLOAD_FETCH          = 16,
    SUIT_SEVERED_INSTALL                = 20,
    SUIT_SEVERED_TEXT                   = 23,

    /* draft-ietf-update-management */
    SUIT_SEVERED_COSWID                 = 14,

    /* draft-ietf-suit-trust-domains */
    SUIT_SEVERED_DEPENDENCY_RESOLUTION  = 15,
    SUIT_SEVERED_CANDIDATE_VERIFICATION = 18,
} suit_envelope_key_t;

typedef enum suit_algorithm_id {
    SUIT_ALGORITHM_ID_INVALID           = 0,
    SUIT_ALGORITHM_ID_SHA256            = -16, // cose-alg-sha-256
    SUIT_ALGORITHM_ID_SHAKE128          = -18, // cose-alg-shake128
    SUIT_ALGORITHM_ID_SHA384            = -43, // cose-alg-sha-384
    SUIT_ALGORITHM_ID_SHA512            = -44, // cose-alg-sha-512
    SUIT_ALGORITHM_ID_SHAKE256          = -45, // cose-alg-shake256
} suit_algorithm_id_t;

typedef enum suit_manifest_key {
    SUIT_MANIFEST_KEY_INVALID           = 0,

    /* draft-ietf-suit-manifest */
    SUIT_MANIFEST_VERSION               = 1,
    SUIT_MANIFEST_SEQUENCE_NUMBER       = 2,
    SUIT_COMMON                         = 3,
    SUIT_REFERENCE_URI                  = 4,
    SUIT_VALIDATE                       = 7,
    SUIT_LOAD                           = 8,
    SUIT_INVOKE                         = 9,
    SUIT_PAYLOAD_FETCH                  = 16,
    SUIT_INSTALL                        = 20,
    SUIT_TEXT                           = 23,

    /* draft-ietf-suit-update-management */
    SUIT_SET_VERSION                    = 6,
    SUIT_COSWID                         = 14,

    /* draft-ietf-suit-trust-domains */
    SUIT_MANIFEST_COMPONENT_ID          = 5,
    SUIT_DEPENDENCY_RESOLUTION          = 15,
    SUIT_CANDIDATE_VERIFICATION         = 18,
    SUIT_UNINSTALL                      = 24,
} suit_manifest_key_t;

typedef enum suit_common_key {
    SUIT_COMMON_KEY_INVALID             = 0,
    SUIT_COMPONENTS                     = 2,
    SUIT_SHARED_SEQUENCE                = 4,

    /* draft-ietf-suit-trust-domains */
    SUIT_DEPENDENCIES                   = 1, // $$SUIT_Common-extensions
} suit_common_key_t;

typedef enum suit_dependency_key {
    SUIT_DEPENDENCY_INVALID             = 0,
    SUIT_DEPENDENCY_PREFIX              = 1,
} suit_dependency_key_t;

typedef enum suit_con_dir_key {
    SUIT_CONDITION_INVALID              = 0,
    SUIT_DIRECTIVE_INVALID              = 0,

    /* draft-ietf-suit-manifest */
    SUIT_CONDITION_VENDOR_IDENTIFIER    = 1,
    SUIT_CONDITION_CLASS_IDENTIFIER     = 2,
    SUIT_CONDITION_IMAGE_MATCH          = 3,
    SUIT_CONDITION_COMPONENT_SLOT       = 5,
    SUIT_CONDITION_CHECK_CONTENT        = 6,
    SUIT_CONDITION_ABORT                = 14,
    SUIT_CONDITION_DEVICE_IDENTIFIER    = 24,
    SUIT_DIRECTIVE_SET_COMPONENT_INDEX  = 12,
    SUIT_DIRECTIVE_TRY_EACH             = 15,
    SUIT_DIRECTIVE_WRITE                = 18,
    SUIT_DIRECTIVE_OVERRIDE_PARAMETERS  = 20,
    SUIT_DIRECTIVE_FETCH                = 21,
    SUIT_DIRECTIVE_COPY                 = 22,
    SUIT_DIRECTIVE_INVOKE               = 23,
    SUIT_DIRECTIVE_SWAP                 = 31,
    SUIT_DIRECTIVE_RUN_SEQUENCE         = 32,

    /* draft-ietf-suit-update-management */
    SUIT_CONDITION_USE_BEFORE           = 4,
    SUIT_CONDITION_IMAGE_NOT_MATCH      = 25,
    SUIT_CONDITION_MINIMUM_BATTERY      = 26,
    SUIT_CONDITION_UPDATE_AUTHORIZED    = 27,
    SUIT_CONDITION_VERSION              = 28,
    SUIT_DIRECTIVE_WAIT                 = 29,
    SUIT_DIRECTIVE_OVERRIDE_MULTIPLE    = 34,
    SUIT_DIRECTIVE_COPY_PARAMS          = 35,

    /* draft-ietf-suit-trust-domains */
    SUIT_CONDITION_DEPENDENCY_INTEGRITY = 7,
    SUIT_CONDITION_IS_DEPENDENCY        = 8,
    SUIT_DIRECTIVE_PROCESS_DEPENDENCY   = 11,
    SUIT_DIRECTIVE_SET_PARAMETERS       = 19,
    SUIT_DIRECTIVE_UNLINK               = 33,
} suit_con_dir_key_t;

#define SUIT_SEVERABLE_INVALID               0 // 0b00000000
#define SUIT_SEVERABLE_IN_MANIFEST           1 // 0b00000001
#define SUIT_SEVERABLE_IN_ENVELOPE           2 // 0b00000010
#define SUIT_SEVERABLE_EXISTS              127 // 0b01111111
#define SUIT_SEVERABLE_IS_VERIFIED         128 // 0b10000000

typedef enum suit_wait_event_key {
    SUIT_WAIT_EVENT_INVALID                 = 0,

    /* draft-ietf-suit-update-management */
    SUIT_WAIT_EVENT_AUTHORIZATION           = 1,
    SUIT_WAIT_EVENT_POWER                   = 2,
    SUIT_WAIT_EVENT_NETWORK                 = 3,
    SUIT_WAIT_EVENT_OTHER_DEVICE_VERSION    = 4,
    SUIT_WAIT_EVENT_TIME                    = 5,
    SUIT_WAIT_EVENT_TIME_OF_DAY             = 6,
    SUIT_WAIT_EVENT_DAY_OF_WEEK             = 7,
} suit_wait_event_key_t;

/* draft-suit-update-management */
#define SUIT_WAIT_EVENT_CONTAINS_AUTHORIZATION BIT(SUIT_WAIT_EVENT_AUTHORIZATION)
#define SUIT_WAIT_EVENT_CONTAINS_POWER BIT(SUIT_WAIT_EVENT_POWER)
#define SUIT_WAIT_EVENT_CONTAINS_NETWORK BIT(SUIT_WAIT_EVENT_NETWORK)
#define SUIT_WAIT_EVENT_CONTAINS_OTHER_DEVICE_VERSION BIT(SUIT_WAIT_EVENT_OTHER_DEVICE_VERSION)
#define SUIT_WAIT_EVENT_CONTAINS_TIME BIT(SUIT_WAIT_EVENT_TIME)
#define SUIT_WAIT_EVENT_CONTAINS_TIME_OF_DAY BIT(SUIT_WAIT_EVENT_TIME_OF_DAY)
#define SUIT_WAIT_EVENT_CONTAINS_DAY_OF_WEEK BIT(SUIT_WAIT_EVENT_DAY_OF_WEEK)

typedef enum suit_parameter_key {
    SUIT_PARAMETER_INVALID              = 0,

    /* draft-ietf-suit-manifest */
    SUIT_PARAMETER_VENDOR_IDENTIFIER    = 1,
    SUIT_PARAMETER_CLASS_IDENTIFIER     = 2,
    SUIT_PARAMETER_IMAGE_DIGEST         = 3,
    SUIT_PARAMETER_COMPONENT_SLOT       = 5,
    SUIT_PARAMETER_STRICT_ORDER         = 12,
    SUIT_PARAMETER_SOFT_FAILURE         = 13,
    SUIT_PARAMETER_IMAGE_SIZE           = 14,
    SUIT_PARAMETER_CONTENT              = 18,
    SUIT_PARAMETER_URI                  = 21,
    SUIT_PARAMETER_SOURCE_COMPONENT     = 22,
    SUIT_PARAMETER_INVOKE_ARGS          = 23,
    SUIT_PARAMETER_DEVICE_IDENTIFIER    = 24,
    SUIT_PARAMETER_FETCH_ARGS           = 30, /* XXX */

    /* draft-ietf-suit-update-management */
    SUIT_PARAMETER_USE_BEFORE           = 4,
    SUIT_PARAMETER_MINIMUM_BATTERY      = 26,
    SUIT_PARAMETER_UPDATE_PRIORITY      = 27,
    SUIT_PARAMETER_VERSION              = 28,
    SUIT_PARAMETER_WAIT_INFO            = 29,

    /* draft-ietf-suit-firmware-encryption */
    SUIT_PARAMETER_ENCRYPTION_INFO      = 19,
} suit_parameter_key_t;

/* draft-suit-manifest */
#define SUIT_PARAMETER_CONTAINS_VENDOR_IDENTIFIER BIT(SUIT_PARAMETER_VENDOR_IDENTIFIER)
#define SUIT_PARAMETER_CONTAINS_CLASS_IDENTIFIER BIT(SUIT_PARAMETER_CLASS_IDENTIFIER)
#define SUIT_PARAMETER_CONTAINS_IMAGE_DIGEST BIT(SUIT_PARAMETER_IMAGE_DIGEST)
#define SUIT_PARAMETER_CONTAINS_COMPONENT_SLOT BIT(SUIT_PARAMETER_COMPONENT_SLOT)
#define SUIT_PARAMETER_CONTAINS_STRICT_ORDER BIT(SUIT_PARAMETER_STRICT_ORDER)
#define SUIT_PARAMETER_CONTAINS_SOFT_FAILURE BIT(SUIT_PARAMETER_SOFT_FAILURE)
#define SUIT_PARAMETER_CONTAINS_IMAGE_SIZE BIT(SUIT_PARAMETER_IMAGE_SIZE)
#define SUIT_PARAMETER_CONTAINS_CONTENT BIT(SUIT_PARAMETER_CONTENT)
#define SUIT_PARAMETER_CONTAINS_URI BIT(SUIT_PARAMETER_URI)
#define SUIT_PARAMETER_CONTAINS_SOURCE_COMPONENT BIT(SUIT_PARAMETER_SOURCE_COMPONENT)
#define SUIT_PARAMETER_CONTAINS_INVOKE_ARGS BIT(SUIT_PARAMETER_INVOKE_ARGS)
#define SUIT_PARAMETER_CONTAINS_DEVICE_IDENTIFIER BIT(SUIT_PARAMETER_DEVICE_IDENTIFIER)
#define SUIT_PARAMETER_CONTAINS_FETCH_ARGS BIT(SUIT_PARAMETER_FETCH_ARGS)

/* draft-suit-update-management */
#define SUIT_PARAMETER_CONTAINS_USE_BEFORE BIT(SUIT_PARAMETER_USE_BEFORE)
#define SUIT_PARAMETER_CONTAINS_MINIMUM_BATTERY BIT(SUIT_PARAMETER_MINIMUM_BATTERY)
#define SUIT_PARAMETER_CONTAINS_UPDATE_PRIORITY BIT(SUIT_PARAMETER_UPDATE_PRIORITY)
#define SUIT_PARAMETER_CONTAINS_VERSION BIT(SUIT_PARAMETER_VERSION)
#define SUIT_PARAMETER_CONTAINS_WAIT_INFO BIT(SUIT_PARAMETER_WAIT_INFO)

/* draft-suit-trust-domains */
#define SUIT_PARAMETER_CONTAINS_ENCRYPTION_INFO BIT(SUIT_PARAMETER_ENCRYPTION_INFO)


typedef enum suit_condition_version_comparison_types {
    SUIT_CONDITION_VERSION_COMPARISON_INVALID       = 0,

    /* draft-ietf-suit-update-management */
    SUIT_CONDITION_VERSION_COMPARISON_GREATER       = 1,
    SUIT_CONDITION_VERSION_COMPARISON_GREATER_EQUAL = 2,
    SUIT_CONDITION_VERSION_COMPARISON_EQUAL         = 3,
    SUIT_CONDITION_VERSION_COMPARISON_LESSER_EQUAL  = 4,
    SUIT_CONDITION_VERSION_COMPARISON_LESSER        = 5,
} suit_condition_version_comparison_types_t;

/* TODO: needed? just UsefulBufC UsefulBuf_IsNULLC(enctyption_info) may work well */
typedef enum suit_info_key {
    SUIT_INFO_DEFAULT               = 0,
    SUIT_INFO_ENCRYPTION            = 1,
} suit_info_key_t;

typedef enum suit_text_key {
    SUIT_TEXT_TYPE_INVALID          = 0,

    /* draft-ietf-manifest-spec */
    SUIT_TEXT_MANIFEST_DESCRIPTION  = 1,
    SUIT_TEXT_UPDATE_DESCRIPTION    = 2,
    SUIT_TEXT_MANIFEST_JSON_SOURCE  = 3,
    SUIT_TEXT_MANIFEST_YAML_SOURCE  = 4,
} suit_text_key_t;

typedef enum suit_text_component_key {
    SUIT_TEXT_CONTENT_INVALID       = 0,

    /* draft-ietf-manifest-spec */
    SUIT_TEXT_VENDOR_NAME           = 1,
    SUIT_TEXT_MODEL_NAME            = 2,
    SUIT_TEXT_VENDOR_DOMAIN         = 3,
    SUIT_TEXT_MODEL_INFO            = 4,
    SUIT_TEXT_COMPONENT_DESCRIPTION = 5,
    SUIT_TEXT_COMPONENT_VERSION     = 6,

    /* draft-ietf-suit-update-management */
    SUIT_TEXT_VERSION_REQUIRED      = 7,
    SUIT_TEXT_CURRENT_VERSION       = 8,
} suit_text_component_key_t;

/* for suit-parameter-strict-order */
typedef enum suit_parameter_bool {
    SUIT_PARAMETER_DEFAULT          = 0,
    SUIT_PARAMETER_TRUE             = 1,
    SUIT_PARAMETER_FALSE            = 2,
} suit_parameter_bool_t;

/*
 * bstr
 */
typedef struct suit_buf {
    size_t                          len;
    uint8_t                         *ptr;
} suit_buf_t;

// COSE_Encrypt_Tagged/COSE_Encrypt0_Tagged
typedef struct suit_encryption_info {
    suit_buf_t cose_encrypt_payload;
    //? TODO
} suit_encryption_info_t;

/*
 * SUIT_Digest
 */
typedef struct suit_digest {
    suit_algorithm_id_t             algorithm_id;
    suit_buf_t                      bytes;
    // TODO :                       suit-digest-parameters
} suit_digest_t;

/*
 * SUIT_Component_Identifier
 */
typedef struct suit_component_identifier {
    size_t                          len;
    suit_buf_t                      identifier[SUIT_MAX_ARRAY_LENGTH];
} suit_component_identifier_t;

typedef struct suit_component_with_index {
    uint8_t                         index;
    suit_component_identifier_t     component;
} suit_component_with_index_t;

/*
 * SUIT_Dependency
 */
typedef struct suit_dependency_metadata {
    suit_component_identifier_t     prefix;
    //TODO:                         $$SUIT_Dependency-extensions
} suit_dependency_metadata_t;

/*
 * SUIT_Dependency_Metadata
 */
typedef struct suit_dependency {
    uint8_t                         index;
    suit_dependency_metadata_t      dependency_metadata;
} suit_dependency_t;

/*
 * SUIT_Dependencies
 */
typedef struct suit_dependencies {
    size_t              len;
    suit_dependency_t   dependency[SUIT_MAX_DEPENDENCY_NUM];
} suit_dependencies_t;

/*
 * [ + int64 ]
 */
typedef struct suit_int64_array {
    size_t len;
    int64_t int64[SUIT_MAX_ARRAY_LENGTH];
} suit_int64_array_t;

/*
 * SUIT_Parameter_Version_Match
 */
typedef struct suit_version_match {
    suit_condition_version_comparison_types_t   type;
    suit_int64_array_t                          value;
} suit_version_match_t;

/*
 * SUIT_Parameters
 */
typedef struct suit_parameters {
    int64_t                         label;
    union {
        suit_buf_t                  string;
        int64_t                     int64;
        uint64_t                    uint64;
        bool                        boolean;
        bool                        isNull;
        suit_digest_t               digest;
        suit_version_match_t        version_match;
    } value;
} suit_parameters_t;

/*
 * [+ SUIT_Parameters]
 */
typedef struct suit_parameters_list {
    size_t                          len;
    uint8_t                         index;  // for SUIT_Override_Mult_Arg
    suit_parameters_t               params[SUIT_MAX_ARRAY_LENGTH];
} suit_parameters_list_t;

/*
 * IndexArg = uint // true // [+ uint ]
 */
typedef struct suit_index {
    uint8_t len;
    uint8_t index[SUIT_MAX_COMPONENT_NUM + SUIT_MAX_DEPENDENCY_NUM];
} suit_index_t;

typedef struct suit_copy_params {
    uint8_t src_index;
    suit_int64_array_t  int64s;
} suit_copy_params_t;

/*
 * (SUIT_Condition // SUIT_Directive // SUIT_Command_Custom)
 */
typedef struct suit_command_sequence_item {
    int64_t                         label;
    union {
        suit_buf_t                  string;
        int64_t                     int64;
        uint64_t                    uint64;
        bool                        isNull;
        suit_index_t                index_arg;
        suit_copy_params_t          copy_params;
        suit_parameters_list_t      params_list;
    } value;
} suit_command_sequence_item_t;

/*
 * SUIT_Command_Sequence or SUIT_Common_Sequence
 */
typedef struct suit_command_sequence {
    size_t                          len;
    suit_command_sequence_item_t    commands[SUIT_MAX_ARRAY_LENGTH];
} suit_command_sequence_t;

/*
 * SUIT_Severable_Command_Sequence
 */
typedef struct suit_sev_command_sequence {
    union {
        suit_digest_t               digest;
        suit_command_sequence_t     cmd_seq;
    } value;
} suit_sev_command_sequence_t;

/*
 * SUIT_Text_Component
 */
typedef struct suit_text_component {
    suit_buf_t  vendor_name;
    suit_buf_t  model_name;
    suit_buf_t  vendor_domain;
    suit_buf_t  model_info;
    suit_buf_t  component_description;
    suit_buf_t  component_version;
    suit_buf_t  version_required;
    // TODO :   $$suit-text-component-key-extensions
} suit_text_component_t;

typedef struct suit_text_component_pair {
    suit_component_identifier_t     key;
    suit_text_component_t           text_component;
} suit_text_component_pair_t;

/*
 * SUIT_Text_LMap
 */
typedef struct suit_text_lmap {
    suit_buf_t                  tag38_ltag;
    size_t                      component_len;
    suit_text_component_pair_t  component[SUIT_MAX_ARRAY_LENGTH];
    suit_buf_t                  manifest_description;
    suit_buf_t                  update_description;
    suit_buf_t                  manifest_json_source;
    suit_buf_t                  manifest_yaml_source;
    // TODO :                   $$suit-text-key-extensions
} suit_text_lmap_t;

/*
 * SUIT_Text_Map
 */
typedef struct suit_text_map {
    size_t                      text_lmaps_len;
    suit_text_lmap_t            text_lmaps[SUIT_MAX_ARRAY_LENGTH];
} suit_text_map_t;

/*
 * SUIT_Authentication_Wrapper
 */
typedef struct suit_authentication_wrapper {
    suit_digest_t                   digest;
    size_t                          signatures_len;
    suit_buf_t                      signatures[SUIT_MAX_ARRAY_LENGTH];
} suit_authentication_wrapper_t;

/*
 * SUIT_Severable_Manifest_Members
 */
typedef struct suit_severable_manifest_members {
    suit_command_sequence_t         dependency_resolution;
    uint8_t                         dependency_resolution_status;
    suit_command_sequence_t         payload_fetch;
    uint8_t                         payload_fetch_status;
    suit_command_sequence_t         install;
    uint8_t                         install_status;
    suit_text_map_t                 text;
    uint8_t                         text_status;
    suit_buf_t                      coswid;
    uint8_t                         coswid_status;
    // TODO :                       $$SUIT_severable-members-extension
} suit_severable_manifest_members_t;

/* SUIT_Severable_Members_Digests */
typedef struct suit_severable_members_digests {
    suit_digest_t                   dependency_resolution;
    suit_digest_t                   payload_fetch;
    suit_digest_t                   install;
    suit_digest_t                   text;
    suit_digest_t                   coswid;
    // TODO :                       $$severable-manifest-members-digests-extensions
} suit_severable_members_digests_t;

/* SUIT_Unseverable_Members */
typedef struct suit_unseverable_members {
    suit_command_sequence_t         validate;
    suit_command_sequence_t         load;
    suit_command_sequence_t         invoke;
    suit_command_sequence_t         uninstall;
    // TODO :                       $$unseverable-manifest-member-extensions
} suit_unseverable_members_t;

/*
 * SUIT_Common
 */
typedef struct suit_common {
    suit_dependencies_t             dependencies;

    uint8_t                         components_len;
    suit_component_with_index_t     components[SUIT_MAX_INDEX_NUM];
    suit_command_sequence_t         shared_seq;
} suit_common_t;

typedef struct suit_delegation_chain {
    size_t                  len;
    UsefulBufC              chain[SUIT_MAX_KEY_NUM];
} suit_delegation_chain_t;

/*
 * SUIT_Delegation
 */
typedef struct suit_delegation {
    size_t                  delegation_chain_num;
    suit_delegation_chain_t delegation_chains[SUIT_MAX_KEY_NUM];
} suit_delegation_t;

/*
 * SUIT_Manifest
 */
typedef struct suit_manifest {
    bool                                is_verified;
    uint64_t                            version;
    uint64_t                            sequence_number;
    suit_common_t                       common;
    suit_buf_t                          reference_uri;
    suit_component_identifier_t         manifest_component_id;
    suit_severable_manifest_members_t   sev_man_mem;
    suit_severable_members_digests_t    sev_mem_dig;
    suit_unseverable_members_t          unsev_mem;
} suit_manifest_t;

typedef struct suit_payload {
    UsefulBufC key;
    uint8_t index;
    UsefulBufC bytes;
} suit_payload_t;

typedef struct suit_payloads {
    size_t  len;
    suit_payload_t payload[SUIT_MAX_ARRAY_LENGTH];
} suit_payloads_t;

/*
 * SUIT_Envelope
 */
typedef struct suit_envelope {
    bool                                tagged;
    suit_delegation_t                   delegation;
    suit_authentication_wrapper_t       wrapper;
    suit_payloads_t                     payloads;
    suit_manifest_t                     manifest;
} suit_envelope_t;

typedef struct suit_encode {
    UsefulBufC manifest;
    // SUIT_SeverableMembers
    UsefulBufC dependency_resolution;
    suit_digest_t dependency_resolution_digest;
    UsefulBufC payload_fetch;
    suit_digest_t payload_fetch_digest;
    UsefulBufC install;
    suit_digest_t install_digest;
    UsefulBufC text;
    suit_digest_t text_digest;
    UsefulBufC coswid;
    suit_digest_t coswid_digest;

    uint8_t *buf;
    size_t pos;
    size_t cur_pos;
    const size_t max_pos;
} suit_encode_t;

/*!
 *  \brief  Describes SUIT_Rep_Policy
 */
typedef union suit_rep_policy {
    uint64_t val;
    struct {
        uint64_t record_on_success: 1;
        uint64_t record_on_failure: 1;
        uint64_t sysinfo_success: 1;
        uint64_t sysinfo_failure: 1;
        uint64_t padding: 60;
    };
} suit_rep_policy_t;

typedef struct suit_reference {
    UsefulBufC      manifest_uri;
    suit_digest_t   manifest_digest;
} suit_reference_t;

typedef struct suit_record {
    suit_component_identifier_t     manifest_id;
    int64_t                         manifest_section;
    uint64_t                        section_offset;
    uint64_t                        component_index;
    suit_parameters_list_t          parameters;
} suit_record_t;

typedef struct suit_report_recoreds {
    size_t          len;
    suit_record_t   suit_records[SUIT_MAX_ARRAY_LENGTH];
} suit_report_records_t;

typedef struct suit_report_result {
    int64_t         result_code;
    suit_record_t   result_record;
} suit_report_result_t;

/*!
 * This passes enough data to construct SUIT_Report.
 */
typedef struct suit_report_args {
    /* SUIT_Report */
    suit_reference_t suit_reference;
    UsefulBufC suit_nonce;
    suit_report_records_t suit_report_records;
    bool success;
    suit_report_result_t suit_report_result;

    suit_envelope_key_t level0;
    union {
        suit_manifest_key_t manifest_key;
    } level1;
    union {
        suit_con_dir_key_t condition_directive;
        suit_common_key_t common_key;
        suit_text_key_t text_key;
    } level2;
    union {
        suit_con_dir_key_t condition_directive;
        suit_parameter_key_t parameter;
        suit_text_component_key_t text_component_key;
    } level3;
    union {
        suit_parameter_key_t parameter;
    } level4;

    QCBORError qcbor_error;
    suit_err_t suit_error;

    suit_rep_policy_t report;
} suit_report_args_t;

/*!
 * This passes enough data to invoke a component.
 */
typedef struct suit_invoke_args {
    suit_component_identifier_t component_identifier;
    /* basically byte-string value, so may not '\0' terminated */
    uint8_t args[SUIT_MAX_ARGS_LENGTH];
    size_t args_len;

    suit_rep_policy_t report;
} suit_invoke_args_t;

typedef enum suit_store_key {
    SUIT_STORE  = 0,
    SUIT_COPY   = 1,
    SUIT_SWAP   = 2,
    SUIT_UNLINK = 3,
} suit_store_key_t;

/*!
 * \brief   Parameters to request storing data as component identifier.
 *
 * Used on suit-directive-write, suit-directive-copy, suit-directive-swap,
 * suit-directive-unlink and suit-directive-fetch (only for integrated payloads).
 */
typedef struct suit_store_args {
    suit_rep_policy_t report;

    /*! Destination SUIT_Component_Identifier */
    suit_component_identifier_t dst;
    /*! Used if \ref operation is SUIT_COPY or SUIT_SWAP */
    suit_component_identifier_t src;
    /*! Pointer and length to the content to be written */
    UsefulBufC src_buf;

    /*! Pointer and length to the COSE_Encrypt */
    UsefulBufC encryption_info;
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM];

    /*! Extra arguments derived from fetch-args */
    UsefulBufC fetch_args;

    /*! SUIT_STORE, SUIT_COPY, SUIT_SWAP, or SUIT_UNLINK */
    suit_store_key_t operation;
} suit_store_args_t;

/*!
 * \brief   Parameters to request fetching and storing data as component identifier.
 *
 * Used on suit-directive-fetch.
 */
typedef struct suit_fetch_args {
    suit_rep_policy_t report;

    /*! Destination SUIT_Component_Identifier */
    suit_component_identifier_t dst;
    /*! Length of uri */
    size_t uri_len;
    /*! URI terminated with '\0' */
    char uri[SUIT_MAX_URI_LENGTH + 1];

    /*!
     *  Pointer to allocated memory in the caller.
     *  This could be NULL if the caller wants callee
     *  to allocate space corresponding to the component identifier.
     */
    void *ptr;
    /*!
     *  The length of the allocated buffer.
     */
    size_t buf_len;

    /*!
     *  Set by suit-parameter-fetch-args.
     */
    UsefulBufC args;

    /* in draft-ietf-suit-firmware-encryption */
    /*! Pointer and length to the COSE_Encrypt */
    UsefulBufC                  encryption_info;
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM];
} suit_fetch_args_t;

/*!
 *  \brief  Returned value from fetch callback.
 *
 *  Used by suit_fetch_callback().
 */
typedef struct suit_fetch_ret {
    /**
     *  The length of the fetched payload.
     */
    size_t buf_len;
} suit_fetch_ret_t;

/*!
 *  \brief  Parameters to request checking condition.
 */
typedef struct suit_condition_args {
    suit_rep_policy_t report;

    /*! Destination SUIT_Component_Identifier */
    suit_component_identifier_t dst;

    /*! suit-condition-* label */
    suit_con_dir_key_t condition;

    /*! To be expected values */
    union {
        int64_t         i64;
        uint64_t        u64;
        UsefulBufC      str;
        struct {
            uint64_t        image_size;
            suit_digest_t   image_digest;
        };
        suit_version_match_t version_match;
    } expected;
} suit_condition_args_t;

/*!
 *  \brief  Parameter for SUIT_Wait_Event_Argument_Other_Device_Version.
 */
typedef struct suit_other_device_version {
    UsefulBufC              other_device;
    size_t                  len;
    suit_version_match_t    versions[SUIT_MAX_ARRAY_LENGTH];
} suit_other_device_version_t;

/*
 * SUIT_Wait_Event
 */
typedef struct suit_wait_event {
    uint64_t                    exists;

    int64_t                     authorization;
    int64_t                     power;
    int64_t                     network;
    suit_other_device_version_t other_device_version;
    uint64_t                    time;
    uint64_t                    time_of_day;
    uint64_t                    day_of_week;
} suit_wait_event_t;

/*!
 *  \brief  Parameters to request wait event.
 *
 *  Used by suit_wait_callback().
 */
typedef struct suit_wait_args {
    suit_rep_policy_t report;

    /*! Destination SUIT_Component_Identifier */
    suit_component_identifier_t dst;

    /*! SUIT_Wait_Event */
    suit_wait_event_t wait_info;
} suit_wait_args_t;

typedef struct suit_parameter_args {
    uint64_t                    exists;

    UsefulBufC                  vendor_id;
    UsefulBufC                  class_id;
    UsefulBufC                  device_id;

    suit_digest_t               image_digest;
    uint64_t                    component_slot;

    /*! default True */
    suit_parameter_bool_t       strict_order;

    /*!
     * default True if suit-directive-try-each is invoked,
     * default False if suit-directive-run-sequence is invoked
     */
    suit_parameter_bool_t       soft_failure;

    uint64_t                    image_size;

    UsefulBufC                  content;
    UsefulBufC                  uri;

    uint64_t                    source_component;

    /*! used in suit-directive-fetch */
    UsefulBufC                  fetch_args;

    /*! used in suit-directive-invoke */
    UsefulBufC                  invoke_args;


    /* in draft-ietf-suit-update-management */
    /*! used in suit-condition-use-before */
    uint64_t                    use_before;
    /*! used in suit-condition-minimum-battery */
    uint64_t                    minimum_battery;
    /*! XXX: used in suit-condition-update-authorized */
    int64_t                     update_priority;
    /*! used in suit-condition-version */
    suit_version_match_t        version_match;

    /*! used in suit-directive-wait */
    suit_wait_event_t           wait_info;

    /* in draft-ietf-suit-trust-domains */


    /* in draft-ietf-suit-firmware-encryption */
    /*! Pointer and length to the COSE_Encrypt */
    UsefulBufC                  encryption_info;
} suit_parameter_args_t;

typedef union {
    uint16_t all;
    struct {
        /*!
         * \brief 1: Skip if the requested section is missing.
         *
         * 0: libcsuit returns \ref SUIT_ERR_MANIFEST_KEY_NOT_FOUND.
         * NOTE: must be 0 inside process-dependency
         * see https://datatracker.ietf.org/doc/html/draft-ietf-suit-trust-domains-02#name-suit-directive-process-depe
         */
        uint16_t allow_missing          : 1;

        /*!
         * 1: Request libcsuit to trigger suit_store_callback()
         * if suit-manifest-component-id is specified.
         */
        uint16_t manifest_component_id  : 1;
        /*! 1: Request libcsuit to process suit-dependency-resolution section. */
        uint16_t dependency_resolution  : 1;
        /*! 1: Request libcsuit to process suit-payload-fetch section. */
        uint16_t payload_fetch          : 1;
        /*! 1: Request libcsuit to process suit-install section. */
        uint16_t install                : 1;
        /*! 1: Request libcsuit to process suit-uninstall section. */
        uint16_t uninstall              : 1;

        /*! 1: Request libcsuit to process suit-validate section. */
        uint16_t validate               : 1;
        /*! 1: Request libcsuit to process suit-load section. */
        uint16_t load                   : 1;
        /*! 1: Request libcsuit to process suit-invoke section. */
        uint16_t invoke                 : 1;

        /*!
         * \brief 1: Request libcsuit to process suit-text section.
         *
         * This parameter is ignored now.
         */
        uint16_t text                   : 1;
        /*!
         * \brief 1: Request libcsuit to process suit-coswid section.
         *
         * This parameter is ignored now.
         */
        uint16_t coswid                 : 1;
    };
} suit_process_flag_t;

typedef struct suit_inputs {
    /* sections requested to process */
    suit_process_flag_t process_flags;

    UsefulBufC manifest;
    suit_digest_t expected_manifest_digest;
    suit_parameter_args_t parameters[SUIT_MAX_INDEX_NUM];

    size_t key_len;
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM];

    UsefulBufC suit_nonce;
    uint8_t dependency_depth;

    size_t left_len;
    uint8_t *ptr;
    uint8_t buf[];
} suit_inputs_t;

typedef struct suit_extracted {
#if !defined(DISABLE_LIBCSUIT_COMMON_DEPENDENCIES)
    suit_dependencies_t dependencies;
#endif
#if !defined(DISABLE_LIBCSUIT_MANIFEST_COMPONENT_ID)
    suit_component_identifier_t manifest_component_id;
#endif

    uint8_t components_len;
    suit_component_with_index_t components[SUIT_MAX_INDEX_NUM];
    suit_payloads_t payloads;

    UsefulBufC manifest;
    suit_digest_t manifest_digest;
    UsefulBufC shared_sequence;
#if !defined(DISABLE_LIBCSUIT_MANIFEST_REFERENCE_URI)
    UsefulBufC reference_uri;
#endif
#if !defined(DISABLE_LIBCSUIT_MANIFEST_DEPENDENCY_RESOLUTION)
    UsefulBufC dependency_resolution;
    suit_digest_t dependency_resolution_digest;
#endif
#if !defined(DISABLE_LIBCSUIT_MANIFEST_PAYLOAD_FETCH)
    UsefulBufC payload_fetch;
    suit_digest_t payload_fetch_digest;
#endif
#if !defined(DISABLE_LIBCSUIT_MANIFEST_INSTALL)
    UsefulBufC install;
    suit_digest_t install_digest;
#endif
#if !defined(DISABLE_LIBCSUIT_MANIFEST_UNINSTALL)
    UsefulBufC uninstall;
#endif
    UsefulBufC validate;
#if !defined(DISABLE_LIBCSUIT_MANIFEST_LOAD)
    UsefulBufC load;
#endif
#if !defined(DISABLE_LIBCSUIT_MANIFEST_INVOKE)
    UsefulBufC invoke;
#endif
} suit_extracted_t;


suit_err_t suit_error_from_qcbor_error(QCBORError error);
bool suit_qcbor_value_is_uint64(QCBORItem *item);
bool suit_qcbor_value_is_uint32(QCBORItem *item);
suit_err_t suit_index_from_item_label(QCBORItem *item, uint8_t *index);
suit_err_t suit_qcbor_get_next_uint(QCBORDecodeContext *message,
                                    QCBORItem *item);
suit_err_t suit_qcbor_get_next(QCBORDecodeContext *message,
                               QCBORItem *item,
                               uint8_t data_type);
suit_err_t suit_qcbor_get_next_label_type(QCBORDecodeContext *message,
                                          QCBORItem *item,
                                          uint8_t data_type,
                                          uint8_t label_type);
suit_err_t suit_qcbor_get(QCBORDecodeContext *message,
                          QCBORItem *item,
                          bool next,
                          uint8_t data_type);
suit_err_t suit_qcbor_peek_next(QCBORDecodeContext *message,
                                QCBORItem *item,
                                uint8_t data_type);
bool suit_qcbor_skip_any(QCBORDecodeContext *message,
                         QCBORItem *item);
suit_err_t suit_verify_item(QCBORDecodeContext *context,
                            QCBORItem *item,
                            suit_digest_t *digest);
size_t suit_qcbor_calc_rollback(QCBORItem *item);
bool suit_continue(suit_decode_mode_t mode,
                   suit_err_t result);

suit_err_t suit_decode_component_identifiers_from_item(suit_decode_mode_t mode,
                                                       QCBORDecodeContext *context,
                                                       QCBORItem *item,
                                                       bool next,
                                                       suit_component_identifier_t *identifier);

suit_err_t suit_decode_components_from_item(suit_decode_mode_t mode,
                                            QCBORDecodeContext *context,
                                            QCBORItem *item,
                                            bool next,
                                            suit_component_with_index_t *components,
                                            uint8_t *num);

#ifdef __cplusplus
}
#endif

#endif  // SUIT_COMMON_H
