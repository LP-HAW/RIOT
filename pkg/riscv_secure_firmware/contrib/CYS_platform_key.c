#include "psa/crypto.h"
#include "psa_crypto_se_driver.h"
#include "psa_crypto_se_management.h"

#include "CYS/protected_key.h"
#include "uapi/ecall.h"

#include <stdbool.h>
#include <stdint.h>

#define PLATFORM_KEY_SE_LOCATION 0x800086

static psa_status_t palloc(psa_drv_se_context_t *drv_context, void *persistent_data,
        const psa_key_attributes_t *attributes, psa_key_creation_method_t method,
        psa_key_slot_number_t *key_slot) {

    (void)drv_context;
    (void)persistent_data;
    (void)attributes;
    (void)method;

    *key_slot = 0;
    return PSA_SUCCESS;
}

static psa_status_t destroy(psa_drv_se_context_t *drv_context,
    void *persistent_data, psa_key_slot_number_t key_slot) {

    (void)drv_context;
    (void)persistent_data;
    (void)key_slot;

    return PSA_SUCCESS;
}

static psa_status_t generate(psa_drv_se_context_t *drv_context, psa_key_slot_number_t key_slot,
        const psa_key_attributes_t *attributes, uint8_t *pubkey, size_t pubkey_size,
        size_t *pubkey_length) {

    (void)drv_context;
    (void)attributes;
    (void)pubkey_size;
    (void)key_slot;

    /* TODO: pubkey_size is always zero */

    CYS_PROT_p256_key_t sealed_key;

    psa_status_t status;
    status = _ecall1(ECALL_CYS_PROT_P256_PLATFORM_KEY,
        (uint32_t)&sealed_key);
    if(status != PSA_SUCCESS) {
        return status;
    }

    status = CYS_PROT_p256_derive(&sealed_key, pubkey);
    if(status != PSA_SUCCESS) {
        return status;
    }

    *pubkey_length = CYS_PROT_P256_PUB_SIZE;

    return PSA_SUCCESS;
}

static psa_status_t sign(psa_drv_se_context_t *drv_context, psa_key_slot_number_t key_slot,
        psa_algorithm_t alg, const uint8_t *p_hash, size_t hash_length, uint8_t *p_signature,
        size_t signature_size, size_t *p_signature_length) {

    (void)drv_context;
    (void)alg;
    (void)signature_size;
    (void)key_slot;

    if(signature_size < CYS_PROT_P256_SIG_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    CYS_PROT_p256_key_t sealed_key;

    psa_status_t status;
    status = _ecall1(ECALL_CYS_PROT_P256_PLATFORM_KEY,
        (uint32_t)&sealed_key);
    if(status != PSA_SUCCESS) {
        return status;
    }

    status = CYS_PROT_p256_sign(&sealed_key, p_hash, hash_length, p_signature);
    if(status != PSA_SUCCESS) {
        return status;
    }

    *p_signature_length = CYS_PROT_P256_SIG_SIZE;

    return PSA_SUCCESS;
}

static psa_drv_se_key_management_t drv_se_key_mgmt = {
    .p_allocate = &palloc,
    .p_generate = &generate,
    .p_destroy = &destroy
};

static psa_drv_se_asymmetric_t drv_se_asym = {
    .p_sign = &sign
};

static psa_drv_se_t drv_se = {
    .hal_version = PSA_DRV_SE_HAL_VERSION,
    .persistent_data_size = 0,
    .key_management = &drv_se_key_mgmt,
    .asymmetric = &drv_se_asym
};

psa_key_id_t CYS_platform_key_id;

void auto_init_CYS_platform_key(void) {
    psa_crypto_init();
    psa_register_secure_element(PLATFORM_KEY_SE_LOCATION, &drv_se, NULL, NULL);

    psa_key_attributes_t privkey_attr = psa_key_attributes_init();
    psa_set_key_algorithm(&privkey_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&privkey_attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_type(&privkey_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&privkey_attr, 256);

    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_LIFETIME_VOLATILE, PLATFORM_KEY_SE_LOCATION);
    psa_set_key_lifetime(&privkey_attr, lifetime);

    psa_generate_key(&privkey_attr, &CYS_platform_key_id);
}
