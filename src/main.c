#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>

#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <zephyr/settings/settings.h>
#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#include <zephyr/logging/log.h>

#define SAMPLE_PERS_KEY_ID PSA_KEY_ID_USER_MIN
#define SAMPLE_KEY_TYPE PSA_KEY_TYPE_AES
#define SAMPLE_ALG PSA_ALG_CTR
#define NRF_CRYPTO_EXAMPLE_PERSISTENT_KEY_MAX_TEXT_SIZE (100)

#define NUM_KEYS 3
#define KEY_SIZE 16 // 8*16,128

#define AES_BLOCK_SIZE 16

#define PRINT_HEX(p_label, p_text, len)                                                                                \
    ({                                                                                                                 \
        LOG_INF("---- %s (len: %u): ----", p_label, len);                                                              \
        LOG_HEXDUMP_INF(p_text, len, "Content:");                                                                      \
        LOG_INF("---- %s end  ----", p_label);                                                                         \
    })

static uint8_t m_plain_text[NRF_CRYPTO_EXAMPLE_PERSISTENT_KEY_MAX_TEXT_SIZE] =
    "Example string to demonstrate basic usage of a persistent key.";

static uint8_t m_encrypted_text[PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(SAMPLE_KEY_TYPE, SAMPLE_ALG,
                                                               NRF_CRYPTO_EXAMPLE_PERSISTENT_KEY_MAX_TEXT_SIZE)];
static uint8_t m_decrypted_text[NRF_CRYPTO_EXAMPLE_PERSISTENT_KEY_MAX_TEXT_SIZE];

LOG_MODULE_REGISTER(enc_central, LOG_LEVEL_DBG);

psa_key_id_t mk;
psa_key_id_t key_ids[3];

int crypto_init(void)
{
    psa_status_t status;

    LOG_INF("crypto init");
    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("unable to init psa crypto");
        return -1;
    }

    return 0;
}

int crypto_finish(void)
{
    psa_status_t status;

    /* Destroy the key handle */
    status = psa_destroy_key(mk);
    if (status != PSA_SUCCESS)
    {
        LOG_INF("psa_destroy_key failed! (Error: %d)", status);
        return -1;
    }

    return 0;
}

int import_key(uint8_t *key_buf, size_t key_len, psa_key_id_t key_index)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, SAMPLE_ALG);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&attributes, key_index);

    psa_status_t status = psa_import_key(&attributes, key_buf, key_len, &key_ids[key_index - 1]);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("IMPORT FAILED %d", status);
        return -1;
    }
    LOG_INF("Key imported! index %d id %d", key_index - 1, key_ids[key_index - 1]);
    memset(key_buf, 0, key_len);
    status = psa_purge_key(key_ids[key_index - 1]);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("psa_purge key failed %d", status);
        return -1;
    }

    psa_reset_key_attributes(&attributes);
    LOG_INF("Key imported successfuly, handle %d", key_index);
    return status;
}

// Encrypt a buffer using a stored key.
int encrypt_buffer(psa_key_id_t key_id, const uint8_t *input, size_t input_len, uint8_t *output, size_t output_size,
                   size_t *output_len, uint8_t *iv, size_t iv_len, size_t *gen_iv_len)
{

    psa_status_t status;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

    LOG_INF("encrypting");

    status = psa_cipher_encrypt_setup(&operation, key_id, PSA_ALG_CTR);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("unable to setup encrypt %d", status);
        return status;
    }
    psa_cipher_generate_iv(&operation, iv, iv_len, gen_iv_len);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("unable to generate iv %d", status);
        return status;
    }
    LOG_INF("generated IV: %s", iv);

    status = psa_cipher_update(&operation, input, input_len, output, output_size, output_len);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("unable to update cipher %d", status);
        return status;
    }

    size_t finish_len = 0;
    status = psa_cipher_finish(&operation, output + *output_len, output_size - *output_len, &finish_len);
    if (status == PSA_SUCCESS)
    {
        *output_len += finish_len;
    }

    LOG_INF("encrypt success");

    return status;
}

// Decrypt a buffer using a stored key
int decrypt_buffer(psa_key_id_t key_id, const uint8_t *input, size_t input_len, uint8_t *output, size_t output_size,
                   size_t *output_len, uint8_t *iv, size_t iv_len)
{
    psa_status_t status;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

    status = psa_cipher_decrypt_setup(&operation, key_id, PSA_ALG_CTR);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("decrypt setup fail %d", status);
        return status;
    }
    status = psa_cipher_set_iv(&operation, iv, iv_len);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("cipher set iv fail %d", status);
        return status;
    }
    status = psa_cipher_update(&operation, input, input_len, output, output_size, output_len);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("psa cipher update fail %d", status);
        return status;
    }
    size_t finish_len = 0;
    status = psa_cipher_finish(&operation, output + *output_len, output_size - *output_len, &finish_len);
    if (status == PSA_SUCCESS)
    {
        *output_len += finish_len;
    }
    LOG_INF("decrypt attempt successfully executed");
    return status;
}

int main(void)
{
    psa_status_t status;

    status = crypto_init();
    // generate dummy keys.
    // instead of using psa_generate_key, we will mock some buffer_rx to use psa import api.
    // dont have key material in the code. These keys will be randomly gen & provided during a secure provision time.
    uint8_t DEBUG_MOCK_KEYS[NUM_KEYS][KEY_SIZE];

    // start at 1 https://arm-software.github.io/psa-api/crypto/1.2/api/keys/ids.html#c.PSA_KEY_ID_NULL
    LOG_INF("generating and importing keys");
    for (int i = 1; i < 4; i++)
    {
        status = psa_generate_random(DEBUG_MOCK_KEYS[i - 1],
                                     sizeof(DEBUG_MOCK_KEYS[i - 1]) / sizeof(DEBUG_MOCK_KEYS[i - 1][0]));
        if (status != PSA_SUCCESS)
        {
            LOG_INF("unable to generate key %d (%d)", i, status);
        }
        LOG_INF("made key %s, importing", DEBUG_MOCK_KEYS[i - 1]);
        import_key(DEBUG_MOCK_KEYS[i - 1], KEY_SIZE, i);
    }

    // for iv, it's using psa_generate in the encrypt.
    // you can append the iv to your encrypted message. generate a new iv on each encrypt.
    uint32_t olen;
    uint8_t initialization_vector[AES_BLOCK_SIZE];
    size_t iv_len = AES_BLOCK_SIZE;
    size_t gen_iv_len;

    LOG_INF("unenc msg: %s", m_plain_text);
    uint32_t random_key = rand() % 2;
    LOG_INF("random key handle %d", random_key);
    status = encrypt_buffer(key_ids[random_key], m_plain_text, sizeof(m_plain_text), m_encrypted_text,
                            sizeof(m_encrypted_text), &olen, initialization_vector, iv_len, &gen_iv_len);
    if (status != PSA_SUCCESS)
    {
        LOG_INF("encrypt error %d", status);
        return -1;
    }
    LOG_INF("Encryption successful!");
    LOG_INF("IV: %s len %d", initialization_vector, gen_iv_len);
    PRINT_HEX("Plaintext", m_plain_text, sizeof(m_plain_text));
    PRINT_HEX("Encrypted text", m_encrypted_text, sizeof(m_encrypted_text));
    LOG_INF("enc op len: %d", olen);

    // try all key IDs to decrypt (to mimic that the other device doesnt know which key was used)
    uint32_t final_olen;
    for (int i = 0; i < 3; i++)
    {
        LOG_INF("Decrypt attempt with key %d", i);
        status = decrypt_buffer(key_ids[i], m_encrypted_text, olen, m_decrypted_text,
                                PSA_CIPHER_UPDATE_OUTPUT_SIZE(SAMPLE_KEY_TYPE, SAMPLE_ALG, sizeof(m_encrypted_text)),
                                &final_olen, initialization_vector, gen_iv_len);
        if (status != PSA_SUCCESS)
        {
            LOG_ERR("Decryption failed: %d\n", status);
            return -1;
        }

        // Compare
        if (memcmp(m_plain_text, m_decrypted_text, NRF_CRYPTO_EXAMPLE_PERSISTENT_KEY_MAX_TEXT_SIZE) == 0)
        {
            LOG_INF("Encryption and decryption match");
            PRINT_HEX("dec", m_decrypted_text, sizeof(m_decrypted_text));
        }
        else
        {
            LOG_INF("Decrypted data does not match original");
            PRINT_HEX("dec", m_decrypted_text, sizeof(m_decrypted_text));
        }
    }

    for (;;)
    {
        LOG_INF("alive");
        k_msleep(10000);
    }
    k_sleep(K_FOREVER);
    return 0;
}
