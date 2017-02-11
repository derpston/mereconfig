#include <mereconfig.h>
#include "base64.hpp"

MereConfig::MereConfig(const char * config_url)
{
    _init(config_url, true);
}

MereConfig::MereConfig(const char * config_url, bool load_stored_config)
{
    _init(config_url, load_stored_config);
}

void MereConfig::_init(const char * config_url, bool load_stored_config)
{
    _config_url = config_url;
    if(load_stored_config)
        _load();
}

unsigned char* MereConfig::_decrypt(unsigned char * message, int length)
{
    // Remove the Base64 armor.
    unsigned char *unpacked = (unsigned char *) malloc(length);
    memset(unpacked, 0, length);

    unsigned int len = decode_base64(message, unpacked);
    
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned int unpacked_size = len;

    // Copy the nonce out of the encrypted message.
    memcpy(nonce, unpacked, crypto_box_NONCEBYTES);

    long esize = (unpacked_size - crypto_box_NONCEBYTES) + crypto_box_BOXZEROBYTES;
    unsigned char *ciphertext = (unsigned char *) malloc(esize);
    memset(ciphertext, 0, crypto_box_BOXZEROBYTES);
    memcpy(ciphertext + crypto_box_BOXZEROBYTES, unpacked + crypto_box_NONCEBYTES, unpacked_size - crypto_box_NONCEBYTES);
    free(unpacked);

    unsigned char *plaintext = (unsigned char *) calloc(esize + 1, sizeof(unsigned char));
    memset(plaintext, 0, esize + 1);
    int retval = crypto_box_open(plaintext, 
        ciphertext,
        esize,
        nonce,
        (const unsigned char *) _their_public_key, 
        (const unsigned char *) _my_secret_key);
    free(ciphertext);

    _last_decrypt_error = retval;
    
    if(retval == 0)
    {
        // The plaintext is padded with nulls - copy out the non-null portion.
        memcpy(plaintext, plaintext + crypto_box_ZEROBYTES, esize - crypto_box_ZEROBYTES);
        plaintext[esize - crypto_box_ZEROBYTES] = '\0';
        return plaintext;
    } else {
        free(plaintext);
        return NULL;
    }

    return plaintext;
}

void MereConfig::set_keys(unsigned char * my_secret_key, unsigned char * their_public_key)
{
    _my_secret_key = my_secret_key;
    _their_public_key = their_public_key;
}

void MereConfig::unset_keys()
{
    _my_secret_key = NULL;
    _their_public_key = NULL;
}

bool MereConfig::_load()
{
    bool retval = false;

    // Load config from persistent storage.
    SPIFFS.begin();

    File config = SPIFFS.open("/config.txt", "r");

    if(config)
    {
        config_size = config.size();
        _usable_size = min(MERECONFIG_MAX_SIZE, config_size);
        _raw_config = (char*) malloc(_usable_size);
        config.readBytes(_raw_config, _usable_size);

        // Compute a hash of the config to help with debugging, checking
        // for updates, etc.
        _hash(_raw_config, _usable_size, hash);

        // Parse the config into keys and values, and produce the lookup
        // table.
        retval = _parse();

    }
    SPIFFS.end();

    return false;
}

bool MereConfig::_is_valid_config(unsigned char * config)
{
    // The config must begin with the magic header bytes, which indicates
    // a valid config. TODO: Better validity checking.
    return 0 == memcmp(config, MAGIC_HEADER, MAGIC_HEADER_LEN);
}

bool MereConfig::_parse()
{
    if(!_is_valid_config((unsigned char *)_raw_config))
        return false;

    // Strip any newlines from the end of the config.
    while(_raw_config[_usable_size - 1] == '\n')
        _raw_config[--_usable_size] = '\0';

    // Tokenise the config, replacing all newlines with NULs.
    char *token;
    char *saveptr;
    token = strtok_r(_raw_config, "\n", &saveptr);

    while(token != NULL)
    {
        char *equals = strtok(token, "=") + strlen(token) + 1;

        // If a token begins with a hash (#) it is considered a comment
        // and skipped.
        if('#' != token[0])
        {
            // Found a new key. Allocate some space for a new kv struct.
            kv * new_kv = (kv*) malloc(sizeof(kv));
            if(_kv_root == NULL)
            {
                _kv_root = new_kv;
            } else {
                // Set up the link from the previous key
                kv * tmp = _kv_root;
                while(tmp->next != NULL)
                    tmp = tmp->next;

                tmp->next = new_kv;
            }

            new_kv->key = token;
            new_kv->value = equals;
            new_kv->next = NULL;

            keys++;
        }
        token = strtok_r(NULL, "\n", &saveptr);
    }
    
    has_config = true;
    return true;
}

void MereConfig::_hash(char * input, uint32_t length, char human_readable_hash[41])
{
    // Compute a sha1 hash of the portion of the config we'll be using.
    uint8_t hash_raw[20] = {0};
    sha1(input, length, hash_raw);

    // Convert the raw hash to hex, for human consumption.
    for(int i=0; i<sizeof(hash_raw); i++)
        sprintf((char*)human_readable_hash + (i * 2), "%02x", hash_raw[i]);
    human_readable_hash[40] = '\0';
}

// Frees all the memory associated with the currently loaded config.
void MereConfig::_free()
{
    if(has_config)
    {
        // Free all the kv structs in the linked list that forms the
        // key-value look up table.
        kv * tmp = _kv_root;
        while(tmp != NULL)
        {
            kv *next = tmp->next;
            free(tmp);
            tmp = next;
        }

        // Free the space used to hold the full config.
        free(_raw_config);

        // Erase the hash.
        memset(hash, 0, sizeof(hash));

        _kv_root = NULL;
        has_config = false;
    }
}

unsigned char *MereConfig::_maybe_decrypt_config(unsigned char * payload, unsigned int length)
{
    unsigned char *config = NULL;

    if(NULL == _my_secret_key)
    {
        // No keys, assume plaintext config.
        config = payload;

    } else {
        // Have keys, assume encrypted config.
        config = _decrypt(payload, length);
    }
    
    return config;
}

bool MereConfig::update()
{
    // Check for an updated config and write it to persistent storage.
    HTTPClient http;
    http.begin(_config_url);
    bool retval = false;

	int status_code = http.GET();
    sprintf(update_result, "HTTP %d", status_code);
 	if(status_code > 0)
	{
        if(status_code == HTTP_CODE_OK)
        {
            String payload = http.getString();
            unsigned char * config = _maybe_decrypt_config((unsigned char *)payload.c_str(), payload.length());

            if(NULL != config)
            {
                if(_is_valid_config(config))
                {
                    // Hash new config to see if it has changed.
                    char new_config_hash[41] = {0};
                    _hash((char*) config,
                        min(strlen((char*)config), MERECONFIG_MAX_SIZE),
                        new_config_hash);
                    
                    if(strcmp(new_config_hash, hash) != 0)
                    {
                        // Config changed, write it to the filesystem and load it.
                        _write_config((char *)config, strlen((char*)config));
                        
                        sprintf(update_result, 
                            "%s: updated config: %s -> %s", update_result,
                            hash, new_config_hash);

                        // Dump old config and load the new one.
                        _free();
                        _load();

                        // Only at this point do we think we have a valid and
                        // up to date config.
                        retval = true;
 
                    } else {
                        sprintf(update_result,
                            "%s: config unchanged.", update_result);
                    }

               } else {
                    char firstbytes[16] = {0};
                    strncpy(firstbytes, (const char*) config, sizeof(firstbytes));
                    snprintf(update_result, sizeof(update_result),
                        "%s: config header incorrect: %s", update_result, firstbytes);
               }
            }

            // If we had an encrypted config, it was malloc()ed inside
            // _decrypt and we should free it here.
            if(NULL != _my_secret_key && NULL != config)
               free(config); 
             
        } else {
            sprintf(update_result, "%s: Failed", update_result);
        }
    } else {
        // Non-HTTP failure; a socket-level problem.
        sprintf(update_result, "Socket error %d: %s", status_code,
            http.errorToString(status_code).c_str());
    }

	http.end();
    return retval;
}

// Write a new config to the filesystem.
bool MereConfig::_write_config(char * new_config, uint32_t length)
{
    SPIFFS.begin();

    File config = SPIFFS.open("/config.txt", "w");
    uint32_t bytes_written = 0;

    if(config)
        bytes_written = config.write((const uint8_t *)new_config, length);

    SPIFFS.end();

    return bytes_written == length;
}

// Returns a pointer to the value associated with `key`, or NULL if the key
// doesn't exist in this config.
char * MereConfig::_find(const char *key)
{
    if(!has_config)
        return NULL;

    kv * tmp = _kv_root;
    while(tmp != NULL)
    {
        if(strcasecmp(tmp->key, key) == 0)
            return tmp->value;
        tmp = tmp->next;
    }

    return NULL;
}

const char* MereConfig::get(const char *key, const char *def)
{
    char *val = _find(key);
    if(val == NULL)
        return def;
    return val;
}

bool MereConfig::get_bool(const char *key, bool def)
{
    char *val = _find(key);
    if(val == NULL)
        return def;
    return strcasecmp(val, "true") == 0;
}

uint32_t MereConfig::get_int(const char *key, uint32_t def)
{
    char *val = _find(key);
    if(val == NULL)
        return def;
    return atoi(val);
}

double MereConfig::get_float(const char *key, double def)
{
    char *val = _find(key);
    if(val == NULL)
        return def;
    return atof(val);
}

