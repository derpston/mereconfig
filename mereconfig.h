#include <stdint.h>
#include "FS.h"
#include <Hash.h>
#include <strings.h>
#include <ESP8266HTTPClient.h>
#include <tweetnacl.h>
#include <StreamString.h>

#define MERECONFIG_MAX_SIZE 256

#define MAGIC_HEADER "# MereConfig header - do not edit #"
#define MAGIC_HEADER_LEN 35 

// Nodes in a linked list storing pointers to key/value pairs loaded
// from the config.
struct kv
{
    char *key = NULL;
    char *value = NULL;
    kv *next = NULL;
};

class MereConfig
{
    public:
        bool has_config = false;
        uint16_t config_size = -1;
        char hash[41] = {0};
        uint16_t keys = 0;
        char update_result[512] = {0};

        MereConfig(const char *);
        MereConfig(const char *, bool);

        bool update();
        void set_keys(unsigned char *, unsigned char *);
        void unset_keys();
        const char *get(const char* key, const char* def);
        bool    get_bool(const char* key, bool def);
        uint32_t get_int(const char* key, uint32_t def);
        double get_float(const char* key, double def);
        ~MereConfig();
    private:
        void _init(const char *, bool);
        const char *_config_url;
        kv *_kv_root = NULL;
        int _last_decrypt_error = -2; // hmm
        unsigned char *_my_secret_key, *_their_public_key;
        char *_raw_config;
        uint16_t _usable_size = -1;

        char *_find(const char* key);
        void _free();
        void _hash(char *, uint32_t, char[41]);
        bool _parse();
        bool _load();
        bool _write_config(char *, uint32_t);
		unsigned char *_decrypt(unsigned char *, int);
        bool _is_valid_config(unsigned char *);
        unsigned char *_maybe_decrypt_config(unsigned char *, unsigned int);
};
