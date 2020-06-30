#ifndef SENG_XT_SENG_METADB_H
#define SENG_XT_SENG_METADB_H

#include <linux/hashtable.h>
#include <linux/list.h>

/**
 * @brief stores one enclave
 *
 * Stores one enclave with additional content to be used in hash table.
 * */
struct enclave {
    uint32_t enclave_ip;            ///< the enclave ip = enclave identifier
    uint8_t enclave_key;            ///< the enclave hash
    struct app* a;                  ///< the app associated with the enclave
    uint32_t host_ip;               ///< the host_ip associated with the enclave
    struct hlist_node enclave_node; ///< hash table node
};

/**
 * @brief stores one category
 *
 * Stores one category to be used in a linked list.
 * */
struct cat {
    char category_name[MAX_CAT_NAME_LENGTH]; ///< category name
    struct list_head cat_node;               ///< linked list node
};

/**
 * @brief stores one app
 *
 * Stores one app to be used in a linked list.
 * */
struct app {
    uint32_t reference_counter;    ///< a reference counter to this app_id
    uint8_t app_hash[SGX_HASH_SIZE]; ///< app hash
    struct list_head categories;   ///< linked list containing associated categories
    struct list_head app_node;     ///< linked list node
};

/**
 * @brief adds an enclave into the hash table
 *
 * Adds an enclave into the enclaves hash table.
 * The app_hash is looked up in the apps list, and a pointer to an existing app is set if possible.
 * Else the app is newly added to the list and the pointer is set.
 *
 * @param[in] pEnclave_ip       the enclave identifier
 * @param[in] app_hash          the app_hash associated with the enclave
 * @param[in] host_ip           the host_ip associated with the enclave
 *
 * @return the pointer to the added enclave
 * */
struct enclave* add_enclave (uint32_t pEnclave_ip, const uint8_t* app_hash, uint32_t host_ip);

/**
 * @brief looks up an enclave in the hash table
 *
 * Tries to find an enclave in the enclaves hash table.
 *
 * @param[in] pEnclave_ip       the enclave identifier
 *
 * @return the pointer to the enclave, or NULL if not found
 * */
struct enclave* find_enclave (uint32_t pEnclave_ip);

/**
 * @brief deletes an enclave in the hash table
 *
 * Deletes the given enclave.
 *
 * @param[in] enclave_ip       the enclave identifier
 *
 * @return true on success, else false
 * */
bool del_enclave (uint32_t enclave_ip);

/**
 * @brief deletes all enclaves in the hash table
 *
 * Deletes all enclaves in the enclaves hash table and all apps in the apps list.
 *
 * */
void del_all_enclaves (void);

/**
 * @brief adds a given category to the given app
 *
 * Adds a given category to the given app.
 *
 * @param[in] a              the app to be added to
 * @param[in] cat_name       the category to be added
 *
 * @return true on success, else false
 * */
bool add_cat_to_app (struct app* a, const char* cat_name);

/**
 * @brief deletes a given category from the given app
 *
 * Deletes a given category from the given app.
 *
 * @param[in] a              the app to be deleted from
 * @param[in] cat_name       the category to be deleted
 *
 * @return true on success, else false
 * */
bool del_cat_from_app (struct app* a, const char* cat_name);

/**
 * @brief deletes all entries in apps given the category name
 *
 * Deletes all entries in apps given the category name.
 *
 * @param[in] cat_name       the category to be deleted
 *
 * @return true on success, else false
 * */
bool del_cat (const char* cat_name);

/**
 * @brief tries to find a category in the given app
 *
 * Tries to find a category in the given app.
 *
 * @param[in] a              the app to be searched in
 * @param[in] cat_name       the category to be searched
 *
 * @return a pointer to the category, else null
 * */
struct cat* find_cat (struct app* a, const char* cat_name);

/**
 * @brief tries to find an app matching the app hash
 *
 * Tries to find an app in the apps list, matching the given app hash.
 *
 * @param[in] app_hash       the app hash to be searched
 *
 * @return a pointer to the app, else null
 * */
struct app* lookup_app_hash (const uint8_t* app_hash);

/**
 * @brief compares the given app hash with the one of the given app
 *
 * Compares the given app hash with the one of the given app.
 *
 * @param[in] a                   the app to be compared with
 * @param[in] rule_app_hash       the app hash to be compared
 *
 * @return true on match, else false
 * */
bool match_app(struct app* a, const uint8_t* rule_app_hash);

/**
 * @brief tries to find the given category name in the given app
 *
 * Tries to find the given category name in the given app.
 *
 * @param[in] a                   the app to be searched in
 * @param[in] rule_cat_name       the category name to be looked up
 *
 * @return true on success, else false
 * */
bool match_category(struct app* a, const char* rule_cat_name);
#endif