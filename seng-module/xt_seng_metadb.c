#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/slab.h> //kmalloc

#include "xt_seng.h"
#include "xt_seng_metadb.h"

/**
 * @brief a hash table for enclaves
 *
 * This hash table is used to store the enclaves, sent by the user-space app.
 * The table uses 2^8 hash buckets.
 * */
DEFINE_HASHTABLE(enclaves, 8);
LIST_HEAD(apps);

//helper functions

/**
 * @brief helps deleting a category in a given app
 *
 * Helps deleting a category in a given app.
 *
 * @param[in] a                   the app to be deleted in
 * @param[in] cat_name            the category name to be deleted up
 * */
void del_cat_helper (struct app* a, const char* cat_name) {
    struct list_head *pos, *q;
    struct cat* c;

    list_for_each_safe (pos, q, &(a->categories)) {
        c = list_entry(pos, struct cat, cat_node);
        if (strncmp(cat_name, c->category_name, MAX_CAT_NAME_LENGTH) == 0) {
            list_del(&(c->cat_node));
            kfree(c);
            return;
        }
    }
}

/**
 * @brief adds an app into the apps list
 *
 * Adds an app into the apps list or increases the reference counter of existing app.
 *
 * @param[in] app_hash             the app hash to be added
 *
 * @return a pointer to the app, or null in case of out of memory
 * */
struct app* add_app (const uint8_t* app_hash) {
    struct app* a;
    a = lookup_app_hash(app_hash);

    if (a) {
        a->reference_counter++;
        return a;
    }

    a = kmalloc(sizeof(struct app), GFP_KERNEL);

    if (!a) {
        printk(KERN_ERR "xt_seng: OOM in add_app!");
        return NULL;
    }

    memcpy(a->app_hash, app_hash, SGX_HASH_SIZE);

    INIT_LIST_HEAD(&(a->categories));
    a->reference_counter = 1;
    list_add(&(a->app_node), &apps);

    #ifdef DEBUG_SENGMOD
    printk(KERN_DEBUG "xt_seng: added app (%s)", a->app_hash);
    #endif

    return a;
}

/**
 * @brief helps deleting all categories of a given app entry
 *
 * Helps deleting all categories of a given app entry.
 *
 * @param[in] a             the app to be deleted in
 * */
void del_cats_helper (struct app* a) {
    struct list_head *pos, *q;
    struct cat* c;

    list_for_each_safe (pos, q, &(a->categories)) {
        c = list_entry(pos, struct cat, cat_node);
        list_del(&(c->cat_node));
        kfree(c);
    }
}

/**
 * @brief deletes an app
 *
 * Deletes an app entry if the reference counter is 1. Else the reference counter is decreased.
 *
 * @param[in] app_hash             the app hash to be added
 *
 * */
void del_app (struct app* a) {
    if (a->reference_counter == 1) {
        del_cats_helper(a);
        list_del(&(a->app_node));
        #ifdef DEBUG_SENGMOD
        printk(KERN_DEBUG "xt_seng: deleted app (%s)", a->app_hash);
        #endif
        kfree(a);
    } else {
        a->reference_counter--;
    }
}

/**
 * @brief deletes all apps from the apps list.
 *
 * Deletes all apps from the apps list.
 *
 * */
void del_all_apps (void) {
    struct list_head *pos, *q;
    struct app* a;

    list_for_each_safe (pos, q, &apps) {
        a = list_entry(pos, struct app, app_node);
        del_cats_helper(a);
        list_del(&(a->app_node));
        kfree(a);
    }
}

/**
 * @brief hash function to determine key of enclaves
 *
 * Takes the last 8 bits of the ip as hash.
 *
 * @param[in] enclave_ip    The enclave ip to be hashed.
 *
 * @return the key
 * */
uint8_t hash_func (uint32_t enclave_ip) {
    return (uint8_t) (enclave_ip & 0xFF);
}

struct enclave* add_enclave (uint32_t pEnclave_ip, const uint8_t* app_hash, uint32_t host_ip) {
    struct enclave* e;
    struct app* a;

    if (find_enclave(pEnclave_ip)) {
        printk(KERN_ERR "xt_seng: Enclave duplicate.");
        return NULL;
    }

    e = kmalloc(sizeof(struct enclave), GFP_KERNEL);
    e->enclave_ip = pEnclave_ip;
    e->enclave_key = hash_func(pEnclave_ip);
    e->host_ip = host_ip;

    a = add_app(app_hash);

    e->a = a;

    hash_add(enclaves, &e->enclave_node, e->enclave_key);

    return e;

}

bool del_enclave (uint32_t pEnclave_ip) {
    struct enclave *e;
    uint8_t pKey = hash_func(pEnclave_ip);

    hash_for_each_possible(enclaves, e, enclave_node, pKey) {
        if (e->enclave_ip == pEnclave_ip) {
            del_app(e->a);
            hash_del(&e->enclave_node);
            kfree(e);
            return true;
        }
    }

    return false;
}

struct enclave* find_enclave (uint32_t pEnclave_ip) {
    struct enclave *e;
    uint8_t pKey = hash_func(pEnclave_ip);

    hash_for_each_possible(enclaves, e, enclave_node, pKey) {
        if (e->enclave_ip == pEnclave_ip) {
            return e;
        }
    }

    return NULL;
}

void del_all_enclaves (void) {
    struct enclave *e;
    unsigned int bkt = 0;

    hash_for_each(enclaves, bkt, e, enclave_node) {
        hash_del(&e->enclave_node);
        kfree(e);
    }

    del_all_apps();

}

bool add_cat_to_app (struct app* a, const char* category_name) {
    struct cat* c;
    struct cat* c_tmp;
    struct list_head *pos, *q;

    if (!category_name) {
        printk(KERN_ERR "xt_seng: called add_cat with null pointer!");
        return false;
    }

    list_for_each_safe (pos, q, &(a->categories)) {
        c_tmp = list_entry(pos, struct cat, cat_node);
        if (strncmp(category_name, c_tmp->category_name, MAX_CAT_NAME_LENGTH) == 0) {
            printk(KERN_DEBUG "xt_seng: duplicate category (%s) in app (%s)", category_name, a->app_hash);
            return true;
        }
    }

    c = kmalloc(sizeof(struct cat), GFP_KERNEL);

    if (!c) {
        printk(KERN_ERR "xt_seng: OOM in add_cat!");
        return false;
    }

    strncpy(c->category_name, category_name, MAX_CAT_NAME_LENGTH - 1);
    c->category_name[MAX_CAT_NAME_LENGTH - 1] = 0;

    list_add(&(c->cat_node), &(a->categories));

    #ifdef DEBUG_SENGMOD
    printk(KERN_DEBUG "xt_seng: added category (%s) in app (%s)", category_name, a->app_hash);
    #endif

    return true;

}

bool del_cat_from_app (struct app* a, const char* category_name) {
    struct list_head *pos, *q;
    struct cat* c;

    list_for_each_safe (pos, q, &(a->categories)) {
        c = list_entry(pos, struct cat, cat_node);
        if (strncmp(category_name, c->category_name, MAX_CAT_NAME_LENGTH) == 0) {
            list_del(&(c->cat_node));
            kfree(c);
            #ifdef DEBUG_SENGMOD
            printk(KERN_DEBUG "xt_seng: Deleted category (%s) from app (%s)", category_name, a->app_hash);
            #endif
            return true;
        }
    }

    printk(KERN_DEBUG "xt_seng: not found in del_cat from app");
    return false;

}

bool del_cat (const char* category_name) {

    struct app* a;
    struct list_head *pos, *q;

    list_for_each_safe (pos, q, &apps) {
        a = list_entry(pos, struct app, app_node);
        del_cat_helper(a, category_name);
    }

    return false;

}

struct cat* find_cat (struct app* a, const char* cat_name) {

    struct cat* c;

    list_for_each_entry (c, &(a->categories), cat_node) {
        if (strncmp(c->category_name, cat_name, MAX_CAT_NAME_LENGTH) == 0) {
            return c;
        }
    }

    printk(KERN_DEBUG "xt_seng: Could not find category %s in app %s", cat_name, a->app_hash);

    return NULL;

}

struct app* lookup_app_hash (const uint8_t* app_hash) {
    struct app* a;

    list_for_each_entry (a, &apps, app_node) {
        if (memcmp(a->app_hash, app_hash, SGX_HASH_SIZE) == 0) {
            return a;
        }
    }

    return NULL;
}

bool match_app(struct app* a, const uint8_t* rule_app_hash) {
    if (memcmp(&a->app_hash, rule_app_hash, SGX_HASH_SIZE) == 0) return true;
    return false;
}

bool match_category(struct app* a, const char* rule_cat_name) {
    struct cat* c = find_cat(a, rule_cat_name);
    if (c) return true;
    return false;
}
