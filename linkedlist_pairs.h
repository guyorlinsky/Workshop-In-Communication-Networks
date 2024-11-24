#ifndef LINKEDLIST_HEADER
#define LINKEDLIST_HEADER

#include "bw_template.h"
#include <stdbool.h>
#include <string.h>
#include <infiniband/verbs.h>


struct node_pairs {
    char key[MAX_KEY_SIZE];
    struct MR_place_pair* pair;
    struct node_pairs * next;
};

typedef struct node_pairs Node_pairs;

struct list_pairs {
    Node_pairs * head;
};

typedef struct list_pairs List_pairs;

List_pairs * makelist_pairs(void);
Node_pairs* add_pairs(const char* key, struct MR_place_pair* pair, List_pairs * list);
void delete_pairs(const char* key, List_pairs * list);
void display_pairs(List_pairs * list);
void reverse_pairs(List_pairs * list);
void reverse_using_two_pointers_pairs(List_pairs * list);

void destroy_pairs(List_pairs * list, bool destroy_internals);

Node_pairs* find_pairs(const char* key, List_pairs* list);
int count_nodes_pairs(List_pairs* cur_list);

#endif
