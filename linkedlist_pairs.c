#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <infiniband/verbs.h>
#include "linkedlist_pairs.h"

Node_pairs * createnode_pairs(const char* key, struct MR_place_pair* pair);

Node_pairs * createnode_pairs(const char* key, struct MR_place_pair* pair){
  Node_pairs * newNode = malloc(sizeof(Node_pairs));
  if (!newNode) {
    return NULL;
  }
  strcpy(newNode->key, key);
  newNode->pair = pair;
  newNode->next = NULL;
  return newNode;
}

List_pairs * makelist_pairs(void){
  List_pairs * list = malloc(sizeof(List_pairs));
  if (!list) {
    return NULL;
  }
  list->head = NULL;
  return list;
}

void display_pairs(List_pairs * list) {
  Node_pairs * current = list->head;
  if(list->head == NULL) 
    return;

  printf("------------------------------\n");

  for(; current != NULL; current = current->next) {
    printf("KEY: %s ", current->key);
    if (current->pair != NULL) {
        printf("PAIR: %p", current->pair);

    }
    printf("\n");
  }

  printf("------------------------------\n");
}

Node_pairs* add_pairs(const char* key, struct MR_place_pair* data, List_pairs * list) {
  Node_pairs* ret_node = NULL;

  Node_pairs * current = NULL;
  if(list->head == NULL){
    list->head = createnode_pairs(key, data);
    ret_node = list->head;
  }
  else {
    current = list->head; 
    while (current->next!=NULL){
      current = current->next;
    }
    current->next = createnode_pairs(key, data);
    ret_node = current->next;
  }

  return ret_node;
}

void delete_pairs(const char* key, List_pairs * list){
  Node_pairs * current = list->head;
  Node_pairs * previous = current;
  while(current != NULL){           
    if(strcmp(current->key, key) == 0){
      previous->next = current->next;
      if(current == list->head)
        list->head = current->next;
      if (current->pair) {
          free(current->pair);
      }
      free(current);
      return;
    }                               
    previous = current;             
    current = current->next;        
  }                                 
}                                   

void reverse_pairs(List_pairs * list){
  Node_pairs * reversed = NULL;
  Node_pairs * current = list->head;
  Node_pairs * temp = NULL;
  while(current != NULL){
    temp = current;
    current = current->next;
    temp->next = reversed;
    reversed = temp;
  }
  list->head = reversed;
}
//Reversing the entire list by changing the direction of link from forward to backward using two pointers
void reverse_using_two_pointers_pairs(List_pairs *list){
    Node_pairs *previous = NULL;
    while (list->head)
    {
        Node_pairs *next_node = list->head->next; //points to second node in list
        list->head->next = previous;//at initial making head as NULL
        previous = list->head;//changing the nextpointer direction as to point backward node 
        list->head = next_node; //moving forward by next node
    }
    list->head=previous;
}

void destroy_pairs(List_pairs * list, bool destroy_internals){ // Jonathan added destroy_internals
  Node_pairs * current = list->head;
  Node_pairs * next = current;
  while(current != NULL){
    next = current->next;
    if (current->pair) {
        if (destroy_internals) {
            if (current->pair->value) {
                free(current->pair->value);
            }
            if (current->pair->mr) {
                ibv_dereg_mr(current->pair->mr);
            }
        }

        free(current->pair);
    }
    free(current);
    current = next;
  }
  free(list);
}

// Jonathan Miroshnik added these below, along with the key/data split
Node_pairs* find_pairs(const char* key, List_pairs* list) {
    for (Node_pairs* cur_node = list->head; cur_node != NULL; cur_node = cur_node->next) {
        if(strcmp(cur_node->key, key) == 0) {
            return cur_node;
        }
    }

//    printf("Did not find pair for key: %s\n", key); // TODO delete

    return NULL;
}

int count_nodes_pairs(List_pairs * cur_list) {
    if (cur_list == NULL) {
        printf("The given list to count is NULL\n");
        return 0;
    }

    int ret = 0;
    for (Node_pairs* cur_node = cur_list->head; cur_node != NULL; cur_node = cur_node->next) {
        ret++;
    }

    return ret;
}