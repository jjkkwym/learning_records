#include "common.h"

struct list_s
{
    int data;
    struct list_s *next;
};
typedef struct list_s list_t;
void create_list(list_t **head)
{
    list_t *p = (list_t *)malloc(sizeof(list_t));
    if(p != NULL)
        DEBUG("malloc suss\n")
    if(head != NULL)
    {
        DEBUG("the input head list not null\n");
        return;
    }
    *head = p;
    DEBUG("creat list suss head list: %p\n",head);
}
void free_list(list_t *head)
{
    DEBUG("free head list %p",head);
    free(head);
}

int main()
{
    list_t *head = NULL;
    create_list(&head);
    free_list(head);
}