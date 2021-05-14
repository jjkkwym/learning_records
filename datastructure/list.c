#include "common.h"

typedef void (*btstack_packet_handler_t) (uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size);
struct list_s
{
    int data;
    btstack_packet_handler_t packet_handler;
    struct list_s *next;
};
typedef struct list_s list_t;
typedef list_t *list_p;

typedef struct btstack_linked_item {
    struct btstack_linked_item *next; // <-- next element in list, or NULL
} btstack_linked_item_t;
typedef struct {
    btstack_linked_item_t    item;
    btstack_packet_handler_t callback;
} btstack_packet_callback_registration_t;

void create_list(list_p *head)
{
    if(*head != NULL)
    {
        DEBUG("the input head list not null\n");
        return;
    }
    list_p p = (list_p)malloc(sizeof(list_t));
    if(p != NULL)
        DEBUG("malloc suss\n")
    p->next = NULL;
    *head = p;
    DEBUG("creat list suss head list: %p\n",*head);
}
void insert_list(list_p *head,int data,    btstack_packet_handler_t packet_handler)
{
    if(*head == NULL)
    {
        DEBUG("head list is null\n");
        return;
    }
    list_p p = (list_p)malloc(sizeof(list_t));
    p->data = data;
    p->packet_handler = packet_handler;
    p->next = NULL;
    list_p curr = *head;
    while(curr->next)
    {
        curr = curr->next;
    }
    curr->next = p;
    DEBUG("curr next:%p\n",curr->next);
}
void display_list(list_p head)
{
    list_p curr = head;
    curr = curr->next;   //pass the head list
    int i = 0;
    while(curr)
    {
        DEBUG("index:%d data:%d curr->handler:%p",i,curr->data,curr->packet_handler);
        curr->packet_handler(0,0,0,0);
        i++;  
        curr = curr->next;
    }
    //DEBUG_INT(curr->data);
}

void free_list(list_t *head)
{
    //DEBUG("free head list %p",head);
    list_t *curr = head;
    list_t *prev;
    while(curr)
    {
        prev = curr;
        curr = curr->next;
        DEBUG("free mem %p\n",prev);
        free(prev);
    }
}

void btstack_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
    DEBUG("packet handler");
}
int main()
{
    list_p head = NULL;
    create_list(&head);
    int i;
    btstack_packet_handler_t handler[10];
    for(i = 0;i < 10;i++)
    {
        handler[i] = btstack_packet_handler;
        insert_list(&head,i,handler[i]);
    }
    
    display_list(head);
    DEBUG("head；%p\n",head)
    free_list(head);
}