#include <iostream>

using namespace std;

/* class a
{
  public:
    a()=default;
    void ls();
  private:
    int d = 0;
}; */

/* void a::ls()
{
    cout << d << endl;
} */

class ListNode
{
  public:
    ListNode(){
        next = 0;
    }
    ListNode(int data,ListNode *in = 0){
        info = data;
        next = in;
    }
  public:la
    int info;
    ListNode *next;
};

int main()
{
    ListNode *pt = new ListNode(10);
    pt->next = new ListNode(30);
    pt->next->next = new ListNode(50);
    cout << pt->info << pt->next->info << pt->next->next->info << endl;
    delete pt->next->next;
    delete pt->next;
    delete pt;
}