/*
 * @lc app=leetcode.cn id=2 lang=c
 *
 * [2] 两数相加
 */

// @lc code=start
/**
 * Definition for singly-linked list.
 * struct ListNode {
 *     int val;
 *     struct ListNode *next;
 * };
 */
struct ListNode {
    int val;
    struct ListNode *next;
 };

struct ListNode* addTwoNumbers(struct ListNode* l1, struct ListNode* l2){
    struct ListNode *ret = malloc(sizeof(struct ListNode));
    int c = 0;//进位
    while(l1 && l2)
    {
        printf("l1:%d l2:%d\n",l1->val);
        ret->val = l1->val + l2->val + c;
        if(ret->val > 9)
        {
            ret->val -=10;
            c = 1;
        }
        else
        {
            c = 0;
        }
        printf("ret %d c = %d\n",ret->val,c);

        l1 = l1->next;
        l2 = l2->next;
    }
    return l1;
}
// @lc code=end

