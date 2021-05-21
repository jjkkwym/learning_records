/*
 * @lc app=leetcode.cn id=1 lang=c
 *
 * [1] 两数之和
 */

// @lc code=start


/**
 * Note: The returned array must be malloced, assume caller calls free().
 */
int* twoSum(int* nums, int numsSize, int target, int* returnSize){
    int *ret = (int *)malloc(2 * sizeof(int));
    *returnSize = 2;
    for(int i = 0;i < numsSize - 1;i++)
    {
        for(int j = i + 1;j < numsSize;j++)
        {
            if(target == (nums[i] + nums[j]))
            {
                printf("%d,%d\n",i,j);
                ret[0] = i;
                ret[1] = j;
                printf("ret:%p ret[0] = %d, ret[1] = %d\n",ret,ret[0],ret[1]);
                return ret;
            }
        }
    }
    return ret;
}
// @lc code=end

