#!/bin/bash
# a=$(ls -al)
# echo ls $a
# set

VAR=4
[ $VAR -gt 3 ]
echo $?
false
echo $?
echo $TEST
echo "$TEST"

FILES=`ls`
echo $FILES
#sed -n '/1.sh/p' $FILES
FILE_INFO=`cat ./shell.md`
echo $FILE_INFO

is_directory()
{
    DIRNAME=$1
    if [ ! -d DIRNAME ]
    then
        return 1
    else
        return 0
    fi
}
for DIR in $@;do
    if is_directory "$DIR";then
        echo "$DIR is a dir"
    else
        echo "$DIR not exist,creating it"
        mkdir $DIR > /dev/null 2>&1
        if [ $? -ne 0 ];then
            echo "cannot create dir $DIR"
        fi
    fi
done