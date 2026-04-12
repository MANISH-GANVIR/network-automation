list=[1,2,3,4,2,3,5,5,6]
set_list=set(list)

for ele in set_list:
    if list.count(ele)>1:
        print(ele,list.count(ele))