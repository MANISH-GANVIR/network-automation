num=int(input())
while num !=0:
    last_digit=num%10 #calculate last digit
    print(last_digit,end=" ")
    num=num//10  #calculate number without last digit
#----------------------------------------------------
num=int(input())
sum=0
while num !=0:
    last_digit=num%10 #calculate last digit
    sum=sum+last_digit
    num=num//10  #calculate number without last digit
print(sum)