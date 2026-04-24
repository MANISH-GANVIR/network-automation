''''#== == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == =
#LBP1: -Program to check wether the given number is odd or even

#logic Format: -
#input: -->an integer number constraint - -->
# 1)n >= 0(if_else)
#2 )even or odd(if_else)
#output: -->even or odd or invalid

#code: -
-----




n = int(input())
if n >= 0:
    if
n % 2 == 0:
print("Even")
else:
print("Odd")
else:
print("Invalid")

== == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == =
LBP
2
Given
an
integer
n, perform
the
following
conditional
actions:
If
n is odd, print
"Weird".
If
n is even and in the
inclusive
range
of
2
to
5, print
"Not Weird".
If
n is even and in the
inclusive
range
of
6
to
20, print
"Weird".
If
n is even and greater
than
20, print
"Not Weird".

Logic: -
-Input:A
number
from the user

-constraint: 1) 1 ≤ n ≤ 100.
2)Odd == > Weird( if / else )
3)even and 2
to
5
"Not Weird"
4)even and 6
to
20, print
"Weird"
5)even and > 20, print
"Not Weird".
- Output: Print
"Weird" or "Not Weird"
based
on
the
conditions.





code:-
-----
n=int(input())
if n%2!=0: #if odd
    print("odd")
else:#else even
    if n>=2 and n<=5:#range
        print("Not Weird")
    elif n>=6 and n<=20:
        print("Weird")
    else:
        print("Not Weird")




===========================================================
LBP 3:-Determine whether a given year is a leap year or not.


Logic:-
Input:A year from the user
constraints:(no constraints).
Output:Print "leap year" or "not leap year" based on the following conditions:




Leap Year Conditions:
(year % 4 == 0) and (year % 100 != 0 or year % 400 == 0)


n = int(input())
if n % 4 == 0 and (n % 100 != 0 or n % 400 == 0):
    print("Leap Year")
else:
    print("Not Leap")

    == == == == == == == == == == == == == == == == == == == == == == == == == == == == == =
    LBP
4: -

LBP:-The e-commerce company Bookshelf wishes to analyse its monthly sales data
between minimum range 30 to max range 100. The company has categorized these
book sales into four groups depending on the number of sales with the help of
these groups the company will know which stock they should increase or decrease
in their inventory for the next month. the groups are as follows


sales range    groups
30-50 ----------> D
51-60 ----------> C
61-80 ----------> B
81-100 ----------> A




write an alg to find the group for the given book sale count.




input---> an integer salesCount represent total sales of a book
constraint---> 1)30<=saleCount<=100 2).....
output---> a character representing the group of given sale count




n = int(input())
if n >= 30 and n <= 100:
    if
n >= 30 and n <= 50:
print("D")
elif n >= 51 and n <= 60:
print("C")
elif n >= 61 and n <= 80:
print("B")
else:
print("A")
else:
print("Invalid")
== == == == == == == == == == == == == == == == == == == == == == == == == == == == ==
Example
5: -

Return the Next Number from the Integer Passed
implement a program that takes a number as an argument, increments the number by +1 and returns the result




input ---> a number from the user
constraints---> no constraints
output ---> an incremented value




read n
print n+1

code: -
-----
n = int(input())
n = n + 1
print(n)
'''
"""

LBP
6: -Title: Free
Coffee
Cups
Description: For
every
6
coffee
cups
purchased, you
receive
an
additional
7
th
cup
for free.
This means if you buy 6 cups, you get 1 free, totaling 7 cups.

[Formula = > Total Cups="n+[n/6]"]




Note:
    Python
Division
Operators: / vs //

             1.
Regular
Division( /)
- Performs
floating - point
division
- Always
returns
a
float(even for whole numbers)
- Examples:
5 / 2 = 2.5
4 / 2 = 2.0

2.
Floor
Division( //)
- Performs
integer
division(rounds
down)
- Returns
int if inputs
are
ints, else returns
float
- Examples:
5 // 2 = 2
         - 5 // 2 = -3
6.7 // 2 = 3.0

Key
Differences:
/ Operator:
- Type: Regular
division
- Returns: Float
           - Behavior: Keeps
decimal
- Example: 5 / 2 = 2.5

                   // Operator:
- Type: Floor
division
- Returns: Int or Float
           - Behavior: Drops
decimal(rounds
down)
- Example: 5 // 2 = 2

When
to
Use:
- Use /
for precise calculations(averages, etc.)
            - Use // for counting / grouping (items per page, etc.)




Edge Cases:
    - Negative
numbers: -5 // 2 = -3
                   - Mixed
types: 5.0 // 2 = 2.0

Important
Notes:
- / always
gives
float
result
- // truncates
toward
negative
infinity
- For
rounding
to
nearest
integer, use
round()
instead

code: -
n = int(input())
if n > 0:
    n = n + (n // 6)
print(n)
'''== == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == =
LBP7: -Title: LBP7 - Extract
Digits
from the Number

Task: Implement
a
program
to
extract
digits
from a given

positive
number and print
them
separated
by
spaces.
Requirements:
Input: A
positive
integer
from the user

(n > 0).
Output: Digits
printed in reverse
order, separated
by
spaces.
- --------------------------------------------------------------------------------------------------
Logic: -
-------
Execution
Flow: -Shows
how
the
loop
processes
the
number
123
step - by - step:
-Initial
Value: n = 123
           - Extract
last
digit = > 123 % 10 = 3(print
3)
-Remove
last
digit
from number := > n = 123 / 10 = 12

Next
Iteration: n = 12
digit = 12 % 10 = 2(print
2)
n = 12 // 10 = 1

Next
Iteration: n = 1
digit = 1 % 10 = 1(print
1)
n = 1 // 10 = 0

Termination: n = 0(loop
ends).

Output: 3
2
1
- ---------------------------------------------------------------------
code
1: -by
while loop(preferred)
    ----------------------------------
n = int(input())  # Take integer input
while n != 0:
    digit = n % 10  # Extract last digit
    print(digit, end=' ')  # Print digit with space
    n = n // 10  # Remove last digit (floor division)

code
2: - by
for loop
    -----------------------------------------------------------------------
# Get integer input from user
n = int(input())

for _ in range(len(str(n))):
    # Calculate number of digits in the number by:
    # 1. Converting the number to string (str(n))
    # 2. Getting its length (len())
    # Loop once for each digit

    digit = n % 10  # Extract the last digit using modulo 10
    print(digit, end=' ')  # Print the digit with space separator
    n = n // 10  # Remove the last digit using floor division

    # Example for n = 1234:
    # 1st iteration: digit=4, n becomes 123
    # 2nd iteration: digit=3, n becomes 12
    # 3rd iteration: digit=2, n becomes 1
    # 4th iteration: digit=1, n becomes 0
-----------------------------------------------------------------------------

FOR
LOOPS | WHILE
LOOPS | OUTPUT
EXAMPLES
------------------------------ | -------------------------------- | --------------------------------
1.
Basic
Syntax: | 1.
Basic
Syntax: |
for variable in iterable:                      |
while condition:                   |
# code block                                       |     # code block                    |
| |
2.
Basic
Example: | 2.
Basic
Example: |
for i in range(5):                                     |
i = 0 | 0
print(i) |
while i < 5:                           |
1
| print(i) | 2
| i += 1 | 3
| | 4
| |
3.
With
break: | 3.
With
break: |
for i in range(5):                                |
i = 0 | 0
if i == 3:                                         |
while i < 5:                                |
1
break | if i == 3:                               |
2
print(i) |
break |
| print(i) |
| i += 1 |
| |
4.
With
continue: | 4.
With
continue: |
for i in range(5):                                     |
i = 0 | 0
if i == 3:                                         |
while i < 5:                                 |
1
continue | i += 1 | 2
print(i) |
if i == 3:                               |
4
| continue |
| print(i) |
| |
5.
With else: | 5.
With else: |
for i in range(5):                                 |
i = 0 | 0
print(i) |
while i < 5:                            |
1
else: | print(i) | 2
print("Done") | i += 1 | 3
| else: | 4
| print("Done") | Done

KEY
DIFFERENCES:
- For
loops: Automatic
iteration
over
sequences
- While
loops: Require
manual
condition
handling
- Both
support:
break, continue, else clauses
- Indentation: Always
4
spaces
for code blocks

== == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == ==
LBP: -8
'''
Problem Statement
Title: Sum of Digits
Objective: Implement a program to calculate the sum of digits in a given number.




Requirements
Input        A positive integer (n > 0) from the user.
Constraint        n must be greater than 0.
Output        Print the sum of the digits.




logic
s = 0
while (n != 0):
    d = n % 10
    s = s + d
    n = n / 10
print s




n = int(input())  # Get user input
s = 0
while n != 0:
    d = n % 10    # Extract last digit
    s += d        # Add to sum
    n = n // 10   # Remove last digit
print(s)          # Output result
'''

code: -
-------
'''
input=n
output=sum of digit of n
const:-n!=0
extract digit and add digit into sum and remove last digit from n
'''

n = int(input())
s = 0
while n != 0:
    digit = n % 10
    s = s + digit
    n = n // 10
print(s)
---------

LBP: 9:-'''
Problem Statement
Title: Sum of Even Digits
Objective: Calculate the sum of only even digits in a given positive integer.




Requirements
Input        A positive integer (n > 0) from the user.
Constraint        n must be greater than 0.
Output        Sum of even digits in n.




n = int(input())  # Get user input
s = 0
while n != 0:
    d = n % 10     # Extract last digit
    if d % 2 == 0: # Check if digit is even
        s += d     # Add to sum if even
    n = n // 10    # Remove last digit
print(s)           # Output result
'''
code: -
-----

'''
input=n
output=sum
Comstrain t=n>0 ,even digit,sum of even digits




'''

n = int(input())
s = 0
while n != 0:
    digit = n % 10
    if digit % 2 == 0:
        s = s + digit
    n = n // 10
print(s)
-----

LBP: 10:-
'''
Implement a program to calculate the sum of odd digits present in a given positive integer.
- Input: A single positive integer (n > 0)
- Output: Sum of all odd digits in the number
- Constraints: Input number must be greater than 0




1. Initialize sum = 0
2. While number > 0:
   a. Extract last digit (number % 10)
   b. If digit is odd (digit % 2 != 0):
      - Add digit to sum
   c. Remove last digit (number = number // 10)
3. Return/print the accumulated sum




# Sum of Odd Digits Calculator




# Input
num = int(input("Enter a positive integer: "))




# Validation
if num <= 0:
    print("Error: Input must be a positive integer")
else:
    # Calculation
    sum_odd = 0
    temp = num  # Preserve original number




    while temp > 0:
        digit = temp % 10
        if digit % 2 != 0:  # Check if odd
            sum_odd += digit
        temp = temp // 10




    # Output
    print(f"Sum of odd digits in {num}: {sum_odd}")
'''
code: -
------
'''
input=n,
otput=s of odd
cons=n>0 and extract digit,add in s,remove last
'''

n = int(input())
s = 0
while n != 0:
    digit = n % 10
    if digit % 2 != 0:
        s = s + digit
    n = n // 10
print(s)
== == == == == == == == == == == == == ==
LBP: 11
'''
Problem Statement
Sum of Prime Digits
Implement a program to calculate the sum of prime digits (2, 3, 5, 7) present in a given positive integer.




Input: A number from the user (n > 0)




Constraint: n must be greater than 0




Output: Sum of prime digits
Logic
Initialize sum s = 0




While n != 0:
a. Extract last digit: d = n % 10
b. Check if digit is prime (2, 3, 5, or 7)
c. If prime, add to sum: s = s + d
d. Remove last digit: n = n // 10




Print the sum s
'''
code: -
-----

'''
input=n
output=s
constraint=n!=0
'''
n = int(input())
s = 0
while n != 0:
    digit = n % 10
    if digit == 2 or digit == 3 or digit == 5 or digit == 7:
        s = s + digit
    n = n // 10
print(s)

== == == == == == == == == == == == == == == == == == == == == == == == == == == ==
LBP: 12:-
----------
'''
Sum of Digits Divisible by 3
Implement a program to calculate the sum of digits in a given number that are divisible by 3.




Input: A positive integer (n > 0) from the user
Constraint: Input number must be greater than 0
Output: Sum of digits divisible by 3




Logic:




Initialize sum variable s to 0




While the number n is not 0:
a. Extract the last digit: d = n % 10
b. Check if the digit is divisible by 3: if d % 3 == 0
c. If true, add the digit to sum: s = s + d
d. Remove the last digit: n = n // 10




Print the final sum s




Python Code:
n = int(input())
s = 0
while n != 0:
    d = n % 10
    if d % 3 == 0:
        s = s + d
    n = n // 10
print(s)
'''
code: -
-----
'''
input=n
output=s
cons=n>0,digit%3==0,s=s+digit
'''

n = int(input())
s = 0
while n != 0:
    digit = n % 10
    if digit % 3 == 0:
        s = s + digit
    n = n // 10
print(s)
== == == == == == == == == == == == == == == == == == =
LBP: 13:-
'''
Problem Statement
Title: Number of Digits
Objective: Implement a program to count the digits in a given positive number.




Input/Output Requirements:




Input: A positive integer (n > 0) from user




Constraint: n must be greater than 0




Output: Count of digits in the number




Logic 1: Mathematical Approach
count = 0
while n != 0:
    count += 1      # Increment counter
    n = n // 10     # Remove last digit
print(count)




logic2:




read in string format
print length of the string




C---> strlen()
Java --> length()
Py ---> len()




s = input()
print(len(s))




'''
== == == == == == == == == == == == == == == ==
LBP: 14:-
'''
Problem Statement
Reverse Integer
Given a non-negative integer, return it with its digits reversed.




Input/Output:




Input: A number from user (n ≥ 0)




Output: Reversed number




1. Mathematical Approach (First Image)
python
n = int(input())
rev = 0
while n > 0:
    digit = n % 10
    rev = rev * 10 + digit
    n = n // 10
print(rev)
Key Features:




Uses modulo and division to extract digits




Handles leading zeros automatically (they disappear)




Works purely with numeric operations




Example:
Input: 1234 → Output: 4321




2. String Slicing Approach (Second Image)
python
s = input()
print(s[::-1])
Key Features:




Uses Python string slicing ([::-1]) for reversal




Preserves leading zeros if present in input




Simpler but less mathematical




Example:
Input: "1200" → Output: "0021"




Comparison Table
'''

s = str(input())
print(s[::-1])

-----------------------
s = str(input())  # My Name Is Manish
s = s.split()  # ['My', 'Name', 'Is', 'Manish']
print(s)

for i in range(len(s) - 1, -1, -1):
    print(s[i], end=' ')  # Manish Is Name My

-----------------------
== == == == == == == == == == == == == == == == == == == == == == == == ==

'''LBP15
Duck Number
Program to read a number and check whether it is a duck number or not.


Hint: A duck number is a number which has zeros present in it,
but no zero present at the beginning of the number.




Input: A number from the user
Constraint: n >= 0
Output: Yes or No'''

'''
logic:-
n=input()
constraint=n>=0
output=yes/no




'''
code: -
n = input()  ## Take input as a string
print("yes" if '0' in n else "NO")

------------Syntax - --------------------------------
One - line
Expression(Ternary
Operator)
print("yes" if '0' in n else "no")
------------Syntax - --------------------------------
Multiline
If - Else
Statement
if '0' in n:
    print("yes")
else:
    print("no")
---------------------------------------
'''# LBP16
## Number of Occurrences
Program to find the number of occurrences of a given digit in a number n.




Input: Two numbers n and d
Constraints: No constraints
Output: Number of occurrences
'''
n = input()
digit = '5'
print(n.count(digit))

D:\Python_LAB\LAB9\Firewal_Automation\.venv\Scripts\python.exe
D:\Python_LAB\LAB9\Firewal_Automation\Intervew.py
123455
2
----------------------------------------------------------------

# LBP17
Palindrome
Number
Program
to
check
whether
the
given
number is a
palindrome or not.

Input: A
number
from the user

Constraint: n > 0
Output: Yes or No

1)Code
for string as a input:-
str = input()
print("Pallindrom" if str == str[::-1] else "Not Pallindrom")

2)Code
for integer as a  input:-
Logic:
step1)Initialize
original_num = num, reversed_num = 0.
step2)Constraint
While(n != 0):
last_digit = num % 10
reversed_num = reversed_num * 10 + last_digit
num = num // 10
Step3)Compare
original_num
with reversed_num:
    If
equal, print
Yes(palindrome).
Else, print
No.

# Start reversing process
# 1st iteration:
# num = 123, last_digit = 123 % 10 = 3
# reversed_num = 0 * 10 + 3 = 3
# num = 123 // 10 = 12

# 2nd iteration:
# num = 12, last_digit = 12 % 10 = 2
# reversed_num = 3 * 10 + 2 = 32
# num = 12 // 10 = 1

# 3rd iteration:
# num = 1, last_digit = 1 % 10 = 1
# reversed_num = 32 * 10 + 1 = 321
# num = 1 // 10 = 0 (loop ends)
# Code:-
n = int(input())
if n > 0:
    original_num = n
reverse_num = 0
while n > 0:
    rem = n % 10
    reverse_num = reverse_num * 10 + rem
    n = n // 10
if original_num == reverse_num:
    print("Palindrome")
else:
    print("Not Palindrome")
else:
print("Please enter a positive number")
'''




'''
LBP18
Check
Birth
Day

Lisa
always
forgets
her
birthday
which is on
th
5
th
July.
So
develop
a
function / method
which
will
be
helpful
to
remember
her
birthday.

The
function / method
checkBirthday
return an
integer
1,
if it is her birthday else return 0.
the
function / method
checkBirthday
accepts
two
arguments.
Month, a
string
representing
the
month
of
her
birth and
day, an
integer
representing
the
data
of
her
birthday.

input - --> month & day
constraints - --> no
output - --> 1 or 0

logic:

read
day
read
month
if month="july" and day == 5 then print 1 else 0'''




month=input()
day=int(input())
if month=="July" and day==5:
    print(1)
else:
    print(0)
------


'''LBP19

Decimal
to
Binary

A
network
protocol
specifies
how
data is exchanged
via
transmission
media.
The
protocol
converts
each
message
into
a
stream
of
1
's and 0'
s.
Given
a
decimal
number, write
an
algorithm
to
convert
the
number
into
a
binary
form.

input - --> a
number
constraint - --> n >= 0
output - --> binary
number
'''




n=int(input())
conversion=bin(n)
print(conversion)
print(conversion [2:])




output:-D:\Python_LAB\LAB9\Firewal_Automation\.venv\Scripts\python.exe D:\Python_LAB\LAB9\Firewal_Automation\Intervew.py 
123
0b1111011
1111011






'''
LBP20
Lucky
Customer

An
e - commerce
website
wishes
to
find
the
lucky
customer
who
will
be
eligible
for
    full
    value
    cash
    back.For
    this
    purpose, a
    number
    N is fed
    to
    the
    system.
It
will
return another
number
that is calculated
by
an
algorithm.
In
the
algorithm, a
science is generated, in which

each
number
n
the
sum
of
the
preceding
numbers.
Initially
the
sequence
will
have
two
1
's in it.
The
System
will
return the
Nth
number
from the generated

sequence
which is treated as the
order
ID.
The
lucky
customer
will
be
one
who
has
placed
that
order.
Write
an
algorithm
to
help
the
website
find
the
lucky
customer.

input - --> a
number
I
constraint - --> n > 0
output - --> a
number
'''
"""
Fibonacci Series:
-----------------
The Fibonacci series is a sequence where:
    - The first number is 0
    - The second number is 1
    - Every next number is the sum of the previous two




Example:
    0, 1, 1, 2, 3, 5, 8, 13, 21, 34, ...




Logic:
------
To find the nth Fibonacci number:
    - If n == 0 → return 0
    - If n == 1 → return 1
    - Else → fib(n) = fib(n - 1) + fib(n - 2)




This is a recursive approach where the function calls itself
to compute smaller Fibonacci numbers and builds up to the result.








# Function to calculate the nth Fibonacci number
def fib(n):
    # Base case: If n is 0 or 1, return n directly
    if n == 0 or n == 1:
        return n
    # Recursive case: fib(n) = fib(n-1) + fib(n-2)
    else:
        return fib(n - 1) + fib(n - 2)




# Example usage
try:
    n = int(input("Enter the position (n) to find the nth Fibonacci number: "))
    if n < 0:
        print("Please enter a non-negative integer.")
    else:
        result = fib(n)
        print(f"Fibonacci number at position {n} is: {result}")
except ValueError:
    print("Invalid input. Please enter an integer.")




"""




# This program finds the lucky customer by calculating the nth number
# in a special cashback sequence starting as: 1, 1, 2, 3, 5, 8, ...




# Function to calculate the cashback sequence number for the nth lucky customer (1-indexed)
def lucky_customer(n):
    # Base case: First and second customers get 1 as cashback
    if n == 1 or n == 2:
        return 1
    # Recursive case: Sum of previous two customers' cashback values
    else:
        return lucky_customer(n - 1) + lucky_customer(n - 2)




# Example usage
try:
    n = int(input("Enter the lucky position (n) to find the cashback amount: "))
    if n <= 0:
        print("Please enter a positive integer (n ≥ 1).")
    else:
        result = lucky_customer(n)
        print(f"Cashback amount for lucky customer at position {n} is: {result}")
except ValueError:
    print("Invalid input. Please enter an integer.")








D:\Python_LAB\LAB9\Firewal_Automation\.venv\Scripts\python.exe D:\Python_LAB\LAB9\Firewal_Automation\Intervew.py 
Enter the lucky position (n) to find the cashback amount: 7
Cashback amount for lucky customer at position 7 is: 13




Process finished with exit code 0








--------------------------
LBP21




Christmas offer
An e-commerce company plans to give their customers a special discount for the Christmas,
they are planning to offer a flat discount. The discount value is calculated as the sum of
all prime digits in the total bill amount.
Write an algorithm to find the discount value for the given total bill amount.
input ---> the input consists of an integer order value representing the total bill amount condition-> no conditions output ---> print an integer representing discount value for the given total bill amount.
15720.00 ====> 5+7+2=14%'''

n = int(input())
sum = 0
while n != 0:
    last_digit = n % 10
    if last_digit == 2 or last_digit == 3 or last_digit == 5 or last_digit == 7:
        sum = sum + last_digit
    n = n // 10
print(sum)

----------------------------------------
'''LBP22
Niven Number




Write a program to accept a number and check and display whether it is a Niven Number or not.
Niven Number is that a number which is divisible by its sum of digits.




input ---> a number
constraint-> n>0
output ---> Niven Number or Not




logic:




sum=0;
temp=n;
while(n!=0)
{
    sum=sum+(n%10);
    n=n/10;
}
if(temp%sum==0) then print Yes else No'''

Code: -
== ==
# Take input from the user
num_list = input()

# Initialize a variable to store the sum of digits
sum_of_digits = 0  # In Python, when you assign sum_of_digits = 0,
# the variable sum_of_digits is indeed an integer by default.


# Iterate over each character (digit) in the input string
for digit in num_list:
    # Convert the character to an integer and add it to the sum
    sum_of_digits = sum_of_digits + int(digit)

# Print the sum of digits
print(sum_of_digits)

# Check if the number is Niven Number
if int(num_list) % sum_of_digits == 0:
    print('Niven Number')
else:
    print('Not Niven Number')

== == == == == == == =






'''LBP23
A Special two digit number
A special two digit number is a number such that when the sum of its digits is added to
the product of its digits, the result should be equal to the original two-digit number.




Implement a program to accept a two digit number and check whether
it is a special two digit number or not.




input ---> a two digit number
constraint-> 10<=n<=99
output ---> special two digit number or not




logic:
read n
formula = sum of digits + product of digits
a = n % 10;
b = (n / 10) % 10;
c = (a + b) + (a * b);
if c == n then Yes else No'''

n = int(input())
if 10 <= n <= 99:
    a, b = n % 10, n // 10
    print("Yes" if (a + b) + (a * b) == n else "No")
== == == == =


'''LBP24
Sum of even numbers




Implement a program to find sum of even number between x and y both are inclusive.




input ---> two int values
constraint-> no
output ---> sum of even numbers between x and y




logic:




sum = 0
for (i = n1; i <= n2; i++) {
    if (i % 2 == 0) {
        sum = sum + i;
    }
}
print sum'''

code: -
== == == =
n1 = int(input())
n2 = int(input())
sum = 0
for num in range(n1, n2 + 1):
    if num % 2 == 0:
        print("Even Number :", num)
        sum = sum + num
print(sum)

== == == == == == == == == == == == == == == == =


'''LBP25
Celsius to Fahrenheit




Create a function/method to convert census to Fahrenheit.




input ---> census
constrint --> no
output ---> Fahrenheit




formula:
F = (C*9/5) + 32'''

code: -
-----
c = int(input())
F = (c * 9 / 5) + 32
print("Census to Fahrenheit:", F)

D:\Python_LAB\LAB9\Firewal_Automation\.venv\Scripts\python.exe
D:\Python_LAB\LAB9\Firewal_Automation\Intervew.py
30
Census
to
Fahrenheit: 86.0

Process
finished
with exit code 0
== == == =
'''LBP26
Fahrenheit to Celsius
Program to convert Fahrenheit to census.




input ---> fahrenheit
constraint --> no
output ---> celsius




formula:C = (F-32)*5/9'''

code: -
-----
f = int(input())
c = (f - 32) * 5 / 9
print("Fahrenheit to census", c)
D:\Python_LAB\LAB9\Firewal_Automation\.venv\Scripts\python.exe
D:\Python_LAB\LAB9\Firewal_Automation\Intervew.py
86
Fahrenheit
to
census
30.0

== == == =
'''LBP27
Find The Sequence Sum
Given three integers i,j&k, a sequence sum to be the value of i+(i+1)+(i+2)...+j+(j-1)+(j-2)...+k (increment from i until it equals to j, then decrement from j until equals k). Given values i,j,k. calculate the sequence sum as described.
int getSequenceSum(int,int,int);




input ---> Three int values
constraints--> no
output ---> sum based on given constraints




logic:
sum=0;
while(i<=j){
    sum=sum+(i++);
};
while(j!=k){
    sum=sum+(--j);
};
print sum
--------------------------------------------------
- While Loop:
    - Use when you don't know how many times the loop will run.
    - Used to repeat a block of code while a certain condition is true.
    - Requires manual increment/decrement.
Code Example:
-------------
i = 0                    # Step 1: Initialize loop variable
while i < 5:             # Step 2: Evaluate condition
    print(i)             # Step 3: Execute block
    i += 1               # Step 4: Manually update loop variable
# Step 5: Exit when condition is False




Text Diagram:
-------------
      ┌──────────────┐
      │ Initialize   │
      │ i = 0        │
      └─────┬────────┘
            │
      ┌─────▼──────┐
      │ Condition: │
      │ i < 5 ?    │
      └─────┬──────┘
            │True
            ▼
     ┌────────────────┐
     │ print(i)       │
     │ e.g., i = 0    │
     └─────┬──────────┘
           │
   ┌───────▼────────────┐
   │ i += 1             │
   │ e.g., i = i + 1    │
   └───────┬────────────┘
           │
           └────────────► back to condition check




            │
          False
           ▼
     ┌────────────┐
     │ Exit Loop  │
     └────────────┘
"""
- For Loop:
    - Use when you know how many times the loop will run or when iterating over a sequence.
    - Used to repeat a block of code for each item in a sequence.
    - Automatic increment/decrement.
Code Example:
-------------
for i in range(5):       # Step 1: Create iterable & get next element
    print(i)             # Step 2: Execute code using element
                         # Step 3: Exit when no more elements




Text Diagram:
-------------
      ┌──────────────────────┐
      │ Create iterable:     │
      │ range(5)             │
      └────────┬─────────────┘
               │
      ┌────────▼────────────┐
      │ Next element exists?│
      └────────┬────────────┘
               │Yes
               ▼
     ┌───────────────────────────┐
     │ Assign to i               │
     │ i = next(range value)     │
     └────────┬──────────────────┘
              │
     ┌────────▼──────────┐
     │ print(i)          │
     │ e.g., i = 0,1,... │
     └───────────────────┘
              │
              └─────► back to range()




               │
              No
               ▼
     ┌────────────────┐
     │ Exit Loop      │
     └────────────────┘




--------------------------------------------------




'''
# Code:-
i = int(input())
j = int(input())
k = int(input())
sum = 0
while i <= j:
    sum = sum + i
    i = i + 1
while j > k:
    j = j - 1
    sum = sum + j
print(sum)

== == =
'''LBP28
You are climbing a stair case.
It takes n steps to reach to the top.




Each time you can either climb 1 or 2 steps.
In how many distinct ways can you climb to the top?




Note: Given n will be a positive integer.




input ---> a number from the user
constraints --> no
output ---> number of ways




logic:




int fib(int n){
    if(n==1||n==0)
    return 1;
    else
    return fib(n-1)+fib(n-2);
}




fib(1) ====> 1
fib(2) ====> 2
fib(3) ====> 3
'''


# code:-


def fib(n):
    if n == 0 or n == 1:
        return 1
    else:
        return fib(n - 1) + fib(n - 2)


n = int(input())
print(fib(n))

== == == == == == == == == == == == == == == == == == == == == == == == =
'''LBP29
Prime Number or Not




Write a program to check whether the given number is prime number or not.
A number is said to prime if it is having only two factors. i.e. 1 and number itself.




input ---> a number from the use
constraint--> n>1
output ---> true or false




11 -r--> 1 and 11
13 ---> 1 and 13
17 ---> 1 and 17




logic:




factors=0;
for(i=1;i<=n;i++){
    if(n%i==0)
    factors++;
}
if factors==2 (means 1 and n itself) then print "true" else "false"'''

# Code:-
n = int(input())  # Take an integer input from the user
factors = 0  # Initialize a variable to count the number of factors
for i in range(1, n + 1):  # Loop through all numbers from 1 to n
    if n % i == 0:  # Check if i is a factor of n
        factors += 1  # If i is a factor, increment the factors count
print("true" if factors == 2 else "false")  # Print whether the number is prime
# (true) or not (false)


== == == == == == == == == == == == == == == == == == == == == == == == == == == ==

'''LBP30
Valid Palindrome
Given a string, determine if it is a Palindrome string or not.
A String is Palindrome if it is equal to reverse of the original string.




input ---> A String from the user
constraint--> Non-empty String
output ---> Palindrome or not




logic:-
-------
LIRIL ===> LIRIL '''
s = input("Enter string: ")
s = s.lower()  # Case-insensitive
print("valid" if s == s[::-1] else "invalid")

== == == == == == == == == == == == =


'''LBP 31
Create PIN using Three given numbers
"Secure Assets Private Ltd", a small company that deals with lockers has recently started
 manufacturing digital locks which can be locked and unlocked using PINs (passwords).
You have been asked to work on the module that is expected to generate PINs using
three input numbers.




The three given input numbers will always consist of three digits each
i.e. each of them will be in the range >=100 and <=999.




Bellow are the rules for generating the PIN.




1. The PIN should made up of 4 digits.
2. The unit (ones) position of the PIN should be the least of the units position of the three numbers.
3. The tens position of the PIN should be the least of the tens position of the three input numbers.
4. The hundreds position of the PIN should be least of the hundreds position of the three numbers.
5. The thousands position of the PIN should be the max of all digits in the three input numbers.




input ---> three numbers
constraints ---> all the numbers must be in the range of >=100 and <=999
output ---> PIN value




LOGIC:




read n1,n2,n3




d1 = min(n1%10,n2%10,n3%10)
d2 = min((n1/10)%10,(n2/10)%10,(n3/10)%10)
d3 = min((n1/100)%10,(n2/100)%10,(n3/100)%10)
d4 = max(maxD(n1),maxD(n2),maxD(n3))
pin = d4*1000+d3*100+d2*10+d1




n1=123
n2=456
n3=789




d1=min(3,6,9)=3
d2=min(2,5,8)=2
d3=min(1,4,7)=1
d4=max(3,6,9)=9




pin=9*1000+1*100+2*10+3
    =9000+100+20+3
    =9123




python implementation:
n1 = [expression for variable in iterable]




Breakdown:




- n1 = : Assignment operator
- [...] : List comprehension
- expression : int(I) (converts each element to an integer)
- for : Loop keyword
- variable : I (represents each element)
- in : Keyword for iteration
- iterable : input() (takes a string input)




In simpler terms, the syntax is:




[output expression for each item in input sequence]




---
n1=[int(i) for i in input()]
n2=[int(i) for i in input()]
n3=[int(i) for i in input()]
d1=min(n1[2],n2[2],n3[2])
d2=min(n1[1],n2[1],n3[1])
d3=min(n1[0],n2[0],n3[0])
d4=max(max(n1),max(n2),max(n3))
print(d4*1000+d3*100+d2*10+d1)




'''
== == == == == == == == == == =
'''LBP32




Program to count number of special characters and white spaces in a given string.




input ---> A string from the user
constraint ---> non-empty string
output ---> number of special characters




logic:
read str from the user
not equal to a-z or A-Z or 0-9 else c++
python implementation:
---
s=input()
counter=0
for i in s:
    if not i.isalnum():
        counter=counter+1
print(counter)
'''
# code:-
s = input("Enter a string: ")
counter = 0

for char in s:
    if not (('a' <= char <= 'z') or
            ('A' <= char <= 'Z') or
            ('0' <= char <= '9')):
        counter += 1

print("Number of special characters and white spaces:", counter)

== ==

'''LBP34:-Email name should be starts with alphabet and should follow by number or underscore.
It should contains either numbers or underscore finally ends with @gmail.com only,
Then given email id is true otherwise false.




input ---> email id
constraint -> lowercase alphabet [a-z] followed by underscore or digit and gmail.com
output ---> true or false




Email Validation Rules:
--------------------------------------------------
1. Email name should start with lowercase alphabet [a-z]
2. Should be followed by numbers or underscore
3. Must end with @gmail.com
4. No other special characters allowed in prefix




Input: email id
Constraints:
- Lowercase letters [a-z] at start
- Followed by underscore or digits
- Must end with @gmail.com
Output: true or false
python implementation:
---
Code:-




import re
m = re.fullmatch("[a-z]+[ |0-9]@gmail[.]com",input())
print("true" if m!=None else "false")




Python Implementation:
--------------------------------------------------
import re




# Regex pattern explanation:
# Regex pattern explanation:
# [a-z]+: Matches one or more lowercase alphabets (a to z)
#         + sign indicates one or more occurrences
# [_0-9]*: Matches zero or more underscores (_) or digits (0 to 9)
#         * sign indicates zero or more occurrences
# @gmail\.com: Literal string @gmail.com




m = re.fullmatch(r"[a-z]+[_0-9]*@gmail\.com", input().lower())
print("true" if m else "false")




Example Usage:
--------------------------------------------------
Input:  example123@gmail.com
Output: true




Input:  invalid_email@yahoo.com
Output: false




Input:  test_123@gmail.com
Output: true'''

# import re
#
# def validate_email():
#     """
#     Validates if an email address:
#     - Starts with lowercase letters [a-z]
#     - Followed by spaces or numbers [ 0-9]
#     - Ends with @gmail.com
#     Returns 'true' if valid, 'false' otherwise
#     """
#     email = input("Enter email id: ").strip().lower()
#     if re.fullmatch(r"[a-z]+[ 0-9]*@gmail\.com", email):
#         print("true")
#     else:
#         print("false")
#
# if __name__ == "__main__":
#     validate_email()


# Code:-
# Import the re module for regular expression operations
import re

# Prompt the user for input
email = input("Enter Gmail address: ")
'''
Pattern explanation:
- [a-z]+             → starts with lowercase letters
- (\.[a-z0-9]+)?     → optional group: dot followed by letters/digits
- [0-9]*             → optional digits after that
- @gmail\.com        → domain must be exactly gmail.com
'''

pattern = r"[a-z]+(\.[a-z0-9]+)?[0-9]*@gmail\.com"

# Perform the match
match = re.fullmatch(pattern, email)

# Print the result
print("true" if match else "false")

== == == == == == == == == == == == == == == == =


—------------------------------------------------------------------------------------------------
LBP
35: -
The
IT
company
"Soft ComInfo"
has
decided
to
transfer
its
messages
through
the
N / M
using
new
encryption
technique.The
company
has
decided
to
encrypt
the
data
using
the
non - prime
number
concept.The
message is in the
form
of
a
number and
the
sum
of
non - prime
digits
present in the
message is used as the
encryption
key.

Write
an
algorithm
to
determine
the
encryption
key.

input - --> The
input
consists
of
an
integer
numMsg
representing
the
numeric
form
of
the
message.
output - --> print
an
integer
representing
the
encryption
key.
note: Digit
1 and 0
are
considered as a
prime
number.

Note: -sum
of
non - prime
digits

== == == == == == == == == == == == == == == == == == == == =
Encryption
Key
Program
Sum
of
Non - Prime
Digits
Note: 0 and 1
are
considered
PRIME
== == == == == == == == == == == == == == == == == == == == =




--------- Single - Line
Version - --------
print(sum([int(i) for i in input() if i in "4689"]))

[Syntax: - < expression >
for < item > in < iterable > if < condition >]

expression: Operation
to
apply
to
each
item(int(d)
here)
.
for item in iterable: Loop
through
each
element(d in digits).

if condition: Optional
filter(d in "4689)"

       - -------- Multi - Line
Version, Method - 1 - --------
# Take input as string
numMsg = input()

# Variable to store sum of non-prime digits
encryption_key = 0

# Loop through each digit
for digit in numMsg:
    d = int(digit)

# Prime check (0 and 1 treated as prime as per problem)
if d > 1:
    is_prime = True
for i in range(2, d):
    if
d % i == 0: \
    is_prime = False
break

# Add digit if it is non-prime
if not is_prime:
    encryption_key = encryption_key + d

# Print the encryption key
print(encryption_key)




—------------------------------------------------
Multi - Line
Code
Method - 2: -
—---------------------------------
# =========================================
# Program: Encryption Key Generator
# Task   : Find sum of NON-PRIME digits
# Note   : 0 and 1 are considered PRIME
# =========================================


# Take input as string to read digit by digit
numMsg = input()

# This will store the final sum (encryption key)
encryption_key = 0

# Go through each digit in the number
for digit in numMsg:

    # Convert digit from string to integer
    d = int(digit)

    # Prime check
    # Skip 0 and 1 (they are considered prime as per question)
    if d > 1:

        # Assume digit is prime
        is_prime = True

        # Check if digit is divisible by any number
        for i in range(2, d):
            if d % i == 0:
                is_prime = False  # not prime
                break

        # If digit is NOT prime, add to sum
        if not is_prime:
            encryption_key = encryption_key + d

# Print the encryption key
print(encryption_key)

== == == == == == == == == == == == == == == == == == == == == == == == == ==
'''strip() Method in Python:-
—--------------------------------




Explanation:
The strip() method in Python is a string method that removes unnecessary characters 
from the starting and ending of a string. By default, it removes spaces,
but you can specify specific characters to remove.




Code Examples:
# Remove spaces from starting and ending of a string
text = "   Hello, World!   "
print(text.strip())  # Output: "Hello, World!"




# Remove specific characters from starting and ending of a string
text = "!!!Hello, World!!!"
print(text.strip("!"))  # Output: "Hello, World"




# Remove spaces from starting of a string
text = "   Hello, World!   "
print(text.lstrip())  # Output: "Hello, World!   "




# Remove spaces from ending of a string
text = "   Hello, World!   "
print(text.rstrip())  # Output: "   Hello, World!"








Key Points:




- strip(): removes characters from starting and ending of a string.
- lstrip(): removes characters from starting of a string.
- rstrip(): removes characters from ending of a string.
- By default, strip() removes spaces, but you can specify specific characters to remove.


=========================================
LBP36
Program: First Capital Letter in a String
=========================================




Problem Statement:
------------------
Implement a program to return the first capital letter in a string.




Input:
------
A string from the user




Constraint:
-----------
The string is non-empty




Output:
-------
First capital letter




-----------------------------------------
Python Program (With Comments)
-----------------------------------------




# Take input string from the user
s = input()




# Loop through each character in the string
for i in s:




    # Check if the character is an uppercase letter
    if i.isupper():




        # Print the first capital letter found
        print(i)




        # Stop the loop after first capital letter
        break




-----------------------------------------
Explanation:
-----------------------------------------
1. The program reads a string from the user.
2. It checks each character one by one.
3. When the first uppercase letter is found,
   it is printed.
4. The loop stops immediately after that.




-----------------------------------------
Example:
-----------------------------------------
Input:
heLloWorld




Output:
L
=========================================


================================================================
LBP37 


Case 1 - Toggle Case of Each Character (With using swapcase())




Implement a program to calculate toggle case of each characters of a string




input -------> A String from user
constraint --> non-empty String
output ------> toggle case string




A=>a
a=>A
code:------------------------------------------
s = input()
print(s.swapcase())






Case 2 - Toggle Case of Each Character (Without using swapcase())




s = input("Enter a string: ")




result = ""




for ch in s:




    # Check if character is uppercase letter
    if ch >= 'A' and ch <= 'Z':
        # Convert uppercase to lowercase
        result += chr(ord(ch) + 32)




    # Check if character is lowercase letter
    elif ch >= 'a' and ch <= 'z':
        # Convert lowercase to uppercase
        result += chr(ord(ch) - 32)




    else:
        # If the character is NOT a letter
        # (for example number, space, or symbol)
        # then keep it the same and add it to result
        result += ch




print("Toggle case string:", result)




Input:->Manish123! ,output:-mANISH123!


—------------------------------------------------------------
LBP38:-
A company launched a new text editor that allows users to enter english letters, numbers and white spaces only.
If a user attempts to enter any other type of characters, it is counted as miss.
Given a String text,
write an algorithm to help the developer detect the number of misses by a given user in the given input.




input -------> String
constraint ---> non-empty string
output -------> number of misses




# take input string from user
s = input()




# counter to count number of misses
c = 0




# loop through each character in the string
for i in s:




    # check if character is letter or number
    # isalnum() returns True for alphabets and numbers
    # isspace() returns True for space
    if i.isalnum() or i.isspace():
        # if valid character, skip it
        continue




    else:
        # if character is not letter, number or space
        # count it as a miss
        c = c + 1




# print total number of misses
print(c)
—---------------------------------------
(Without using functions)
# take input string
s = input()




# counter for misses
c = 0




# check each character
for i in s:




    # check if uppercase letter
    if i >= 'A' and i <= 'Z':
        continue




    # check if lowercase letter
    elif i >= 'a' and i <= 'z':
        continue




    # check if digit
    elif i >= '0' and i <= '9':
        continue




    # check if space
    elif i == ' ':
        continue




    else:
        # if character is not allowed
        c = c + 1




# print number of misses
print(c)




========================================================




LBP39:-LBP39




Implement the following function
    int BlackJack(int n1,int n2);




the function accepts two +ve integers n1 and n2 as its arguments.
Implement the function on given two values to return an int value as follows




return whichever value is nearest to 21 without going over. Return 0 if they both go over.




input --------> two int values n1 and n2
constraint ---> no
output -------> 0 or n1 or n2




python implementation:
----------------------




def bj(n1,n2):
    if n1>21 and n2>21:
        return 0
    if n1>21:
        return n2
    elif n2>21:
        return n1
    else:
        return max((n1,n2))




n1=int(input())
n2=int(input())
print(bj(n1,n2))




Input :
19
21
Output:
21




—----------------------------------------------------------------------------------------------
Without max()




# take first number from user
n1 = int(input())
# take second number from user
n2 = int(input())
# if both numbers are greater than 21
if n1 > 21 and n2 > 21:
    print(0)
# if n1 is greater than 21
elif n1 > 21:
    print(n2)
# if n2 is greater than 21
elif n2 > 21:
    print(n1)
# if both numbers are less than or equal to 21
else:
    # check which number is closer to 21
    if (21 - n1) < (21 - n2):
        print(n1)
    else:
        print(n2)


=======================================================
LBP40




A company wishes to transmit data to another server.
The data consists of numbers only.
To secure the data during transmission, they plan to reverse the data during transmission,
they plan to reverse the data first.
Write an algorithm to reverse the data first




input ----> an integer data, representing the data to be transmitted
output ----> print an integer representing the given data in reverse form








python implementation:
---------------------




s = input()
print(s[::-1])




=========================================================


LBP 41:-
One Time Password




A company wishes to devise an order confirmation procedure.
They plan to require an extra confirmation instead of simply auto-confirming
the order at the time it is placed. for this purpose,
the system will generate one time password to be shared with the customer.
The customer who is placing the order has to enter the OTP to confirm the order.
The OTP generated for the requested order ID, as the product of the digits in orderID.




Write an algorithm to find the OTP for the OrderID.




input ----> an intger representing order id
output ----> an integer representing OTP




logic:




p=1;
while(n!=0){
    d=n%10;
    p=p*d;
    n=n/10;
}
print p
python implementation:
----------------------
import math
print(math.prod([int(i) for i in input()]))
–Without math–
n = input()




p = 1
for i in n:
    p = p * int(i)




print(p)




Example1




Input (Order ID):
1234




Step-by-Step




Step    i (digit)    p calculation    p value
Start   -            p = 1            1
1       1            p = 1 × 1        1
2       2            p = 1 × 2        2
3       3            p = 2 × 3        6
4       4            p = 6 × 4        24




Output:
24
Meaning: OTP = product of the digits of the order ID.




Example 2)
Input:
305
Calculation:
3 × 0 × 5 = 0




Output:
0




=========================================================
LBP42




Jackson, a math student, is developing an application on prime numbers.
for the given two integers on the display of the application,
the user has to identify all the prime numbers within the given range (including the given values).
afterwards the application will sum all those prime numbers.
Jackson has to write an algorithm to find the sum of all the prime numbers of the given range.




Write an algorithm to find the sum of all the prime numbers of the given range.




input ----> two space seperated integers RL and RR.
output ----> sum of the prime numbers between RL and RR.




logic




s=0;
for(i=n1;i<=n2;i++){
    if(isprime(i))
        s=s+i;
}




python implementation:
----------------------




def isprime(n):
    f=0
    for i in range(1,n+1):
        if n%i==0:
            f=f+1
    return f==2




n1=int(input())
n2=int(input())
s=0
for i in range(n1,n2+1):
    if isprime(i):
        s=s+i




print(s)
—----------------------------------------
# take first number of the range
n1 = int(input())




# take second number of the range
n2 = int(input())




# variable to store sum of prime numbers
s = 0




# loop through all numbers from n1 to n2
for i in range(n1, n2+1):




    # f will count number of factors of i
    f = 0




    # check all numbers from 1 to i
    for j in range(1, i+1):




        # if j divides i completely then it is a factor
        if i % j == 0:
            f = f + 1




    # prime number has exactly 2 factors (1 and itself)
    if f == 2:
        s = s + i   # add the prime number to sum




# print the final sum of all prime numbers in the range
print(s)








=========================================================
LBP43
An e-Commerce company plans to give their customers a discount for the new year's holiday.
The discount will be calculated on the basis of the bill amount of the order place.
The discount amount is the product of the sum of all odd digits and the sum of all even digits of
the customers total bill amount.




input ----> an integer bill amount, representing the total bill amount of the customer.
output ----> print an integer representing the discount amount for the given total bill.




logic:




se=0
so=0
while(n!=0){
    d=n%10;
    if(d%2==0)
        se=se+d;
    else
        so=so+d;
    n=n/10;
}
print(se*so);




Implementation:-
—-------------------
# take the bill amount as input
n = int(input())




# se will store sum of even digits
se = 0




# so will store sum of odd digits
so = 0




# loop until all digits of the number are processed
while n != 0:




    # extract the last digit
    d = n % 10




    # check if the digit is even
    if d % 2 == 0:
        se = se + d      # add to even sum
    else:
        so = so + d      # add to odd sum




    # remove the last digit from number
    n = n // 10




# discount = (sum of even digits) * (sum of odd digits)
print(se * so)




Example




Input:
1234




Step Calculation:
Odd digits = 1 + 3 = 4
Even digits = 2 + 4 = 6




Discount = (sum of odd digits) × (sum of even digits)
Discount = 4 × 6 = 24




Output:
24




=========================================================




====Array Elements=======================================
LBP44: 
There is a great war between the even and odd numbers.
Many numbers already lost thier life in this war and its your task to end this.
You have to determine which group sums larger. the even, or the odd, the larger group wins.




Create a function that takes an array of integers , sums the even and odd numbers seperately,
then return the difference between sum of even and odd numbers.




input --------> number and array elements
constraint ---> no
output -------> difference between sum of even and odd numbers




logic:




se=0
so=0
for(i=0;i<n;i++)
{
    if(a[i]%2==0)
        se=se+a[i];
    else
        so=so+a[i];
}
diff=abs(se-so)




Code:-
—-----
# Take input for number of elements
n = int(input())




# Take list input and convert each value to integer
L = [int(i) for i in input().split()]




# Variable to store sum of even numbers
se = 0




# Variable to store sum of odd numbers
so = 0




# Loop through each number in list
for i in L:




    # Check if number is even
    if i % 2 == 0:
        se = se + i      # Add even number to even sum




    else:
        so = so + i      # Add odd number to odd sum




# Print absolute difference between even sum and odd sum
print(abs(se - so))








=========================================================
LBP45:-Perfect Number




Create a function that tests whether or not an integer is a perfect number.
A perfect number is a number that can be written as sum of its factors
(equal to sum of its proper divisors) excluding the number itself.




Input  -----> a number from the user
Constraint -----> n > 0
Output -----> true or false




Example:




4 -----> 1, 2, 4 -----> 1, 2 -----> 1+2 = 3
6 -----> 1, 2, 3, 6 -----> 1, 2, 3 -----> 1+2+3 = 6




Algorithm (Pseudo Code):




s = 0
for(i = 1; i < n; i++)
{
    if(n % i == 0)
        s = s + i
}




if s == n then yes else no




Python Implementation with Comments:




# Take number input from user
n = int(input())




# Variable to store sum of divisors
s = 0




# Loop from 1 to n-1 (proper divisors only)
for i in range(1, n):




    # Check if i is a divisor of n
    if n % i == 0:
        s = s + i   # Add divisor to sum




# Check if sum of divisors equals the number
# If yes → perfect number
# If no → not a perfect number
print('true' if s == n else 'false')








Example Run:




Input:
6




Output:
true








=============


LBP46




Magic Date




Program to read date, month and year from the user and check whether it is magic date or not.
Here are the rules for magic date.




1) mm*dd is a 1-digit number that matches the last digit in YYYY
2) mm*dd is a 2-digit number that matches the last two digits in YYYY
3) mm*dd is a 3-digit number that matches the last three digits in YYYY




input  -------> three int values
constraint ---> no
output -------> true or false








Examples




1-5-2005  ---> Yes
2-5-2005  ---> No
2-5-2010  ---> Yes












Python Implementation




# Take input in format: dd-mm-yyyy
L = [i for i in input().split("-")]




# L[0] = day
# L[1] = month
# L[2] = year




# Convert day and month to integer and multiply them
# Then check if the result matches the ending digits of the year
# endswith() checks if year ends with that multiplication result




print(str(L[2].endswith(str(int(L[0]) * int(L[1])))).lower())












Explanation




Step 1:
User enters date like:
2-5-2010




Step 2:
List becomes
L = ['2', '5', '2010']




Step 3:
Multiply day and month
2 * 5 = 10




Step 4:
Check if year ends with "10"




2010 ends with 10




Output
true




=========================================================
LBP47




Oddish or Evenish




Create a function that determines whether a number is Oddish or Evenish.




A number is Oddish if the sum of all of its digits is odd.
A number is Evenish if the sum of all of its digits is even.




If a number is Oddish return Oddish else return Evenish.








input ---------> a number
constraint ----> n > 0
output --------> Oddish or Evenish








Logic
-----




s = 0




while(n != 0)
{
    d = n % 10
    s = s + d
    n = n / 10
}




if s % 2 == 0 then print "Evenish" else "Oddish"












Python Implementation
---------------------




# Take number input from user
# Example: 1234




print("Evenish" if sum([int(i) for i in input()]) % 2 == 0 else "Oddish")












Explanation
-----------




input()            -> takes number as string
for i in input()   -> loop through each digit
int(i)             -> convert digit to integer
sum([...])         -> add all digits




Example




Input
1234




Digits
1 + 2 + 3 + 4 = 10




10 % 2 = 0




Output
Evenish








Example




Input
123




Digits
1 + 2 + 3 = 6




6 % 2 = 0




Output
Evenish








Example




Input
111




Digits
1 + 1 + 1 = 3




3 % 2 = 1




Output
Oddish




=========================================================


LBP48




Accept video length in minutes the format is mm:ss in String format, 
create a function that takes video length and return it in seconds.




input --------> video length in mm:ss
constraint ---> no
output -------> length in seconds








Examples




01:00  ====> 60




02:05  ====> 120 + 5 = 125




22:01  ====> 1320 + 1 = 1321








Note




01 ----> 0 ----> octal
01 ----> int(01) ----> 1








C Logic




int convert(char ch){
    return ch - 48;
}








ASCII Values




a = 97
A = 65
0 = 48
1 = 49
and so on








Example




01 ===> char,char




'0' - 48  ===> 48 - 48 = 0




'1' - 48  ===> 49 - 48 = 1












Python Implementation
---------------------




# Take input in mm:ss format
# Example input: 02:05




l = input().split(":")




# l[0] -> minutes
# l[1] -> seconds




# Convert minutes into seconds and add remaining seconds
print(int(l[0]) * 60 + int(l[1]))












Example Run




Input
02:05




Output
125








=========================================================
LBP49




Next Prime




Given an integer, create a function that returns the next prime.
If the number is prime, return the number itself.




input ---------> a number
constraint ----> prime number
output --------> prime number








Logic
-----




f = 0




for(i = 1; i <= n; i++)
{
    if(n % i == 0)
        f++;
}




if f == 2 then it is prime else not












Python Implementation
---------------------




# Function to check whether a number is prime or not
def isprime(n):




    f = 0   # counter to count number of factors




    # check all numbers from 1 to n
    for i in range(1, n+1):




        # if i divides n then it is a factor
        if n % i == 0:
            f = f + 1




    # a prime number has exactly 2 factors (1 and itself)
    return f == 2








# take input number
n = int(input())




# keep checking numbers until we find a prime
while True:




    if isprime(n):   # if number is prime
        print(n)     # print it
        break        # stop the loop




    n = n + 1        # otherwise check next number








====================================================
LBP50




Sum of digits between two numbers




Create a function that sums the total number of digits between two numbers inclusive.
For example, if the numbers are 19 and 22, then




(1+9) + (2+0) + (2+1) + (2+2) = 19








input ---------> a number from the user
constraints ---> no
output --------> sum of digits








Logic
-----




for(i = n1; i <= n2; i++)
{
    s = s + sumofdigits(i);
}




print s value












Python Implementation
---------------------




# Take first number
n1 = int(input())




# Take second number
n2 = int(input())




# Variable to store total sum
s = 0




# Loop from n1 to n2 (inclusive)
for i in range(n1, n2 + 1):




    # Convert number to string so we can access each digit
    # Convert each digit back to integer and sum them
    s = s + sum([int(j) for j in str(i)])




# Print final result
print(s)












Example




Input
19
22




Numbers
19 → 1+9 = 10
20 → 2+0 = 2
21 → 2+1 = 3
22 → 2+2 = 4




Total
10 + 2 + 3 + 4 = 19




Output
19




=========================================================
LBP51




Defanging an IP address




Given a valid IP address, return a defanged version of that IP address.
A defanged IP address replaces every period "." with "[.]".




input ---------> A string
constraint ----> non-empty string
output --------> replacement string




.  ====>  [.]








Python Implementation
---------------------




# Take IP address input from user
s = input()




# replace() function '.' ko '[.]' se replace karega
# '.'  -> old character
# '[.]' -> new replacement string
result = s.replace('.', '[.]')




# Print the defanged IP address
print(result)
Input
192.168.1.1




Output
192[.]168[.]1[.]1








=========================================================
LBP52




Jewels and Stones




You are given strings jewels representing the types of stones that are jewels,
and stones representing the stones you have.




Each character in stones is a type of stone you have.
You want to know how many of the stones you have are also jewels.




Letters are case sensitive.
So "a" is considered a different type of stone from "A".




input --------> A string
constraint ---> no
output -------> how many of the stones








Python Implementation
---------------------




# Take input for jewels
s1 = input()




# Take input for stones
s2 = input()




# Variable to store count of jewels found in stones
c = 0




# Loop through each character in jewels
for i in s1:




    # count() counts how many times jewel appears in stones
    c = c + s2.count(i)




# Print total count
print(c)








Example




Input
aA
aAAbbbb




Explanation
Jewels = aA
Stones = aAAbbbb




'a' appears 1 time
'A' appears 2 times




Total = 3




Output
3




=========================================================
LBP53




Given a string s, and an integer array indices of the same length.
The string s will be shuffled such that the character at the ith position
moves to indices[i] in the shuffled string.




Return shuffled string.








input ---------> a string and an array
constraint ----> no
output --------> a string












Example




s = aiohn
a = 3 1 4 2 0




Index positions




s[0] = a
s[1] = i
s[2] = o
s[3] = h
s[4] = n




a[0] = 3
a[1] = 1
a[2] = 4
a[3] = 2
a[4] = 0








Now place characters according to indices




b[a[0]] = s[0]  → b[3] = a
b[a[1]] = s[1]  → b[1] = i
b[a[2]] = s[2]  → b[4] = o
b[a[3]] = s[3]  → b[2] = h
b[a[4]] = s[4]  → b[0] = n








Final array




b = n i h a o




Output
nihao












Python Implementation
---------------------




# Take string input
s = input()




# Take array input and convert to integers
a = [int(i) for i in input().split()]




# Create empty list with same length as string
b = [0] * len(s)




# Loop through string indices
for i in range(0, len(s)):




    # Place character at correct shuffled index
    b[a[i]] = s[i]




# Join list into string and print result
print("".join(b))




=========================================================
LBP54




Get word count




Create a function/method that takes a string and return the word count.
The string will be a sentence.




Input: A string
Constraints: No
Output: Word count








Python Implementation
---------------------




# Take sentence input from user
s = input()




# split() sentence ko words me divide karta hai
# Default separator space hota hai
l = s.split()




# len() list ke total elements (words) count karta hai
print(len(l))








Example




Input
I love python programming




After split
['I', 'love', 'python', 'programming']




Word count
4




Output
4




=========================================================


=========================================================
LBP55




Check if String ending matches second String




Create a function/method that takes two strings and returns true if the
first string ends with second string, otherwise return false.




Input: two strings
Constraints: No
Output: true or false












Python Implementation
---------------------




# Take first string input
s1 = input()




# Take second string input
s2 = input()




# endswith() check karta hai ki s1 ka ending s2 se match karta hai ya nahi
# Agar match karega to True return karega, warna False




print('true' if s1.endswith(s2) else 'false')












Example




Input
programming
ming




Explanation
programming ka ending "ming" hai




Output
true




=========================================================
LBP56




Shuffle the Name




Create a function/method that accepts a string (of person's first and last name)
and returns a string with first and last name swapped.




Input: two space separated strings
Constraints: No
Output: return last name followed by first name




Python Implementation
---------------------




# Take first name input
s1 = input()




# Take last name input
s2 = input()




# Print last name first and then first name
print(s2, s1)












Example




Input
John
Doe




Output
Doe John




=========================================================
LBP57




Reverse the order of a String




Create a method/function that takes a string as its argument
and returns the string in reversed order.




input --------> a string
constraint ---> no
output -------> reversed string












Stack




Stack follows the concept of LIFO (Last In First Out).
The element that is inserted last will be removed first.




Example:
If elements are pushed like this




A
B
C




Then popping will give




C
B
A




So the last element inserted comes out first.












Stack in Different Languages




C      ====> Arrays and Pointers
C++    ====> Arrays, Stack and Pointers
Java   ====> Arrays, Stack
Python ====> List, Stack








Python Stack Operations




List ====> append(), pop()




append() -> adds an element to the stack (push operation)




pop() -> removes the last element from the stack (pop operation)












Python Implementation (Using Slicing)
-------------------------------------




# input() takes a string from the user
# [::-1] is slicing used to reverse a string




# slicing syntax
# string[start : stop : step]




# step = -1 means move in reverse direction




print(input()[::-1])












Example




Input
hello




Output
olleh












Another Example




Input
python




Output
nohtyp




—-------------------------------------------------------------------------------------------------
Python Slicing Examples




Slicing Syntax
string[start : stop : step]




start -> starting index
stop -> ending index (not included)
step -> step size / direction








Example 1: Basic Slicing




s = "python"
print(s[0:3])




Output
pyt




Explanation
Index 0 = p
Index 1 = y
Index 2 = t








Example 2: From Start




s = "python"
print(s[:4])




Output
pyth




Explanation
Start defaults to 0
Stop = 4








Example 3: Till End




s = "python"
print(s[2:])




Output
thon




Explanation
Start = index 2
Stop = end of string








Example 4: Step Slicing




s = "python"
print(s[::2])




Output
pto




Explanation
Takes every second character








Example 5: Reverse String (Important)




s = "hello"
print(s[::-1])




Output
olleh




Explanation
Step = -1 so string is read in reverse direction








Example 6: Reverse using input




s = input("Enter string: ")
print(s[::-1])




Example




Input
coding




Output
gnidoc








Index Diagram




String = python




Index
0 1 2 3 4 5
p y t h o n




Examples




s[1:4] -> yth
s[::2] -> pto
s[::-1] -> nohtyp 
=========================================================


LBP58




Re-form the word




A word has been split into a left part and right part.
Re-form the word by adding both halves together changing the first to an uppercase letter.




input ---------> two strings from the user
constraint ----> no
output --------> concatenated string with caps in first character








Example
prakash, babu  ====>  Prakashbabu












Python Implementation
---------------------




# Take first part of the word
s1 = input()




# Take second part of the word
s2 = input()




# Combine both strings using +
# title() converts the first letter to uppercase
print((s1 + s2).title())




======================
LBP59




ANAGRAMS




Two strings a and b are called anagrams if they contain all the same characters 
in the same frequencies.




Input
-----
Two strings a and b




Constraint
----------
No constraint




Output
------
true or false








Example
-------
abc, bca  ---> true
abc, bcc  ---> false








Logic
-----
read s1
read s2
sort s1 in ascending order
sort s2 in ascending order
compare the two strings for equality ---> true or false








Example of sorting
------------------
abc  ---> abc
bca  ---> abc








Python Implementation
---------------------




# Read first string from user
s1 = input()




# Read second string from user
s2 = input()




# sorted() function converts the string into a list of characters
# and sorts the characters in ascending order
# Example: "bca" -> ['a','b','c']




# If both sorted strings are equal, then they are anagrams
# otherwise they are not anagrams




print('true' if sorted(s1) == sorted(s2) else 'false')




Output Example
--------------
Input
abc
bca




Output
true




Input
abc
bcc




Output
false




=========================================================
LBP60




MAX OCCURRING CHARACTER




Given a string, implement a program to find the max occurring character in the given string.




Input
-----
A string from the user.




Constraints
-----------
No




Output
------
Max occurring character








Example
-------
welcome  ===> e
java     ===> a








Logic
-----




# Create an array of size 256 to store frequency of each character
a[256] = {0}




# Traverse the string
for(i = 0; s[i]; i++)
{
    # Increase frequency of character
    a[s[i]]++;
}




Example Frequency Count




a[97] = 2   -> 'a'
a[j]  = 1
a[v]  = 1




max element is 2








Python Implementation
---------------------




import collections




# Read string from user
s = input()




# Counter() counts frequency of each character
r = collections.Counter(s)




# print(r)  -> This would print the dictionary of character frequencies




# max() finds the character having maximum frequency
# key = r.get tells max() to compare values (frequencies)
print(max(r, key = r.get))








Output Example
--------------




Input
welcome




Output
e




=========================================================
LBP61




DETERMINE THE COLOR OF A CHESS BOARD SQUARE








Problem
-------
You are given coordinates of a chess board square.
Return True if the square is White and False if the square is Black.








Input
-----
A string (example: a1, b3, c4)




Constraint
----------
Length of string = 2
First character = a to h
Second character = 1 to 8




Output
------
true or false








Chess Board Diagram
-------------------




      a   b   c   d
    +---+---+---+---+
4   | W | B | W | B |
    +---+---+---+---+
3   | B | W | B | W |
    +---+---+---+---+
2   | W | B | W | B |
    +---+---+---+---+
1   | B | W | B | W |
    +---+---+---+---+








Example
-------




a1 → Black
a2 → White
b1 → White
b2 → Black








Observation
-----------




If column number and row number have
same parity (both even or both odd) → Black




If parity is different → White








Letter to Number Conversion
---------------------------




a → 1
b → 2
c → 3
d → 4
e → 5
f → 6
g → 7
h → 8








ASCII Values
------------




ord('a') = 97
ord('b') = 98
ord('1') = 49
ord('2') = 50








Logic
-----




1. Read coordinate string
2. Convert column letter to number
3. Get row number
4. Check parity using modulo
5. If parity different → White
6. Else → Black








Python Implementation
---------------------




# Read coordinate from user
s = input()




# Convert column letter into number
# Example: 'a' → ASCII 97 → 97 - 96 = 1
x = ord(s[0]) - 96




# Convert row character to ASCII value
y = ord(s[1])




# If parity different → white square
# If parity same → black square
print("true" if x % 2 != y % 2 else "false")








Example Run
-----------




Input
a1




Output
false




=========================================================
Collections Library (Python)




collections is a built-in Python module that provides special data structures 
to store and manage data efficiently.




It extends the functionality of basic containers like list, tuple and dictionary.




Example:
import collections




Common Classes in collections:
1. Counter      -> Counts frequency of elements
2. defaultdict  -> Dictionary with default values
3. OrderedDict  -> Dictionary that maintains insertion order
4. deque        -> Double-ended queue (fast insert/delete)




Example of Counter:




import collections
s = "banana"
r = collections.Counter(s)




Output:
{'b':1, 'a':3, 'n':2}




Meaning:
b appears 1 time
a appears 3 times
n appears 2 times
—-------------------------------------------------------------------------------------------------
get() Function (Python Dictionary)




get() is a dictionary method used to get the value of a specific key.




Syntax
------
dictionary.get(key)




If the key exists, it returns the value.
If the key does not exist, it returns None instead of giving an error.








Example
-------




d = {'a':3, 'b':2, 'c':1}




print(d.get('a'))




Output
------
3








Use in Max Occurring Character
------------------------------




import collections




s = input()




# Counter counts frequency of each character
r = collections.Counter(s)




Example:
If s = "banana"




r = {'b':1, 'a':3, 'n':2}




Here
r.get('a') = 3
r.get('b') = 1
r.get('n') = 2








print(max(r, key = r.get))








Explanation
-----------




max() finds the maximum key based on the value.




key = r.get means:
max() should compare the values (frequencies) of the keys.




So max() checks:




a -> r.get('a') = 3
b -> r.get('b') = 1
n -> r.get('n') = 2




Maximum value = 3




So output = a
















=========================================================
LBP62




FIND THE BOMB








Problem
-------
Write a function that finds the word "bomb" in the given string.
The search should NOT be case sensitive.




If the word "bomb" is found → return "DUCK!"
Otherwise → return "Relax, there's no bomb."








Input
-----
A string








Constraint
----------
No constraint








Output
------
"DUCK!" 
or 
"Relax, there's no bomb."








Example
-------




Input
There is a bomb in the room




Output
DUCK!








Input
Hello how are you




Output
Relax, there's no bomb.








Logic
-----




1. Read the input string.
2. Convert the string to lowercase.
3. Check if the word "bomb" exists in the string.
4. If found → print "DUCK!"
5. Otherwise → print "Relax, there's no bomb."








Python Implementation
---------------------




# Read input string from user
# lower() converts the string to lowercase
# so that BOMB, Bomb, bomb all become "bomb"




s = input().lower()




# Check if the word "bomb" exists in the string
# "in" operator checks substring presence




print("DUCK!" if "bomb" in s else "Relax, there's no bomb.")








Example Run
-----------




Input
Hey there is a BOMB here




Process
String converted to lowercase → "hey there is a bomb here"




Output
DUCK!




=========================================================
LBP63




HOW MANY VOWELS








Problem
-------
Create a function that takes a string and returns the number of vowels contained within it.








Input
-----
A string








Constraint
----------
No constraint








Output
------
Number of vowels








Vowels
------
a, e, i, o, u
A, E, I, O, U








Example
-------




Input
hello




Output
2








Input
education




Output
5








Logic
-----




1. Read the string from the user.
2. Initialize a counter variable c = 0.
3. Traverse each character in the string.
4. Check if the character is a vowel.
5. If it is a vowel → increase the counter.
6. Print the final count.








Python Implementation
---------------------




# Read input string
s = input()




# Initialize counter
c = 0




# Traverse each character in the string
for i in s:




    # Check if character is a vowel
    if i in "aeiouAEIOU":




        # Increase vowel count
        c = c + 1




# Print total number of vowels
print(c)








Example Run
-----------




Input
Apple




Process
A → vowel
p → not vowel
p → not vowel
l → not vowel
e → vowel




Output
2




=========================================================
LBP64




X's and O's, Nobody knows








Problem
-------
Create a function that takes a string and checks if it has the same
number of x's and o's and returns either true or false.








Rules
-----




1. Return boolean value true or false.
2. Return true if the number of x's and o's are the same.
3. Return false if they are not the same.
4. The string can contain any character.
5. When 'x' and 'o' are not present in the string, return true.








Input
-----
A string




Constraint
----------
No constraint




Output
------
true or false








Example
-------




Input
xxoo




Output
true








Input
xxxoo




Output
false








Logic
-----




1. Read the input string.
2. Count number of 'x' characters in the string.
3. Count number of 'o' characters in the string.
4. Compare both counts.
5. If counts are equal → print true.
6. Otherwise → print false.








Python Implementation
---------------------




# Read input string
s = input()




# Count number of 'x' in the string
xc = s.count('x')




# Count number of 'o' in the string
oc = s.count('o')




# Compare both counts
# If equal → true
# If not equal → false
print('true' if xc == oc else 'false')








Example Run
-----------




Input
xoxoxo




Process
x count = 3
o count = 3




Output
true




=========================================================
LBP65




STUTTERING FUNCTION








Problem
-------
Write a function that stutters a word as if someone is struggling to read it.




The first two letters of the word are repeated twice with an ellipsis (...)
and then the word is pronounced with a question mark (?).








Input
-----
A string








Constraint
----------
No constraint








Output
------
xx... xx... word?








Example
-------




Input
incredible




Output
in... in... incredible?








Input
apple




Output
ap... ap... apple?








Logic
-----




1. Read the input word.
2. Take the first two characters of the word.
3. Print the first two characters followed by "...".
4. Repeat it two times.
5. Then print the complete word followed by "?".




Example
-------




Word = apple




First two characters = ap




Output format
ap... ap... apple?








Python Implementation
---------------------




# Read input word
s = input()




# s[0] -> first character
# s[1] -> second character




# Print first two characters twice with "..."
# then print the full word with "?"




print(f"{s[0]}{s[1]}...{s[0]}{s[1]}...{s}?")








Example Run
-----------




Input
hello




Process
he... he... hello?




Output
he... he... hello?






LBP66:REPEATING LETTERS
Problem
-------
Create a method that takes a string and returns a string
in which each character is repeated once.








Input
-----
String from the user








Constraint
----------
No constraint








Output
------
String








Example
-------




Input
hello




Output
hheelllloo








Input
abc




Output
aabbcc








Logic
-----




1. Read the string from the user.
2. Traverse each character in the string.
3. Repeat each character two times.
4. Print the result.








Python Implementation
---------------------




# Read input string
s = input()




# Traverse each character in the string
for i in s:




    # i*2 repeats the character two times
    # end='' keeps output in same line
    print(i*2, end='')




















Example Run
-----------




Input
cat




Process
c → cc
a → aa
t → tt




Output
ccaatt




=========================================================
LBP67




DOUBLE LETTERS








Problem
-------
Create a function that takes a word and returns true if the word
has two consecutive identical letters.








Input
-----
A string








Constraint
----------
No constraint








Output
------
true or false








Example
-------




aabc  -> true
baba  -> false
abba  -> true








Logic
-----




1. Read the input string.
2. Traverse the string from index 0 to length-1.
3. Compare current character with the next character.
4. If both characters are same → set found = True.
5. Stop the loop.
6. Print the result.








Python Implementation
---------------------




# Read input string
s = input()




# Flag variable to check if consecutive letters exist
found = False




# Traverse string until second last character
for i in range(len(s)-1):




    # Compare current character with next character
    if s[i] == s[i+1]:




        # If equal, set found to True
        found = True




        # Stop checking further
        break








# Convert boolean result to lowercase string (true/false)
print(str(found).lower())








Example Run
-----------




Input
hello




Process
h != e
e != l
l == l  → consecutive letters found




Output
true




=========================================================




LBP68




PLAYER SCORE GAME








Problem
-------
Andy, Ben and Charlotte are playing a board game.




The three players decided to create a new scoring system.




A player's first initial:
A → Andy
B → Ben
C → Charlotte




Each letter represents one point scored by that player.




Given a string of capital letters, return the score of each player.








Input
-----
A string








Constraint
----------
No constraint








Output
------
Score of players A, B, C








Example
-------




Input
AABBC




Output
A = 2
B = 2
C = 1








Explanation
-----------
A appears 2 times
B appears 2 times
C appears 1 time








Logic
-----




1. Read the string from the user.
2. Count number of 'A' characters.
3. Count number of 'B' characters.
4. Count number of 'C' characters.
5. Print the counts.








Python Implementation
---------------------




# Read input string
s = input()




# count() counts how many times a character appears in the string




print(
    s.count('A'),   # count of player A
    s.count('B'),   # count of player B
    s.count('C')    # count of player C
)








Example Run
-----------




Input
ABACBC




Process
A → 2
B → 2
C → 2




Output
2 2 2




=========================================================


LBP69




REMOVE EVERY VOWEL FROM A STRING








Problem
-------
Create a function that takes a string and returns a new string
with all vowels removed.








Input
-----
A string








Constraint
----------
No constraint








Output
------
A string without vowels








Vowels
------
a, e, i, o, u








Example
-------




Input
hello




Output
hll








Input
education




Output
dctn








Logic
-----




1. Read the string from the user.
2. Identify vowels (a, e, i, o, u).
3. Remove all vowels from the string.
4. Print the remaining characters.








Python Implementation
---------------------




# Import regular expression module
import re




# re.sub(pattern, replacement, string)
# [aeiou] matches any vowel
# "" replaces vowel with empty string




print(re.sub("[aeiou]", "", input()))








Example Run
-----------




Input
computer




Process
Remove vowels → o, u, e




Output
cmptr




=========================================================


========================================================
LBP70




SPACE BETWEEN EACH CHARACTER








Problem
-------
Create a function that takes a string and returns a string
with spaces in between all of the characters.








Input
-----
A string








Constraint
----------
No constraint








Output
------
A string with spaces between characters








Example
-------




Input
hello




Output
h e l l o








Input
python




Output
p y t h o n








Logic
-----




1. Read the string from the user.
2. Traverse each character of the string.
3. Print each character followed by a space.
4. Keep printing on the same line.








Python Implementation
---------------------




# Read input string
s = input()




# Traverse each character
for i in s:




    # Print character with space
    # end=' ' keeps output in same line
    print(i, end=' ')








Example Run
-----------




Input
code




Process
c → c
o → o
d → d
e → e




Output
c o d e




========================================================
========================================================
LBP71
VOWEL REPLACER
Problem
-------
Create a function that replaces all the vowels in a string
with a specified character.








Input
-----
A string from the user
A character from the user








Constraint
----------
No constraint








Output
------
A string








Example
-------




Input
hello
*




Output
h*ll*








Input
education
#




Output
#d#c#t##n








Logic
-----




1. Read the string from the user.
2. Read the replacement character from the user.
3. Traverse each character in the string.
4. If the character is a vowel (a, e, i, o, u):
      replace it with the given character.
5. Otherwise keep the character as it is.
6. Print the final string.








Python Implementation
---------------------




# Import regular expression module
import re




# Read string from user
s1 = input()




# Read replacement character
s2 = input()




# re.sub(pattern, replacement, string)
# [aeiou] matches vowels
# vowels are replaced by the user given character




print(re.sub("[aeiou]", s2, s1))








Example Run
-----------




Input
apple
*




Process
Replace vowels a, e with *




Output
*ppl*


LBP72




SAY "HELLO" SAY "BYE"








Problem
-------
Write a function that takes a string name and a number num (either 1 or 0).




If number = 1 → return "Hello" + name  
Otherwise → return "Bye" + name.








Input
-----
A string from the user
A number (0 or 1)








Constraint
----------
No constraint








Output
------
A string








Example
-------




Input
Manish
1




Output
Hello Manish








Input
Rahul
0




Output
Bye Rahul








Logic
-----




1. Read the name from the user.
2. Read the number from the user.
3. Check the value of the number.
4. If number = 1 → print "Hello" + name.
5. Otherwise → print "Bye" + name.








Python Implementation
---------------------




# Read name from user
s = input()




# Read number from user
n = int(input())




# Check condition
if n == 1:




    # Print Hello with name
    print("Hello", s)




else:




    # Print Bye with name
    print("Bye", s)








Example Run
-----------




Input
Alex
1




Output
Hello Alex






LBP73




VALID ZIP CODE








Problem
-------
Zipcodes consist of 5 consecutive digits.




Given a string, write a function to determine whether the input
is a valid zip code.




A valid zip code must follow these rules:




1. Must contain only numbers.
2. It should not contain any spaces.
3. Length should be exactly 5.








Input
-----
A string








Constraint
----------
No constraint








Output
------
true or false








Example
-------




Input
12345




Output
true








Input
12a45




Output
false








Logic
-----




1. Read the input string.
2. Initialize a counter variable.
3. Traverse each character of the string.
4. Check if the character is a digit (0–9).
5. If yes → increase the counter.
6. If total digits = 5 → valid zip code.
7. Otherwise → invalid zip code.








Python Implementation
---------------------




# Read input string
s = input()




# Counter for digits
c = 0




# Traverse each character
for i in s:




    # Check if character is a digit
    if i.isdigit():




        # Increase digit count
        c = c + 1








# Check if exactly 5 digits exist
print("true" if c == 5 else "false")








Example Run
-----------




Input
54321




Process
5 → digit
4 → digit
3 → digit
2 → digit
1 → digit




Total digits = 5




Output
true




=========================================================




=========================================================
LBP74




RETURN THE MIDDLE CHARACTER OF A STRING








Problem
-------
Create a function that takes a string and returns the middle character(s).




If the word length is odd → return the middle character.  
If the word length is even → return the middle two characters.








Input
-----
A string from the user








Constraint
----------
No constraint








Output
------
Middle character(s)








Example
-------




Input
abc




Output
b








Input
abcd




Output
bc








Logic
-----




1. Read the string from the user.
2. Find the length of the string.
3. Check if the length is even or odd.




If length is even:
    print s[n/2 - 1] and s[n/2]




If length is odd:
    print s[n/2]








Python Implementation
---------------------




# Read input string
s = input()




# Find length of string
n = len(s)




# Check if length is even
if n % 2 == 0:




    # Print middle two characters
    # sep='' prints without space
    print(s[n//2 - 1], s[n//2], sep='')




else:




    # Print middle character
    print(s[n//2])








Example Run
-----------




Input
python




Process
Length = 6 (even)




Middle characters
s[2] = t
s[3] = h




Output
th




=========================================================


LBP75




INDEX OF FIRST VOWEL








Problem
-------
Create a function that returns the index of the first vowel in a string.








Input
-----
A string








Constraint
----------
No constraint








Output
------
An integer value (index of first vowel)








Vowels
------
a, e, i, o, u








Example
-------




Input
hello




Output
1








Explanation
-----------
h → index 0 (not vowel)
e → index 1 (vowel)








Logic
-----




1. Read the string from the user.
2. Traverse the string using index.
3. Check if the character is a vowel.
4. If vowel found → print the index.
5. Stop the loop.








Python Implementation
---------------------




# Read input string
s = input()




# Traverse string using index
for i in range(0, len(s)):




    # Check if character is a vowel
    if s[i] in "aeiou":




        # Print index of first vowel
        print(i)




        # Stop checking further
        break








Example Run
-----------




Input
program




Process
p → index 0 (not vowel)
r → index 1 (not vowel)
o → index 2 (vowel)




Output
2












=========================================================


LBP76




LONGEST WORD








Problem
-------
Write a function that finds the longest word in a sentence.




If two or more words have the same maximum length,
return the first longest word.




Characters such as apostrophe, comma, period etc.
are considered part of the word.




Example:
O'Connor → length = 8








Input
-----
A string from the user








Constraint
----------
No constraint








Output
------
Longest word








Example
-------




Input
I love programming




Output
programming








Input
Python is powerful




Output
powerful








Logic
-----




1. Read the sentence from the user.
2. Split the sentence into words.
3. Initialize a variable to store maximum length.
4. Traverse each word.
5. Compare the length of the word with current maximum.
6. If greater → update maximum and store the word.
7. Print the longest word.








Python Implementation
---------------------




# Split input sentence into list of words
L = input().split()




# Variable to store maximum length
m = 0




# Variable to store longest word
s = ""




# Traverse each word
for i in L:




    # Check length of word
    if len(i) > m:




        # Update maximum length
        m = len(i)




        # Store longest word
        s = i








# Print longest word
print(s)








Example Run
-----------




Input
Coding is very interesting




Process
Coding → length 6
is → length 2
very → length 4
interesting → length 11




Output
interesting




=========================================================
=========================================================
LBP77  PRINT ALL PERMUTATIONS OF A STRING
Problem
-------
Given a string str, print all permutations of the string.




A permutation is an arrangement of all or part of a set of objects
with regard to the order of the arrangement.




Example:
The words "bat" and "tab" are two different permutations
of the same word.








Input
-----
A string from the user








Constraint
----------
No constraint


Output
------
All permutations of the string


Example
-------
Input
abc


Output
abc acb bac bca cab cba


Explanation
-----------
All possible arrangements of characters of "abc" are printed.
Logic
-----
1. Read the string from the user.
2. Generate all permutations of the string.
3. Convert each permutation tuple into a string.
4. Print all permutations.
Python Implementation
---------------------




# Import permutations function
from itertools import permutations




# Generate permutations of the input string
l = list(permutations(input()))




# Traverse each permutation
for i in l:




    # Join tuple characters to form a string
    print("".join(i), end=' ')


Example Run
-----------
Input
ab


Process
Permutations → ab, ba


Output
ab ba


========================================================================
PLB78


REMOVING DUPLICATE CHARACTERS FROM A STRING


Definition:
Remove all duplicate characters and keep only first occurrence




Problem Statement:
Given a string S, remove all duplicate characters


Input:
a string from the user


Constraint:
remove all duplicates


Output:
a string without duplicates




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Input String:
a b a c b a




Step by step:


Take 'a' → not present → add → [a]  
Take 'b' → not present → add → [a,b]  
Take 'a' → already present → skip  
Take 'c' → not present → add → [a,b,c]  
Take 'b' → already present → skip  
Take 'a' → already present → skip  


Final list:
[a, b, c]


Output:
abc




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Take input string
- Create empty list
- Traverse each character:
    - If character not in list:
        - Add it
- Join list into string
- Print result




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input string
s = input()


# empty list to store unique characters
l = []


# traverse string
for ch in s:
    if ch not in l:     # check duplicate
        l.append(ch)


# join list into string
result = ''.join(l)


# print result
print(result)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
abacba




--------------------------------------------------
OUTPUT
--------------------------------------------------
abc




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
''.join(list) → convert list to string




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB79


SWAP CORNER WORDS AND REVERSE MIDDLE WORDS


Definition:
- First word ↔ Last word swap
- Middle words → reverse




Problem Statement:
Take a string and:
- Exchange first and last word
- Reverse all middle words


Input:
a string


Constraint:
No


Output:
a modified string




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Input:
abc   def   mno   xyz




Step 1: Split into words
[abc, def, mno, xyz]




Step 2: Swap first and last
[xyz, def, mno, abc]




Step 3: Reverse middle words
def → fed  
mno → onm  


Final Output:
xyz fed onm abc




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Take input string
- Split into words using split()
- Print last word first
- Reverse middle words using [::-1]
- Print first word at end




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input string
s = input()


# split into words
words = s.split()


# print last word
print(words[-1], end=' ')


# reverse middle words
for i in range(len(words)-2, 0, -1):
    print(words[i][::-1], end=' ')


# print first word
print(words[0])




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
abc def mno xyz




--------------------------------------------------
OUTPUT
--------------------------------------------------
xyz fed onm abc




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
[::-1] → reverse string




========================================================================PLB80


VALID HEX CODE


Definition:
Hex code is a color code like #A1B2C3




Problem Statement:
Check whether a given string is a valid hex code


Conditions:
1. Must start with '#'
2. Length must be exactly 7 (# + 6 characters)
3. Characters must be:
   - digits (0-9)
   - or letters (A-F / a-f)




Input:
a string


Constraint:
No


Output:
True or False




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Valid Example:
#A1B2C3


Check:
# ✔
Length 7 ✔
A-F / 0-9 ✔




Invalid Example:
#G12Z56


G ❌
Z ❌




--------------------------------------------------
PYTHON IMPLEMENTATION (NORMAL)
--------------------------------------------------


s = input()


if len(s) == 7 and s[0] == '#':

    valid = True

    for ch in s[1:]:
        if not (ch.isdigit() or ch.lower() in "abcdef"):
            valid = False
            break

    print(valid)


else:
    print(False)




--------------------------------------------------
PYTHON IMPLEMENTATION (REGEX SHORTCUT)
--------------------------------------------------


import re


print('true' if re.fullmatch(r"#[A-Fa-f0-9]{6}", input()) else 'false')




--------------------------------------------------
REGEX EXPLANATION
--------------------------------------------------


# → must start with #
[A-Fa-f0-9] → allowed characters
{6} → exactly 6 characters


Total → # + 6 chars = 7 length




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
#A1B2C3




--------------------------------------------------
OUTPUT
--------------------------------------------------
true




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
PLB81


EVEN LENGTH WORDS


Definition:
Even length words → words whose length is divisible by 2




Problem Statement:
Write a program to print even length words in a string


Input:
a string from the user


Constraint:
No


Output:
list of words with even length




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Input:
hello world java




Break words:
hello → length 5 ❌  
world → length 5 ❌  
java  → length 4 ✔  




Output:
java




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Take input string
- Split into words using split()
- Traverse each word:
    - If length % 2 == 0:
        - Print word




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input string
s = input()


# split into words
words = s.split()


# check each word
for w in words:
    if len(w) % 2 == 0:   # even length check
        print(w, end=' ')




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
hello world java




--------------------------------------------------
OUTPUT
--------------------------------------------------
java




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Even condition:
len(word) % 2 == 0




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB82


CHANGE EVERY LETTER TO THE NEXT LETTER


Definition:
Replace each character with its next character  
Example:
a → b  
b → c  
d → e  




Problem Statement:
Write a program to change every letter to the next letter


Note:
No 'z' in test cases




Input:
a string from the user


Constraint:
No


Output:
modified string




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Input:
abc xyz




ASCII concept:


a → 97 → +1 → 98 → b  
b → 98 → +1 → 99 → c  
c → 99 → +1 → 100 → d  




Output:
bcd yza




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Take input string
- Traverse each character
- Convert char → ASCII using ord()
- Add 1
- Convert back using chr()
- Print result




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input string
s = input()


# change each character
for ch in s:
    # convert to ASCII → add 1 → convert back
    print(chr(ord(ch) + 1), end='')




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
abc




--------------------------------------------------
OUTPUT
--------------------------------------------------
bcd




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
ord(ch) → gives ASCII value  
chr(num) → converts ASCII to character




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB 83


FIRST N VOWELS


Definition:
Vowels → a, e, i, o, u




Problem Statement:
Return first n vowels from a string


Input:
a string and an integer n


Constraint:
Return "invalid" if n > total vowels


Output:
first n vowels




--------------------------------------------------
LOGIC
--------------------------------------------------


- Extract vowels from string
- If n > total vowels → invalid
- Else print first n vowels




--------------------------------------------------
PYTHON IMPLEMENTATION (NORMAL)
--------------------------------------------------


s = input()
n = int(input())


vowels = ""


for ch in s:
    if ch.lower() in "aeiou":
        vowels += ch


if n > len(vowels):
    print("invalid")
else:
    print(vowels[:n])




--------------------------------------------------
PYTHON IMPLEMENTATION (REGEX)
--------------------------------------------------


import re


s = input()
n = int(input())


ns = re.sub("[^aeiouAEIOU]", "", s)


print("invalid" if n > len(ns) else ns[:n])




--------------------------------------------------
re.sub() SHORT INFO
--------------------------------------------------


Syntax:
re.sub(pattern, replacement, string)


Use:
pattern ko find karke replace/remove karta hai


Example:
re.sub("[^aeiou]", "", s)
→ vowels chhod ke sab remove




--------------------------------------------------
EXAMPLE
--------------------------------------------------
Input:
education
3


Output:
eua




--------------------------------------------------
END
--------------------------------------------------
========================================================================PLB 84


IS THE STRING IN ORDER?


Definition:
Check if characters of string are in sorted (ascending) order




Problem Statement:
Return true if string is in order, else false


Input:
a string


Constraint:
if empty string → print "invalid"


Output:
true or false




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Input:
abcd


Sorted:
abcd → same ✔ → true




Input:
abdc


Sorted:
abcd → different ✘ → false




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Take input string
- Convert string to list
- Sort the list
- Join back to string
- Compare with original string
    - same → true
    - different → false




--------------------------------------------------
PYTHON IMPLEMENTATION (NORMAL)
--------------------------------------------------


s = input()


if s == "":
    print("invalid")
else:
    l = list(s)     # convert to list
    l.sort()        # sort characters
    s2 = ''.join(l) # convert back to string

    print("true" if s == s2 else "false")




--------------------------------------------------
EXAMPLE
--------------------------------------------------


Input:
abcd


Output:
true




Input:
abdc


Output:
false




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
.sort() → sorts list  
''.join(list) → convert list to string




--------------------------------------------------
END
--------------------------------------------------
========================================================================PLB85


INTEGER TO ENGLISH WORDS


Definition:
Convert a number into words  
Example:
123 → one two three




Problem Statement:
Convert a non-negative integer into English words


Input:
a number from the user


Constraint:
n > 0


Output:
number in English words




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Input:
123


Break digits:
1   2   3


Map:
1 → one  
2 → two  
3 → three  


Output:
one two three




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Take input number
- Convert number to string
- Traverse each digit
- Map digit → word
- Print words




--------------------------------------------------
PYTHON IMPLEMENTATION (SIMPLE)
--------------------------------------------------


# mapping digits to words
words = {
    '0': "zero",
    '1': "one",
    '2': "two",
    '3': "three",
    '4': "four",
    '5': "five",
    '6': "six",
    '7': "seven",
    '8': "eight",
    '9': "nine"
}


# input
n = input()


# print words
for digit in n:
    print(words[digit], end=' ')




--------------------------------------------------
EXAMPLE
--------------------------------------------------


Input:
506


Output:
five zero six




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Use dictionary for mapping




--------------------------------------------------
END
--------------------------------------------------
========================================================================PLB86


CENSORED STRINGS


Definition:
In the given string, all vowels are replaced with '*'.
Another string contains the removed vowels.
We need to reconstruct the original string.




--------------------------------------------------
PROBLEM STATEMENT
--------------------------------------------------


Given:
s1 → censored string (with '*')
s2 → string containing vowels


Return:
Original string after replacing '*' with vowels




--------------------------------------------------
INPUT
--------------------------------------------------
s1 = censored string  
s2 = vowels string  


--------------------------------------------------
OUTPUT
--------------------------------------------------
Reconstructed original string




--------------------------------------------------
EXAMPLE
--------------------------------------------------


Input:
s1 = w*lc*m*
s2 = eoe


Output:
welcome




--------------------------------------------------
LOGIC (TEXT DIAGRAM)
--------------------------------------------------


s1 → w   *   l   c   *   m   *
s2 →     e       o       e


Step-by-step replacement:


* → e  
* → o  
* → e  


Final:
w   e   l   c   o   m   e




--------------------------------------------------
STEP BY STEP LOGIC
--------------------------------------------------


1. Read s1 and s2  
2. Initialize index j = 0 for s2  
3. Traverse each character in s1  


   IF character == '*':
        replace with s2[j]
        increment j


   ELSE:
        print same character




--------------------------------------------------
PYTHON IMPLEMENTATION (WITH COMMENTS)
--------------------------------------------------


s1 = input()   # censored string
s2 = input()   # vowels string


j = 0  # index for vowels


for ch in s1:


    # If '*' found → replace with vowel
    if ch == '*':
        print(s2[j], end='')
        j = j + 1


    # Else print original character
    else:
        print(ch, end='')




--------------------------------------------------
EXAMPLE RUN
--------------------------------------------------


Input:
w*lc*m*
eoe


Output:
welcome




--------------------------------------------------
IMPORTANT POINTS
--------------------------------------------------


- Number of '*' must be equal to number of vowels
- Order of vowels must be maintained
- Replacement happens sequentially




--------------------------------------------------
ONE LINE UNDERSTANDING
--------------------------------------------------


Replace each '*' in s1 with next character from s2
========================================================================
LBP87


parentheses balance


Given a string S of '(' and ')' parentheses, we add the minimum number of parentheses ( '(' or ')' ), and in any positions ) so that the resulting parentheses string is valid.  
Formally, a parentheses string is valid if and only if:  
It is the empty string, or It can be written as AB (A concatenated with B), where A and B are valid strings, or It can be written as (A), where A is a valid string.  
Given a parentheses string, return the minimum number of parentheses we must add to make the resulting string valid.


input --------> a string from the user  
con ----------> no  
output -------> number of parentheses to be added  




--------------------------------------------------
WHAT TO DO (SIMPLE UNDERSTANDING)
--------------------------------------------------
- Check the string character by character
- Try to match every ')' with a '('
- If no '(' is available → we need one
- At the end, some '(' may remain → they need ')'
- Count total missing brackets




--------------------------------------------------
LOGIC (TEXT DIAGRAM)
--------------------------------------------------
Example: )((


) → need=1  
) → need=2  
( → open=1  


Total = need + open = 3  




--------------------------------------------------
CORE UNDERSTANDING
--------------------------------------------------
"(" → open bracket  
")" → close bracket  


- If '(' comes → store it  
- If ')' comes:
    if '(' available → match it  
    else → need one '('  


Final:
unmatched '(' + unmatched ')'




--------------------------------------------------
PYTHON IMPLEMENTATION (WITH COMMENTS)
--------------------------------------------------


s = input()          # input string


open_count = 0      # count of unmatched '('  
need = 0            # count of extra '(' needed  


for ch in s:


    if ch == '(':
        open_count += 1     # store open bracket


    elif ch == ')':
        if open_count > 0:
            open_count -= 1 # match with previous '('
        else:
            need += 1       # no '(' available → need one


# total additions required
print(need + open_count)




--------------------------------------------------
ONE LINE
--------------------------------------------------
answer = unmatched '(' + unmatched ')'
========================================================================LBP88


American keyboard


Given a string, return the true if that can be typed using letters of alphabet on only one row's of American keyboard like the image below.  
In the American keyboard:


the first row consists of the characters "qwertyuiop",  
the second row consists of the characters "asdfghjkl", and  
the third row consists of the characters "zxcvbnm".


dad ----> true  
mom ----> false  


Note:
1. You may use one character in the keyboard more than once.  
2. You may assume the input string will only contain letters of alphabet.


input --------> a string from the user  
cons ---------> no  
output -------> true or false  




--------------------------------------------------
WHAT TO DO (SIMPLE UNDERSTANDING)
--------------------------------------------------
- Check if all characters of string belong to same keyboard row  
- If all characters are from one row → true  
- Otherwise → false  




--------------------------------------------------
LOGIC (TEXT DIAGRAM)
--------------------------------------------------
Rows:
r1 → qwertyuiop  
r2 → asdfghjkl  
r3 → zxcvbnm  


Example: "dad"


d → r2  
a → r2  
d → r2  


All in same row → TRUE  


Example: "mom"


m → r3  
o → r1  
m → r3  


Different rows → FALSE  




--------------------------------------------------
STEP BY STEP LOGIC
--------------------------------------------------
- Take input string
- Count characters in each row
- If all characters belong to any one row:
    return true
- else:
    return false




--------------------------------------------------
PYTHON IMPLEMENTATION (WITH COMMENTS)
--------------------------------------------------


s = input()                 # input string
c1, c2, c3 = 0, 0, 0       # counters for 3 rows


for ch in s:


    if ch in "qwertyuiop":
        c1 += 1            # row 1 count


    if ch in "asdfghjkl":
        c2 += 1            # row 2 count


    if ch in "zxcvbnm":
        c3 += 1            # row 3 count


# check if all characters belong to one row
print(str(c1 == len(s) or c2 == len(s) or c3 == len(s)).lower())




--------------------------------------------------
ONE LINE
--------------------------------------------------
Check if all characters of string belong to same keyboard row
========================================================================LBP88


American keyboard


Given a string, return the true if that can be typed using letters of alphabet on only one row's of American keyboard like the image below.  
In the American keyboard:


the first row consists of the characters "qwertyuiop",  
the second row consists of the characters "asdfghjkl", and  
the third row consists of the characters "zxcvbnm".


dad ----> true  
mom ----> false  


Note:
1. You may use one character in the keyboard more than once.  
2. You may assume the input string will only contain letters of alphabet.


input --------> a string from the user  
cons ---------> no  
output -------> true or false  




--------------------------------------------------
WHAT TO DO (SIMPLE UNDERSTANDING)
--------------------------------------------------
- Check if all characters of string belong to same keyboard row  
- If all characters are from one row → true  
- Otherwise → false  




--------------------------------------------------
LOGIC (TEXT DIAGRAM)
--------------------------------------------------
Rows:
r1 → qwertyuiop  
r2 → asdfghjkl  
r3 → zxcvbnm  


Example: "dad"


d → r2  
a → r2  
d → r2  


All in same row → TRUE  


Example: "mom"


m → r3  
o → r1  
m → r3  


Different rows → FALSE  




--------------------------------------------------
STEP BY STEP LOGIC
--------------------------------------------------
- Take input string
- Count characters in each row
- If all characters belong to any one row:
    return true
- else:
    return false




--------------------------------------------------
PYTHON IMPLEMENTATION (WITH COMMENTS)
--------------------------------------------------


s = input()                 # input string
c1, c2, c3 = 0, 0, 0       # counters for 3 rows


for ch in s:


    if ch in "qwertyuiop":
        c1 += 1            # row 1 count


    if ch in "asdfghjkl":
        c2 += 1            # row 2 count


    if ch in "zxcvbnm":
        c3 += 1            # row 3 count


# check if all characters belong to one row
print(str(c1 == len(s) or c2 == len(s) or c3 == len(s)).lower())




--------------------------------------------------
ONE LINE
--------------------------------------------------
Check if all characters of string belong to same keyboard row
========================================================================LBP89
Rotate String


Given two strings s and goal, return true if and only if s can become goal after some number of shifts on s.
A shift on s consists of moving the leftmost character of s to the rightmost position.
For example, if s = "abcde", then it will be "bcdea" after one shift.


input --------> two strings from the user
cons ---------> no
output -------> true or false


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Check if goal can be formed by rotating s
- Rotate = move first character to end
- If any rotation equals goal → true
- else → false


--------------------------------------------------
LOGIC
--------------------------------------------------
s = abcde


Rotations:
abcde
bcdea
cdeab
deabc
eabcd


Shortcut:
s+s = abcdeabcde
Check:
goal in (s+s)


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
s1 = input()      # original string
s2 = input()      # goal string


print('true' if s2 in s1+s1 else 'false')


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
abcde
cdeab
Output:
true


Input:
abcde
abced
Output:
false


--------------------------------------------------
ONE LINE
--------------------------------------------------
goal in (s + s)
========================================================================LBP90
Missing Letters


Given a string containing unique letters, return a sorted string with the letters that don't appear in the string.


input --------> a string from the user
con ----------> no
output -------> return missing characters


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Check all letters from a to z
- If a letter is not present in string → print it
- Output should be in sorted order (a to z)


--------------------------------------------------
LOGIC
--------------------------------------------------
Example: abde


a → present
b → present
c → missing
d → present
e → present


So output → c


Check:
loop from 'a' to 'z'
if letter not in string → print


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
s = input()              # input string


for i in range(97,123): # ASCII values of a-z
    ch = chr(i)         # convert to character


    if ch not in s:     # check missing
        print(ch, end='')


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
abde


Output:
cfg hijklmnopqrstuvwxyz


Input:
abcdefghijklmnopqrstuvwxyz


Output:
(empty)


--------------------------------------------------
ONE LINE
--------------------------------------------------
Print characters from a-z that are not in string
========================================================================LBP91
Replace Letters With Position In Alphabet


Create a function that takes a string and replaces each letter with its appropriate position in the alphabet. "a" is 1, "b" is 2, "c" is 3, etc, etc.


Note: If any character in the string isn't a letter, ignore it.


input ----------> a string from the user
constraint -----> non-empty string
output ---------> position of characters separated by space


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Convert each letter to its alphabet position
- Ignore non-letter characters
- Print positions separated by space


--------------------------------------------------
LOGIC
--------------------------------------------------
a → 1
b → 2
c → 3


Formula:
position = ord(ch) - 96


Example:
abc → 1 2 3


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
s = input().lower()          # convert to lowercase


for ch in s:


    if ch.isalpha():        # check only letters
        print(ord(ch)-96, end=' ')   # convert to position


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
abc
Output:
1 2 3


Input:
a1b2c
Output:
1 2 3


--------------------------------------------------
ONE LINE
--------------------------------------------------
Convert each letter using ord(ch)-96
========================================================================LBP92
Replace character with it's occurrence


Implement a Program to replace a character with it's occurrence in given string.


input --------> a string and a character from the user
con ----------> non-empty string
output -------> replaced string


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Replace given character with its occurrence number
- First occurrence → 1, second → 2, third → 3
- Other characters remain same


--------------------------------------------------
LOGIC
--------------------------------------------------
Example:
s = abcabab
ch = a


a → 1
b → b
c → c
a → 2
b → b
a → 3
b → b


Output:
1bc2b3b


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
s = input()        # input string
ch = input()       # character to replace


count = 1          # occurrence counter


for i in s:


    if i == ch:
        print(count, end='')   # print occurrence
        count += 1            # increment counter
    else:
        print(i, end='')      # print same char


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
abcabab
a


Output:
1bc2b3b


Input:
hello
l


Output:
he12o


--------------------------------------------------
ONE LINE
--------------------------------------------------
Replace target character with its occurrence count
========================================================================LBP93
first non-repeated character


Program to find first non-repeated character


input ----> a non-empty string from the user
con ------> no
output ---> non-repeated character


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Find first character that appears only once
- Ignore repeating characters
- Print first unique character


--------------------------------------------------
LOGIC
--------------------------------------------------
Example:
india


i → repeated
n → not repeated → ANSWER


Example:
indian


i → repeated
n → repeated
d → not repeated → ANSWER


--------------------------------------------------
EXTRA UNDERSTANDING (ARRAY VIEW)
--------------------------------------------------
india → remove repeated → nda


a[0] = n
a[1] = d
a[2] = a


But question asks FIRST non-repeated:
So answer = n (not last element)


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
s = input()           # input string


for ch in s:


    if s.count(ch) == 1:   # check occurrence
        print(ch)          # first non-repeated
        break              # stop after first


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
india
Output:
n


Input:
indian
Output:
d


--------------------------------------------------
ONE LINE
--------------------------------------------------
Print first character whose count is 1
========================================================================LBP94
Pangrams


Implement a program to check whether the given string pangram or not.
A pangram is a string that contains all the letters of the English alphabet. 
An example of a pangram is "The quick brown fox jumps over the lazy dog"


input ----> a string from the user
con ------> non-empty string
output ---> Yes or No


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Check if all letters from a to z are present in string
- If all present → Yes
- If any missing → No


--------------------------------------------------
LOGIC
--------------------------------------------------
alphabet = abcdefghijklmnopqrstuvwxyz


Example:
"The quick brown fox jumps over the lazy dog"
→ contains all letters → YES


Example:
"hello"
→ missing many letters → NO


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
s = input().lower()     # convert to lowercase
alphabet = "abcdefghijklmnopqrstuvwxyz"


flag = True


for ch in alphabet:


    if ch not in s:     # check each letter
        flag = False
        break


print("Yes" if flag else "No")


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
The quick brown fox jumps over the lazy dog
Output:
Yes


Input:
hello
Output:
No


--------------------------------------------------
ONE LINE
--------------------------------------------------
Check if all letters from a-z are present in string
========================================================================LBP95
Print First Letter of each Word


Implement a function/Method to return first character in each word from the given input string.


input ----> a string
con ------> no
output ---> first character in each string


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Split string into words
- Take first letter of each word
- Print them together


--------------------------------------------------
TOKENIZATION (IMPORTANT)
--------------------------------------------------
Tokenization means splitting a string into parts (tokens)


Example:
"hello world java" → ["hello", "world", "java"]


Here each word is a token


split() is used for word-level tokenization


--------------------------------------------------
LOGIC
--------------------------------------------------
Example:
hello world java


hello → h
world → w
java → j


Output → hwj


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
s = input()           # input string
words = s.split()     # tokenization (split into words)


for w in words:
    print(w[0], end='')   # print first letter


--------------------------------------------------
SHORT PYTHON (ONE LINE CODE)
--------------------------------------------------
print(''.join([i[0] for i in input().split()]))


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
hello world java
Output:
hwj


Input:
python is easy
Output:
pie


--------------------------------------------------
ONE LINE
--------------------------------------------------
Tokenize string and print first character of each word
========================================================================LBP96
Number of vowels


Implement a program to return number of vowels present in the given string


input --------> a string from the user
con ----------> non-empty string
output -------> return number of vowels


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Count vowels in the string
- Vowels = a, e, i, o, u


--------------------------------------------------
LOGIC
--------------------------------------------------
Example:
hello


e → vowel
o → vowel


Count = 2


--------------------------------------------------
IMPORTANT CORRECTION
--------------------------------------------------
Given code was wrong:


if i not in "aeiou" → counts consonants ❌


Correct:
if i in "aeiou" → counts vowels ✅


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
s = input().lower()   # convert to lowercase
count = 0             # vowel counter


for ch in s:


    if ch in "aeiou":   # check vowel
        count += 1


print(count)


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
hello
Output:
2


Input:
education
Output:
5


--------------------------------------------------
ONE LINE
--------------------------------------------------
Count characters present in "aeiou"
========================================================================LBP97
Number of consonants


Implement a program to return number of consonants present in the given string


input --------> a string from the user
con ----------> non-empty string
output -------> return number of consonants


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Count consonants in the string
- Consonants = alphabets except a, e, i, o, u


--------------------------------------------------
SIMPLE LOGIC (AS GIVEN)
--------------------------------------------------
s = input()
c = 0


for i in s:
    if i not in "aeiou":
        c = c + 1


print(c)


NOTE:
- Counts everything except vowels ❌
- Spaces, digits also counted


--------------------------------------------------
CORRECT LOGIC (FINAL)
--------------------------------------------------
s = input()
c = 0


for i in s:


    # isalpha() → checks if character is a letter (a-z or A-Z)
    # returns True for alphabets, False for digits/symbols


    # lower() → converts uppercase to lowercase
    # helps in comparing with "aeiou"


    if i.isalpha() and i.lower() not in "aeiou":
        c = c + 1


print(c)


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
hello
Output:
3


Input:
Hello123
Output:
3


--------------------------------------------------
ONE LINE
--------------------------------------------------
Count characters which are alphabets AND not vowels
========================================================================LBP98
Check only digits


Implement a program to check if a string contains only digits.


input --------> a string from the user
con ----------> no
output -------> Yes or No


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Check whether all characters in string are digits (0–9)


--------------------------------------------------
LOGIC
--------------------------------------------------
Example:
"1234" → all digits → Yes
"12a3" → contains letter → No


--------------------------------------------------
SIMPLE LOGIC
--------------------------------------------------
- Check each character
- If digit → count++
- If count == length → Yes else No


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
# isdigit() → checks if all characters are digits (0–9)
# returns True if only digits, otherwise False


s = input()


print("Yes" if s.isdigit() else "No")


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
12345
Output:
Yes


Input:
123a5
Output:
No


--------------------------------------------------
ONE LINE
--------------------------------------------------
Use isdigit() to check if string has only digits
========================================================================
LBP99 :-Capitalize Every word first character


Implement a program to capitalize first letter of each word in a string.


input --------> a string from the user
con ----------> non-empty string
output -------> a string with capitalization


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Convert first letter of every word to uppercase


--------------------------------------------------
LOGIC
--------------------------------------------------
hello world → Hello World


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
# title() → converts first letter of each word to uppercase


s = input()


print(s.title())


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
hello world
Output:
Hello World


Input:
python is easy
Output:
Python Is Easy


--------------------------------------------------
ONE LINE
--------------------------------------------------
Use title() to capitalize first letter of each word
========================================================================LBP100
Student Rewarded


You are given a string representing an attendance record for a student.
The record only contains the following three characters: 'A' : Absent. 'L' : Late. 'P' : Present.
A student could be rewarded if his attendance record doesn't contain more than one 'A' (absent) or more than two continuous 'L' (late).


You need to return whether the student could be rewarded according to his attendance record.


input --------> a string from the user
con ----------> non empty string
output -------> Yes or No


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Check count of 'A'
- Check continuous 'L'


--------------------------------------------------
LOGIC
--------------------------------------------------
"A" count > 1 → No  
"LLL" present → No  
otherwise → Yes


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
s = input()


# count('A') → total absent
# "LLL" in s → checks 3 continuous L


print("No" if s.count('A') > 1 or "LLL" in s else "Yes")


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
PPALLP
Output:
Yes


Input:
PPALLL
Output:
No


--------------------------------------------------
ONE LINE
--------------------------------------------------
Reject if A>1 OR "LLL" present
========================================================================
LBP101
reading and writing an array


Implement a program to read an array element and write on the screen.


input --------> size of the array and array elements
con ----------> size<100
output -------> the given array


--------------------------------------------------
ARRAYS (BASIC INFO)
--------------------------------------------------
- small values → variables
- large values → arrays
- array = collection of same type elements
- index starts from 0
- range → 0 to n-1


Example:
a[0], a[1], a[2]


--------------------------------------------------
WHAT TO DO
--------------------------------------------------
- Read size n
- Read n elements
- Print elements


--------------------------------------------------
LOGIC
--------------------------------------------------
read n (size)


for i=0 to n-1:
    read element


for i=0 to n-1:
    print element


--------------------------------------------------
LANGUAGE NOTE
--------------------------------------------------
C      ----> int a[100];
C++    ----> int a[100];
Java   ----> int a[] = new int[n];
Python ----> no fixed array → use list


--------------------------------------------------
PYTHON IMPLEMENTATION
--------------------------------------------------
n = int(input())


# L = [int(i) for i in input().split()]


# Explanation:
# input().split() → takes input like "1 2 3" and splits into ['1','2','3']
# for i in ... → loop through each value
# int(i) → convert each string to integer
# [ ... ] → store all values in a list


# Final result:
# L becomes [1, 2, 3]


L = [int(i) for i in input().split()]


for i in L:
    print(i, end=' ')


--------------------------------------------------
SAMPLE INPUT / OUTPUT
--------------------------------------------------
Input:
3
1 2 3


Output:
1 2 3


--------------------------------------------------
ONE LINE
--------------------------------------------------
Convert space-separated input into list of integers
=================================================================
PLB102 - Sum of All Elements in Array


--------------------------------------------------


Problem Statement:
Write a program to read an array and print the sum of all its elements.


--------------------------------------------------


Input:
- Size of the array (n)
- Array elements


Condition:
- n < 100


Output:
- Sum of all elements


--------------------------------------------------


Logic:
1. Initialize sum = 0
2. Loop from 0 to n-1
3. Add each element to sum
4. Print sum


--------------------------------------------------


Python Implementation:


n = int(input())
L = [int(i) for i in input().split()]
print(sum(L))


--------------------------------------------------


Line Explanation:


L = [int(i) for i in input().split()]


Step-by-step:
1. input() → takes input as string
   Example: "1 2 3 4"


2. split() → converts into list of strings
   ['1', '2', '3', '4']


3. for i in ... → loop through each element


4. int(i) → convert each string into integer


5. [] → create list


Final List:
[1, 2, 3, 4]


--------------------------------------------------


Example:


Input:
5
1 2 3 4 5


Output:
15


--------------------------------------------------


Without using sum():


n = int(input())
L = [int(i) for i in input().split()]


s = 0


for i in L:
    s = s + i


print(s)


--------------------------------------------------
=========================================================PLB103 - Sum of Even Numbers in Array


--------------------------------------------------


Problem Statement:
Write a program to read an array and print the sum of all even elements.


--------------------------------------------------


Input:
- Size of the array (n)
- Array elements


Condition:
- n < 100


Output:
- Sum of all even elements


--------------------------------------------------


Logic:
1. Initialize sum = 0
2. Loop from 0 to n-1
3. Check if element is even (a[i] % 2 == 0)
4. If even, add to sum
5. Print sum


--------------------------------------------------


Python Implementation:


n = int(input())
L = [int(i) for i in input().split() if int(i) % 2 == 0]
print(sum(L))


--------------------------------------------------


Line Explanation:


L = [int(i) for i in input().split() if int(i) % 2 == 0]


Step-by-step:
1. input() → takes input as string
2. split() → converts into list of strings
3. int(i) → convert into integer
4. if int(i) % 2 == 0 → check even number
5. [] → create list of only even numbers


--------------------------------------------------


Multiline Version (Detailed with Comments):


n = int(input())           # Read the count of numbers (size of array)


data = input()             # Read the input string containing space-separated numbers
nums = data.split()        # Split the string into a list of individual number strings
                           # Example: "2 4 6 8" becomes ["2", "4", "6", "8"]


L = []                     # Initialize an empty list to store even numbers


for i in nums:             # Iterate through each number string in the list
    num = int(i)           # Convert the string to an integer
    if num % 2 == 0:       # Check if the number is even (remainder is 0 when divided by 2)
        L.append(num)      # Add the even number to the list L


print(sum(L))              # Calculate the sum of all even numbers and print the result


--------------------------------------------------


Example:


Input:
5
1 2 3 4 5


Output:
6


--------------------------------------------------


Without using sum():


n = int(input())
L = [int(i) for i in input().split()]


s = 0


for i in L:
    if i % 2 == 0:
        s = s + i


print(s)


--------------------------------------------------
========================================================================PLB104 - Sum of Odd Numbers in Array


--------------------------------------------------


Problem Statement:
Write a program to read an array and print the sum of all odd elements.


--------------------------------------------------


Input:
- Size of the array (n)
- Array elements


Condition:
- n < 100


Output:
- Sum of all odd elements


--------------------------------------------------


Logic:
1. Initialize sum = 0
2. Loop through all elements
3. Check if element is odd (a[i] % 2 != 0)
4. If odd, add to sum
5. Print sum


--------------------------------------------------


Python Implementation:


n = int(input())
L = [int(i) for i in input().split() if int(i) % 2 != 0]
print(sum(L))


--------------------------------------------------


Line Explanation:


L = [int(i) for i in input().split() if int(i) % 2 != 0]


Step-by-step:
1. input() → takes input as string
2. split() → converts into list of strings
3. int(i) → convert into integer
4. if int(i) % 2 != 0 → check odd number
5. [] → create list of only odd numbers


--------------------------------------------------


Multiline Version (Detailed with Comments):


n = int(input())           # Read the count of numbers (size of array)


data = input()             # Read the input string containing space-separated numbers
nums = data.split()        # Split into list
                           # Example: "1 2 3 4 5" → ["1","2","3","4","5"]


L = []                     # Empty list for odd numbers


for i in nums:             
    num = int(i)           # Convert to integer
    if num % 2 != 0:       # Check odd
        L.append(num)      # Add to list


print(sum(L))              # Print sum of odd numbers


--------------------------------------------------


Example:


Input:
5
1 2 3 4 5


Output:
9


--------------------------------------------------


Without using sum():


n = int(input())
L = [int(i) for i in input().split()]


s = 0


for i in L:
    if i % 2 != 0:
        s = s + i


print(s)


--------------------------------------------------










========================================================================PLB105 - Sum of Prime Numbers in Array


--------------------------------------------------


Problem Statement:
Write a program to read an array and print the sum of all prime elements.


--------------------------------------------------


Input:
- Size of the array (n)
- Array elements


Condition:
- n < 100


Output:
- Sum of all prime elements


--------------------------------------------------


Logic:
1. Define a function to check prime
2. Loop through elements
3. If number is prime → add to sum
4. Print sum


--------------------------------------------------


Python Implementation:


def isprime(n):
    factors = 0
    for i in range(1, n+1):
        if n % i == 0:
            factors = factors + 1
    return factors == 2


n = int(input())
L = [int(i) for i in input().split() if isprime(int(i))]
print(sum(L))


--------------------------------------------------


Line Explanation:


isprime(n):
- Counts how many numbers divide n
- If exactly 2 factors → prime


Example:
7 → factors = 2 → prime
6 → factors = 4 → not prime


--------------------------------------------------


Multiline Version (Detailed with Comments):


def isprime(n):
    factors = 0                     # count factors


    for i in range(1, n+1):        # loop from 1 to n
        if n % i == 0:             # check divisor
            factors += 1           # increase count


    return factors == 2            # prime if exactly 2 factors




n = int(input())                   # size of array


data = input()                     # read input
nums = data.split()                # split into list


L = []                             # list for prime numbers


for i in nums:
    num = int(i)                   # convert to int
    if isprime(num):               # check prime
        L.append(num)              # add to list


print(sum(L))                      # print sum of primes


--------------------------------------------------


Example:


Input:
5
1 2 3 4 5


Prime numbers:
2, 3, 5


Output:
10


--------------------------------------------------


Without using list:


def isprime(n):
    factors = 0
    for i in range(1, n+1):
        if n % i == 0:
            factors += 1
    return factors == 2


n = int(input())
nums = input().split()


s = 0


for i in nums:
    num = int(i)
    if isprime(num):
        s = s + num


print(s)


--------------------------------------------------
========================================================================PLB106 - Sum of Palindrome Numbers in Array
--------------------------------------------------
Problem Statement:
Write a program to read an array and print the sum of all palindrome elements.
--------------------------------------------------
Input:
- Size of the array (n)
- Array elements
Condition:
- n < 100
Output:
- Sum of all palindrome numbers
--------------------------------------------------
Logic:
1. Loop through elements
2. Check if number == reverse
3. If yes, add to sum
4. Print sum
--------------------------------------------------
Python Implementation:
n = int(input())
L = [int(i) for i in input().split() if i == i[::-1]]
print(sum(L))
--------------------------------------------------
Line Explanation:
i == i[::-1] → check palindrome using reverse
Example: "121" == "121" ✔, "123" != "321" ✘
--------------------------------------------------
Multiline Version:
n = int(input())
data = input()
nums = data.split()
L = []
for i in nums:
    if i == i[::-1]:
        L.append(int(i))
print(sum(L))
--------------------------------------------------
Example:
Input:
5
121 123 44 10 7
Output:
172
--------------------------------------------------
Without slicing:
n = int(input())
nums = input().split()
s = 0
for i in nums:
    num = int(i)
    temp = num
    rev = 0
    while temp > 0:
        d = temp % 10
        rev = rev * 10 + d
        temp = temp // 10
    if num == rev:
        s = s + num
print(s)
--------------------------------------------------
========================================================================PLB107 - Sum of Strong Numbers in Array
--------------------------------------------------
Problem Statement:
Write a program to read an array and print the sum of all strong numbers.
--------------------------------------------------
Input:
- Size of the array (n)
- Array elements
Condition:
- n < 100
Output:
- Sum of all strong numbers
--------------------------------------------------
Strong Number:
A number is strong if sum of factorial of its digits = number
Example:
123 = 1!+2!+3! = 9 (Not strong)
145 = 1!+4!+5! = 145 (Strong)
--------------------------------------------------
Logic:
1. Extract digits
2. Find factorial of each digit
3. Add them
4. Compare with original number
--------------------------------------------------
Python Implementation (With Comments):


import math                      # import math module for factorial


def strong(n):
    s = 0                        # variable to store sum of factorials
    temp = n                     # store original number (backup)


    while n != 0:                # loop until n becomes 0
        d = n % 10               # get last digit
        s = s + math.factorial(d)  # add factorial of digit
        n = n // 10              # remove last digit


    return s                     # return sum of factorials


n = int(input())                 # read size of array


# list comprehension:
# - split input
# - convert to int
# - check strong condition
L = [int(i) for i in input().split() if int(i) == strong(int(i))]


print(sum(L))                    # print sum of strong numbers


--------------------------------------------------
strong() Explanation:
- n % 10 → extract digit
- math.factorial(d) → factorial of digit
- n // 10 → remove last digit
- total sum return hota hai
- agar total == number → strong number


--------------------------------------------------
Multiline Version (With Full Comments):


import math                      # import math module


def strong(n):
    s = 0                        # store sum of factorials
    temp = n                     # backup of original number


    while n != 0:                # loop until number becomes 0
        d = n % 10               # extract last digit
        s = s + math.factorial(d)  # add factorial of digit
        n = n // 10              # remove last digit


    return s                     # return total sum


n = int(input())                 # read size of array


data = input()                   # read input string (space separated numbers)
nums = data.split()              # convert into list of strings


L = []                           # empty list to store strong numbers


for i in nums:                   
    num = int(i)                 # convert string to integer
    if num == strong(num):       # check if number is strong
        L.append(num)            # add to list if condition true


print(sum(L))                    # print sum of strong numbers


--------------------------------------------------
Example:


Input:
5
1 2 145 10 40585


Output:
40731


--------------------------------------------------
Without using list (With Comments):


import math                      # import math module


def strong(n):
    s = 0                        # sum of factorials


    while n != 0:                # loop until n becomes 0
        d = n % 10               # extract digit
        s = s + math.factorial(d)  # add factorial
        n = n // 10              # remove digit


    return s                     # return total


n = int(input())                 # read size


nums = input().split()           # read elements


s = 0                            # initialize sum


for i in nums:
    num = int(i)                 # convert to integer
    if num == strong(num):       # check strong
        s = s + num              # add to sum


print(s)                         # print result


--------------------------------------------------


========================================================================PLB108 - Sum of Elements in Array Ending with 3
--------------------------------------------------
Problem Statement:
Write a program to read an array and print sum of elements ending with 3.
--------------------------------------------------
Input:
- Size of the array (n)
- Array elements
Condition:
- n < 100
Output:
- Sum of elements ending with 3
--------------------------------------------------
Logic:
1. Loop through elements
2. Check last digit using %10
3. If last digit == 3 → add to sum
4. Print sum
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                 # read size of array


# list comprehension:
# - split input into elements
# - convert to int
# - check last digit == 3
L = [int(i) for i in input().split() if int(i) % 10 == 3]


print(sum(L))                    # print sum of filtered elements


--------------------------------------------------
Line Explanation:


int(i) % 10 == 3
→ %10 gives last digit
Example:
13 % 10 = 3 ✔
25 % 10 = 5 ✘


--------------------------------------------------
Multiline Version (With Full Comments):


n = int(input())                 # read size of array


data = input()                   # read input string
nums = data.split()              # convert into list


L = []                           # empty list to store numbers ending with 3


for i in nums:
    num = int(i)                 # convert string to integer


    if num % 10 == 3:            # check last digit is 3
        L.append(num)            # add to list


print(sum(L))                    # print sum of numbers ending with 3


--------------------------------------------------
Example:


Input:
5
13 22 33 40 53


Numbers ending with 3:
13, 33, 53


Output:
99


--------------------------------------------------
Without using list (With Comments):


n = int(input())                 # read size


nums = input().split()           # read elements


s = 0                            # initialize sum


for i in nums:
    num = int(i)                 # convert to integer


    if num % 10 == 3:            # check condition
        s = s + num              # add to sum


print(s)                         # print result


--------------------------------------------------
========================================================================PLB109 - Search for an Element in an Array
--------------------------------------------------
Problem Statement:
Write a program to search for an element in an array.
--------------------------------------------------
Input:
- Size of the array (n)
- Array elements
- Element to search (key)
Condition:
- n < 100
Output:
- Index of element if found, else -1
--------------------------------------------------
Logic:
1. Take array input
2. Take key to search
3. Check if key exists in array
4. If yes → print index
5. Else → print -1
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                 # read size of array


# read array elements and convert to list of integers
L = [int(i) for i in input().split()]


key = int(input())               # read element to search


if key in L:                     # check if element exists
    print(L.index(key))          # print index of first occurrence
else:
    print(-1)                    # element not found


--------------------------------------------------
Line Explanation:


key in L
→ checks whether key exists in list


L.index(key)
→ returns index of first occurrence


Example:
L = [10, 20, 30]
key = 20 → index = 1


--------------------------------------------------
Multiline Version (With Full Comments):


n = int(input())                 # read size


data = input()                   # read input string
nums = data.split()              # split into list


L = []                           # empty list


for i in nums:
    L.append(int(i))             # convert each to int and store


key = int(input())               # element to search


found = False                    # flag variable


for i in range(len(L)):          
    if L[i] == key:              # check element
        print(i)                 # print index
        found = True             # mark found
        break                    # stop loop


if not found:                    
    print(-1)                    # if not found


--------------------------------------------------
Example:


Input:
5
10 20 30 40 50
30


Output:
2


--------------------------------------------------
Without using index() (With Comments):


n = int(input())                 # read size
nums = input().split()           # read elements


L = []
for i in nums:
    L.append(int(i))             # convert to int


key = int(input())               # element to search


s = -1                           # default value


for i in range(len(L)):
    if L[i] == key:              # check match
        s = i                    # store index
        break


print(s)                         # print result


--------------------------------------------------
========================================================================PLB110 - Sort the Elements in an Array (ASC) ,where ASC means Ascending Order
--------------------------------------------------
Problem Statement:
Write a program to sort the given array elements in ascending order.
--------------------------------------------------
Input:
- Size of the array (n)
- Array elements
Condition:
- n < 100
Output:
- Sorted array in ascending order
--------------------------------------------------
Logic:
1. Read array elements
2. Sort the array
3. Print elements one by one
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                 # read size of array


# read elements and convert to integer list
L = [int(i) for i in input().split()]


L.sort()                         # sort list in ascending order


# print elements in same line
for i in L:
    print(i, end=' ')


--------------------------------------------------
Line Explanation:


L.sort()
→ sorts list in ascending order


print(i, end=' ')
→ prints elements in single line separated by space


--------------------------------------------------
Multiline Version (With Full Comments):


n = int(input())                 # read size


data = input()                   # read input string
nums = data.split()              # split into list


L = []                           # empty list


for i in nums:
    L.append(int(i))             # convert to int and store


L.sort()                         # sort the list


for i in L:
    print(i, end=' ')            # print elements in one line


--------------------------------------------------
Example:


Input:
5
5 2 4 1 3


Output:
1 2 3 4 5


--------------------------------------------------
Without using sort() (Manual Sorting):


n = int(input())                 # read size
nums = input().split()           # read elements


L = []
for i in nums:
    L.append(int(i))             # convert to int


# simple sorting (nested loop)
for i in range(len(L)):
    for j in range(i+1, len(L)):
        if L[i] > L[j]:          # compare elements
            temp = L[i]          # swap
            L[i] = L[j]
            L[j] = temp


for i in L:
    print(i, end=' ')            # print sorted list


--------------------------------------------------
========================================================================PLB111 - Sort the Elements in an Array (DESC)
--------------------------------------------------
Problem Statement:
Write a program to sort the given array elements in descending order.
--------------------------------------------------
Input:
- Size of the array (n)
- Array elements
Condition:
- n < 100
Output:
- Sorted array in descending order
--------------------------------------------------
Logic:
1. Read array elements
2. Sort in descending order
3. Print elements
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                 # read size of array


# read elements and convert to integer list
L = [int(i) for i in input().split()]


L.sort(reverse=True)             # sort list in descending order


# print elements in same line
for i in L:
    print(i, end=' ')


--------------------------------------------------
Line Explanation:


L.sort(reverse=True)
→ reverse=True means descending order


--------------------------------------------------
Multiline Version (With Full Comments):


n = int(input())                 # read size


data = input()                   # read input string
nums = data.split()              # split into list


L = []                           # empty list


for i in nums:
    L.append(int(i))             # convert to int and store


L.sort(reverse=True)             # sort in descending order


for i in L:
    print(i, end=' ')            # print elements in one line


--------------------------------------------------
Example:


Input:
5
5 2 4 1 3


Output:
5 4 3 2 1


--------------------------------------------------
Without using sort() (Manual Sorting):


n = int(input())                 # read size
nums = input().split()           # read elements


L = []
for i in nums:
    L.append(int(i))             # convert to int


# manual sorting (descending)
for i in range(len(L)):
    for j in range(i+1, len(L)):
        if L[i] < L[j]:          # change condition for DESC
            temp = L[i]          # swap
            L[i] = L[j]
            L[j] = temp


for i in L:
    print(i, end=' ')            # print sorted list


--------------------------------------------------
========================================================================PLB112 - Binary Search
--------------------------------------------------
Problem Statement:
Write a program to search for an element in an array using binary search.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
- Element to search (key)
Condition:
- n < 100
Output:
- Index of element if found, else -1
--------------------------------------------------
Binary Search Information:
- Binary search works only on sorted arrays
- It divides the array into two halves
- Time Complexity: O(log n) → faster than linear search
--------------------------------------------------
Logic:
1. Sort the array
2. Set low = 0, high = n-1
3. Find mid = (low + high) // 2
4. Compare key with middle element
5. Repeat until found or not found
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


L = [int(i) for i in input().split()]  # read array elements


key = int(input())                  # read element to search


L.sort()                            # sort array (important)


low = 0                             # starting index
high = n - 1                        # ending index


found = -1                          # default value (not found)


while low <= high:
    mid = (low + high) // 2         # calculate middle index


    if L[mid] == key:               # if element found
        found = mid                 # store index
        break


    elif key > L[mid]:              # search right half
        low = mid + 1


    else:                           # search left half
        high = mid - 1


print(found)                        # print index or -1


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
2 4 1 5 3
4


Step 1:
L = [2,4,1,5,3] → after sort → [1,2,3,4,5]


Iteration 1:
low=0, high=4
mid=2 → L[2]=3
4 > 3 → search right → low=3


Iteration 2:
low=3, high=4
mid=3 → L[3]=4 → FOUND


Output:
3


--------------------------------------------------
========================================================================
PLB113 - Max Element in an Array
--------------------------------------------------
Problem Statement:
Write a program to read array elements and find the maximum element.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
Condition:
- n < 100
Output:
- Maximum element
--------------------------------------------------
Concept:
- Maximum element means the largest value in the array
- We can either:
  1. Sort the array and take last element
  2. Compare elements one by one
--------------------------------------------------
Logic (Method 1 - Sorting):
1. Read array elements
2. Sort the array
3. Last element will be maximum
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


L = [int(i) for i in input().split()]  # read array elements


L.sort()                            # sort array in ascending order


print(L[n-1])                       # last element is maximum


--------------------------------------------------
Logic (Method 2 - Without Sorting):
1. Assume first element as max
2. Compare with all elements
3. Update max if bigger element found
--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


m = L[0]                             # assume first element as max


for i in L:
    if i > m:                        # check if current element is greater
        m = i                        # update max


print(m)                             # print maximum element


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 25 5 40 15


Step 1:
L = [10, 25, 5, 40, 15]


Method 1 (Sorting):
After sort → [5, 10, 15, 25, 40]
Last element → 40


Method 2 (Manual):
Initial m = 10
Compare 25 → m = 25
Compare 5 → no change
Compare 40 → m = 40
Compare 15 → no change


Output:
40


--------------------------------------------------
========================================================================PLB114 - Min Element in an Array
--------------------------------------------------
Problem Statement:
Write a program to read array elements and find the minimum element.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
Condition:
- n < 100
Output:
- Minimum element
--------------------------------------------------
Concept:
- Minimum element means the smallest value in the array
- We can:
  1. Sort the array and take first element
  2. Compare elements one by one
--------------------------------------------------
Logic (Method 1 - Sorting):
1. Read array elements
2. Sort the array
3. First element will be minimum
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


L = [int(i) for i in input().split()]  # read array elements


L.sort()                            # sort array in ascending order


print(L[0])                         # first element is minimum


--------------------------------------------------
Logic (Method 2 - Without Sorting):
1. Assume first element as min
2. Compare with all elements
3. Update min if smaller element found
--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


m = L[0]                             # assume first element as min


for i in L:
    if i < m:                        # check smaller element
        m = i                        # update min


print(m)                             # print minimum element


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 25 5 40 15


Step 1:
L = [10, 25, 5, 40, 15]


Method 1 (Sorting):
After sort → [5, 10, 15, 25, 40]
First element → 5


Method 2 (Manual):
Initial m = 10
Compare 25 → no change
Compare 5 → m = 5
Compare 40 → no change
Compare 15 → no change


Output:
5


--------------------------------------------------
========================================================================PLB115 - Difference Between Largest and Smallest Element
--------------------------------------------------
Problem Statement:
Write a program to read array elements and find the difference between max and min element.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
Condition:
- n < 100
Output:
- Difference between max and min element
--------------------------------------------------
Concept:
- Max = largest element
- Min = smallest element
- Difference = Max - Min
--------------------------------------------------
Logic (Method 1 - Sorting):
1. Read array elements
2. Sort the array
3. Max = last element → L[n-1]
4. Min = first element → L[0]
5. Difference = L[n-1] - L[0]
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


L = [int(i) for i in input().split()]  # read array elements


L.sort()                            # sort array


# last element = max, first element = min
print(L[n-1] - L[0])                # print difference


--------------------------------------------------
Logic (Method 2 - Without Sorting):
1. Find max element
2. Find min element
3. Subtract min from max
--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


mx = L[0]                            # assume first element as max
mn = L[0]                            # assume first element as min


for i in L:
    if i > mx:                       # update max
        mx = i
    if i < mn:                       # update min
        mn = i


print(mx - mn)                       # print difference


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 25 5 40 15


Step 1:
L = [10, 25, 5, 40, 15]


Method 1 (Sorting):
After sort → [5, 10, 15, 25, 40]
Max = 40, Min = 5
Difference = 40 - 5 = 35


Method 2 (Manual):
mx=10, mn=10
Compare 25 → mx=25
Compare 5 → mn=5
Compare 40 → mx=40
Compare 15 → no change


Output:
35


--------------------------------------------------
========================================================================PLB116 - Second Largest Element in an Array
--------------------------------------------------
Problem Statement:
Write a program to read array elements and find the second maximum element.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
Condition:
- n < 100
Output:
- Second largest element
--------------------------------------------------
Concept:
- After sorting:
  Max element = L[n-1]
  Second max = L[n-2]
--------------------------------------------------
Logic (Method 1 - Sorting):
1. Read array elements
2. Sort the array
3. Second largest = L[n-2]
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


L = [int(i) for i in input().split()]  # read array elements


L.sort()                            # sort array in ascending order


print(L[n-2])                       # second largest element


--------------------------------------------------
Logic (Method 2 - Without Sorting):
1. Find largest element
2. Find second largest element
--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


max1 = float('-inf')                 # largest element
max2 = float('-inf')                 # second largest


for i in L:
    if i > max1:                     # if new max found
        max2 = max1                  # update second max
        max1 = i                     # update max
    elif i > max2 and i != max1:     # update second max
        max2 = i


print(max2)                          # print second largest


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 25 5 40 15


Step 1:
L = [10, 25, 5, 40, 15]


Method 1 (Sorting):
After sort → [5, 10, 15, 25, 40]
Second largest → 25


Method 2 (Manual):
max1=-inf, max2=-inf
10 → max1=10
25 → max1=25, max2=10
5 → no change
40 → max1=40, max2=25
15 → no change


Output:
25


--------------------------------------------------
========================================================================PLB117 - Second Smallest Element in an Array
--------------------------------------------------
Problem Statement:
Write a program to read array elements and find the second minimum element.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
Condition:
- n < 100
Output:
- Second smallest element
--------------------------------------------------
Concept:
- After sorting:
  Smallest element = L[0]
  Second smallest = L[1]
--------------------------------------------------
Logic (Method 1 - Sorting):
1. Read array elements
2. Sort the array
3. Second smallest = L[1]
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


L = [int(i) for i in input().split()]  # read array elements


L.sort()                            # sort array in ascending order


print(L[1])                         # second smallest element


--------------------------------------------------
Logic (Method 2 - Without Sorting):
1. Find smallest element
2. Find second smallest element
--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


min1 = float('inf')                  # smallest element
min2 = float('inf')                  # second smallest


for i in L:
    if i < min1:                     # new smallest found
        min2 = min1                  # update second smallest
        min1 = i                     # update smallest
    elif i < min2 and i != min1:     # update second smallest
        min2 = i


print(min2)                          # print second smallest


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 25 5 40 15


Step 1:
L = [10, 25, 5, 40, 15]


Method 1 (Sorting):
After sort → [5, 10, 15, 25, 40]
Second smallest → 10


Method 2 (Manual):
min1=inf, min2=inf
10 → min1=10
25 → min2=25
5 → min1=5, min2=10
40 → no change
15 → no change


Output:
10


--------------------------------------------------
========================================================================PLB118 - Number of Occurrences of an Element
--------------------------------------------------
Problem Statement:
Write a program to find the number of occurrences of a given element in an array.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
- Element to search (key)
Condition:
- n < 100
Output:
- Number of occurrences of the element
--------------------------------------------------
Concept:
- Occurrence means how many times an element appears in array
--------------------------------------------------
Logic:
1. Read array elements
2. Take key element
3. Count how many times key appears
4. Print count
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


L = [int(i) for i in input().split()]  # read array elements


key = int(input())                  # read element to search


print(L.count(key))                 # count occurrences of key


--------------------------------------------------
Line Explanation:


L.count(key)
→ counts how many times key appears in list


Example:
L = [1,2,2,3,2]
key = 2 → count = 3


--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


key = int(input())                   # element to search


count = 0                            # initialize counter


for i in L:
    if i == key:                     # check match
        count += 1                   # increase count


print(count)                         # print result


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
1 2 2 3 2
2


Step:
L = [1,2,2,3,2]


Check:
1 → no
2 → count=1
2 → count=2
3 → no
2 → count=3


Output:
3


--------------------------------------------------
========================================================================PLB119 - Insert Element at First Position in an Array
--------------------------------------------------
Problem Statement:
Write a program to insert an element at the first position in an array.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
- Element to be inserted
Condition:
- n < 100
Output:
- Array after insertion
--------------------------------------------------
Concept:
- Insert at first position (index 0)
- All elements shift to right
--------------------------------------------------
Logic:
1. Read array elements
2. Take element to insert
3. Insert at index 0
4. Print updated array
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


# read elements and convert to list
L = [int(i) for i in input().split()]


# take input and insert directly at index 0
L.insert(0, int(input()))           # insert element at first position


# print updated array
for i in L:
    print(i, end=' ')


--------------------------------------------------
Line Explanation:


L.insert(0, int(input()))
→ takes input and inserts at index 0
→ shifts all elements right


--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input string
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


x = int(input())                     # element to insert


L.insert(0, x)                       # insert at first position


for i in L:
    print(i, end=' ')                # print result


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 20 30 40 50
5


Step:
L = [10, 20, 30, 40, 50]


After insertion:
[5, 10, 20, 30, 40, 50]


Output:
5 10 20 30 40 50


--------------------------------------------------
========================================================================PLB120 - Insert Element at Last Position in an Array
--------------------------------------------------
Problem Statement:
Write a program to insert an element at the last position in an array.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
- Element to be inserted
Condition:
- n < 100
Output:
- Array after insertion
--------------------------------------------------
Concept:
- Insert at last means element is added at end of array
- No shifting required
--------------------------------------------------
Logic:
1. Read array elements
2. Take element to insert
3. Add at last position
4. Print updated array
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


# read elements and convert to list
L = [int(i) for i in input().split()]


# take input and append at end
L.append(int(input()))              # insert element at last position


# print updated array
for i in L:
    print(i, end=' ')


--------------------------------------------------
Line Explanation:


L.append(x)
→ adds element at end of list
→ no shifting required


--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input string
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


x = int(input())                     # element to insert


L.append(x)                          # insert at last position


for i in L:
    print(i, end=' ')                # print result


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 20 30 40 50
99


Step:
L = [10, 20, 30, 40, 50]


After insertion:
[10, 20, 30, 40, 50, 99]


Output:
10 20 30 40 50 99


--------------------------------------------------
========================================================================PLB121 - Delete Element from First Position in an Array
--------------------------------------------------
Problem Statement:
Write a program to delete an element from the first position in an array.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
Condition:
- n < 100
Output:
- Array after deletion from first position
--------------------------------------------------
Concept:
- First element is at index 0
- Deleting it shifts all elements to left
--------------------------------------------------
Logic:
1. Read array elements
2. Remove element at index 0
3. Print updated array
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


# read elements and convert to list
L = [int(i) for i in input().split()]


L.pop(0)                            # remove first element (index 0)


# print updated array
for i in L:
    print(i, end=' ')


--------------------------------------------------
Line Explanation:


L.pop(0)
→ removes element at index 0
→ shifts remaining elements to left


--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input string
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


# remove first element
L.pop(0)


for i in L:
    print(i, end=' ')                # print result


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 20 30 40 50


Step:
L = [10, 20, 30, 40, 50]


After deletion:
[20, 30, 40, 50]


Output:
20 30 40 50


--------------------------------------------------
========================================================================PLB122 - Delete Element from Last Position in an Array
--------------------------------------------------
Problem Statement:
Write a program to delete an element from the last position in an array.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
Condition:
- n < 100
Output:
- Array after deletion from last position
--------------------------------------------------
Concept:
- Last element is at index n-1
- Removing last element does not require shifting
--------------------------------------------------
Logic:
1. Read array elements
2. Remove last element
3. Print updated array
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


# This line reads input and converts it into a list of integers
L = [int(i) for i in input().split()]


L.pop()                             # remove last element


# print updated array
for i in L:
    print(i, end=' ')


--------------------------------------------------
Line Explanation (Important):


# L = [int(i) for i in input().split()]


# Step 1: input() → takes input as a string
# Example: "10 20 30 40 50"


# Step 2: split() → splits string into list of strings
# ['10', '20', '30', '40', '50']


# Step 3: for i in ... → loop through each element
# i = '10', '20', '30', ...


# Step 4: int(i) → convert string to integer
# '10' → 10


# Step 5: [] → store all values in a list


# Final:
# L = [10, 20, 30, 40, 50]


--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input string
nums = data.split()                  # split into list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


# remove last element
L.pop()


for i in L:
    print(i, end=' ')                # print result


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 20 30 40 50


Step:
L = [10, 20, 30, 40, 50]


After deletion:
[10, 20, 30, 40]


Output:
10 20 30 40


--------------------------------------------------
========================================================================PLB123 - Delete Element at Given Position in an Array
--------------------------------------------------
Problem Statement:
Write a program to delete an element from an array at a given position.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
- Position to delete
Condition:
- n < 100
Output:
- Array after deletion
--------------------------------------------------
Concept:
- Position means index (0-based)
- Deleting element shifts remaining elements left
--------------------------------------------------
Logic:
1. Read array elements
2. Take position input
3. Delete element at that index
4. Print updated array
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


# read elements and convert to integer list
L = [int(i) for i in input().split()]


pos = int(input())                  # position to delete


L.pop(pos)                          # remove element at given index


# print updated array
for i in L:
    print(i, end=' ')


--------------------------------------------------
Line Explanation (Important):


# L = [int(i) for i in input().split()]


# Step 1: input() → takes input as string
# Example: "10 20 30 40 50"


# Step 2: split() → converts into list of strings
# ['10','20','30','40','50']


# Step 3: for i in ... → loop through each element


# Step 4: int(i) → convert string to integer


# Step 5: [] → create final list


# Final:
# L = [10, 20, 30, 40, 50]


--------------------------------------------------
Line Explanation:


L.pop(pos)
→ removes element at given index
→ remaining elements shift left


--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input string
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


pos = int(input())                   # position to delete


L.pop(pos)                           # delete element


for i in L:
    print(i, end=' ')                # print result


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 20 30 40 50
2


Step:
L = [10, 20, 30, 40, 50]


Delete index 2:
→ remove 30


Result:
[10, 20, 40, 50]


Output:
10 20 40 50
========================================================================
PLB124 - Delete a Given Element from an Array
--------------------------------------------------
Problem Statement:
Write a program to delete a given element from an array.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
- Element to delete (e)
Condition:
- n < 100
Output:
- Array after deleting the element
- If element not found → print -1
--------------------------------------------------
Concept:
- Delete by value (not index)
- Only first occurrence will be removed
--------------------------------------------------
Logic:
1. Read array elements
2. Take element to delete
3. Check if element exists
4. Remove it
5. Print updated array
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


# read elements and convert to integer list
L = [int(i) for i in input().split()]


e = int(input())                    # element to delete


if e in L:                          # check if element exists
    L.remove(e)                     # remove first occurrence


    # print updated array
    for i in L:
        print(i, end=' ')
else:
    print(-1)                       # element not found


--------------------------------------------------
Line Explanation (Important):


# L = [int(i) for i in input().split()]


# Step 1: input() → takes input as string
# Example: "10 20 30 40 50"


# Step 2: split() → converts into list of strings
# ['10','20','30','40','50']


# Step 3: for i in ... → loop through each element


# Step 4: int(i) → convert string to integer


# Step 5: [] → create final list


# Final:
# L = [10, 20, 30, 40, 50]


--------------------------------------------------
Line Explanation:


L.remove(e)
→ removes first occurrence of element e
→ shifts remaining elements left


--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input string
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


e = int(input())                     # element to delete


found = False                        # flag


for i in L:
    if i == e:
        L.remove(i)                  # remove element
        found = True
        break


if found:
    for i in L:
        print(i, end=' ')            # print result
else:
    print(-1)                        # not found


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 20 30 40 50
30


Step:
L = [10, 20, 30, 40, 50]


Delete element 30:
→ [10, 20, 40, 50]


Output:
10 20 40 50


--------------------------------------------------
========================================================================
PLB125 - Update an Element in an Array
--------------------------------------------------
Problem Statement:
Write a program to update an element in the given array.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
- Old element (oe)
- New element (ne)
Condition:
- n < 100
Output:
- Array after updating
--------------------------------------------------
Concept:
- Replace old element with new element
- Update is done by value (not index)
--------------------------------------------------
Logic:
1. Read array elements
2. Take old element and new element
3. Traverse array
4. If element == old → replace with new
5. Print updated array
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


# read elements and convert to integer list
L = [int(i) for i in input().split()]


oe = int(input())                   # old element
ne = int(input())                   # new element


# loop through array using index
for i in range(0, n):
    if L[i] == oe:                  # check old element
        L[i] = ne                   # replace with new element


# print updated array
for i in L:
    print(i, end=' ')


--------------------------------------------------
Line Explanation (Important):


# L = [int(i) for i in input().split()]


# Step 1: input() → takes input as string
# Example: "10 20 30 40 50"


# Step 2: split() → converts into list of strings
# ['10','20','30','40','50']


# Step 3: for i in ... → loop through each element


# Step 4: int(i) → convert string to integer


# Step 5: [] → create final list


# Final:
# L = [10, 20, 30, 40, 50]


--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input string
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


oe = int(input())                    # old element
ne = int(input())                    # new element


for i in range(len(L)):              # loop using index
    if L[i] == oe:                  # check condition
        L[i] = ne                   # update value


for i in L:
    print(i, end=' ')                # print result


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 20 30 40 50
30
99


Step:
L = [10, 20, 30, 40, 50]


Replace 30 with 99:
→ [10, 20, 99, 40, 50]


Output:
10 20 99 40 50


--------------------------------------------------






========================================================================PLB126 - Update Element in an Array by Position
--------------------------------------------------
Problem Statement:
Write a program to update an element in the array based on given position.
--------------------------------------------------
Input:
- Size of array (n)
- Array elements
- Position (loc)
- New element (ne)
Condition:
- n < 100
Output:
- Array after updating
--------------------------------------------------
Concept:
- Position means index (0-based)
- Replace value at given index with new value
--------------------------------------------------
Logic:
1. Read array elements
2. Take position (index)
3. Take new element
4. Replace L[loc] with new element
5. Print updated array
--------------------------------------------------
Python Implementation (With Comments):


n = int(input())                     # read size of array


# read elements and convert to integer list
L = [int(i) for i in input().split()]


loc = int(input())                  # position (index to update)


ne = int(input())                   # new element


L[loc] = ne                         # update element at given index


# print updated array
for i in L:
    print(i, end=' ')


--------------------------------------------------
Line Explanation (Important):


# L = [int(i) for i in input().split()]


# Step 1: input() → takes input as string
# Example: "10 20 30 40 50"


# Step 2: split() → converts into list of strings
# ['10','20','30','40','50']


# Step 3: for i in ... → loop through each element


# Step 4: int(i) → convert string to integer


# Step 5: [] → create final list


# Final:
# L = [10, 20, 30, 40, 50]


--------------------------------------------------
Line Explanation:
#Loc =location  and ne=new location
L[loc] = ne  → updates element at index loc with new value


Example:
L = [10,20,30]
loc = 1, ne = 99
→ L = [10,99,30]


--------------------------------------------------
Multiline Version (With Comments):


n = int(input())                     # read size


data = input()                       # read input string
nums = data.split()                  # split list


L = []                               # empty list


for i in nums:
    L.append(int(i))                 # convert to int


loc = int(input())                   # position
ne = int(input())                    # new element


L[loc] = ne                          # update


for i in L:
    print(i, end=' ')                # print result


--------------------------------------------------
Dry Run (With Input Reference):


Input:
5
10 20 30 40 50
2
99


Step:
L = [10, 20, 30, 40, 50]


Update index 2:
→ replace 30 with 99


Result:
[10, 20, 99, 40, 50]


Output:
10 20 99 40 50


--------------------------------------------------
========================================================================
================================
PLB127 - ARRAY REVERSE
================================


PROBLEM:
Write a program to reverse the elements present in an array.


INPUT:
n -> size of array
array elements (space separated)


CONSTRAINT:
n < 100


OUTPUT:
Print array in reverse order




================================
LOGIC:
================================
1. Take size n
2. Take array input using split()
3. Convert elements to integer
4. Use slicing [::-1] to reverse array
5. Print elements




================================
PYTHON CODE:
================================


# Take size of array
n = int(input())


# Take array elements
# input().split() → splits input into list of strings
# int(i) → converts each element into integer
# [] → creates final list
L = [int(i) for i in input().split()]


# Reverse and print
# [::-1] → reverse the list
for i in L[::-1]:
    print(i, end=' ')




================================
IMPORTANT POINT:
================================
L = [int(i) for i in input().split()]


Example:
Input: 1 2 3 4
Step 1: split() → ['1','2','3','4']
Step 2: int(i) → [1,2,3,4]
Final List → L = [1,2,3,4]




================================
EXAMPLE:
================================


INPUT:
5
10 20 30 40 50


OUTPUT:
50 40 30 20 10




================================
SHORT METHOD:
================================
print(*L[::-1])




================================
PSEUDO CODE:
================================
START
INPUT n
INPUT array L
REVERSE L using slicing
PRINT reversed array
END




================================
EXTRA (WITHOUT SLICING - INTERVIEW):
================================


for i in range(n-1, -1, -1):
    print(L[i], end=' ')
========================================================================
================================
PLB128 - INCREMENT ARRAY ELEMENTS
================================


PROBLEM:
Implement a program to increment every element by one unit in array.


INPUT:
n -> size of array
array elements (space separated)


CONSTRAINT:
n < 100


OUTPUT:
Increment each element by one unit




================================
LOGIC:
================================
1. Take size n
2. Take array input using split()
3. Convert elements to integer
4. Traverse each element in array
5. Add 1 to each element
6. Print updated values




================================
PYTHON CODE:
================================


# Take size of array
n = int(input())


# Take array elements
# input().split() → splits input into list of strings
# int(i) → converts each element into integer
L = [int(i) for i in input().split()]


# Traverse and increment each element
for i in L:
    print(i + 1, end=' ')




================================
IMPORTANT POINT:
================================
for i in L:
→ i directly har element ko represent karta hai


i + 1
→ har element me 1 add ho raha hai




================================
EXAMPLE:
================================


INPUT:
5
1 2 3 4 5


OUTPUT:
2 3 4 5 6




================================
SHORT METHOD:
================================
print(*[i+1 for i in L])




================================
PSEUDO CODE:
================================
START
INPUT n
INPUT array L
FOR each element in L
    ADD 1
    PRINT element
END




================================
EXTRA (USING INDEX):
================================


for i in range(n):
    print(L[i] + 1, end=' ')


--------------------------------------------------
========================================================================
================================================================
PLB129 - NUMBER OF DUPLICATE ELEMENTS (VIMP Interview Question)
================================================================


PROBLEM:
Implement a program to find the number of duplicate elements present in the given array.


INPUT:
n -> size of array
array elements (space separated)


CONSTRAINT:
n < 100


OUTPUT:
Number of duplicate elements in the array




================================
PYTHON ARRAY vs LIST CONCEPT (VERY IMPORTANT)
================================


In Python, we do NOT explicitly create arrays like in C or Java.


Python uses LIST instead of array.


Example:
L = [int(i) for i in input().split()]


→ Here, input is taken AND list is created in the same line.


So:
- No separate array declaration
- List acts as array


Traditional Way (for understanding):
L = []
for i in input().split():
    L.append(int(i))


→ First create list, then insert elements




================================
LOGIC:
================================
1. Take size n
2. Take array input using split()
3. Use dictionary to store frequency of elements
4. Traverse array and count frequency
5. Check values in dictionary
6. If frequency >= 2 → count it as duplicate
7. Print count




================================
PYTHON CODE (MAIN APPROACH - DICTIONARY)
================================


# Take size of array
n = int(input())


# Take array elements
L = [int(i) for i in input().split()]


# Create empty dictionary
d = {}


# Counter for duplicates
c = 0


# Count frequency of each element
for i in L:
    d[i] = d.get(i, 0) + 1


# Check duplicates
for i in d.values():
    if i >= 2:
        c = c + 1


# Print result
print(c)




================================
IMPORTANT SYNTAX (VERY IMPORTANT)
================================


d.get(key, default_value)


Example:
d.get(1, 0)


Explanation:
- key → element we are searching
- default_value → returned if key is not present


Working:
→ If key exists → return value
→ If key does NOT exist → return default value


Real Usage:
d[i] = d.get(i, 0) + 1


→ If 'i' exists → increase value
→ If not → start from 1




================================
STEP BY STEP EXAMPLE
================================


L = [1,1,2]


Iteration 1:
i = 1 → d.get(1,0)=0 → d[1]=1


Iteration 2:
i = 1 → d.get(1,0)=1 → d[1]=2


Iteration 3:
i = 2 → d.get(2,0)=0 → d[2]=1


Final:
d = {1:2, 2:1}




================================
EXAMPLE
================================


INPUT:
5
1 1 2 2 3


OUTPUT:
2




================================
EXTRA METHOD 1 (SET + COUNT)
================================


L = [1,2,3,3,4,4,4,5]


S = set(L)


for i in S:
    if L.count(i) > 1:
        print(i, "count is", L.count(i))


NOTE:
- Simple but slow
- Time Complexity: O(n^2)




================================
EXTRA METHOD 2 (BRUTE FORCE)
================================


c = 0
for i in range(n):
    for j in range(i+1, n):
        if L[i] == L[j]:
            c = c + 1
            break
print(c)




================================
TIME COMPLEXITY
================================


Dictionary   → O(n)   ✔ Best
Set + Count  → O(n^2) ❌
Brute Force  → O(n^2) ❌




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L
CREATE dictionary d


FOR each element
    update frequency


SET count = 0


FOR each value
    IF value >= 2
        count++


PRINT count
END




================================
FINAL INTERVIEW LINE
================================


"In Python, lists act as arrays and can be created during input itself. 
Dictionary-based frequency counting is the most efficient approach with O(n) time complexity."


=======================================================================
================================
TIME COMPLEXITY (FULL EXPLANATION)
================================


DEFINITION:
Time Complexity tells how the running time of a program grows with input size (n).




================================
WHAT IS "n" ?
================================


n → number of elements / size of input


Example:
If array = [1,2,3,4,5]
Then n = 5




================================
WHAT IS "O" (BIG O NOTATION)?
================================


"O" does NOT stand for any abbreviation.


It is called Big O Notation.


Meaning:
It represents the order of growth of an algorithm.


It tells:
- How time increases when input size (n) increases
- Focus is on growth, not exact time




================================
EXECUTION TIME MEANING
================================


These terms (Fast, Slow) do NOT mean exact time in seconds.


They show how time increases when input size (n) increases.


Assume:
1 operation = 1 unit time




--------------------------------
O(1) → Constant
--------------------------------
n = 10   → 1 operation
n = 1000 → 1 operation


→ Time does NOT change




--------------------------------
O(log n) → Logarithmic
--------------------------------
n = 8   → 3 operations
n = 16  → 4 operations
n = 1024→ 10 operations


→ Time increases very slowly




--------------------------------
O(n) → Linear
--------------------------------
n = 10   → 10 operations
n = 1000 → 1000 operations


→ Time increases proportionally with n




--------------------------------
O(n log n)
--------------------------------
n = 10   → ~30 operations
n = 1000 → ~10000 operations


→ Faster than O(n²), slower than O(n)




--------------------------------
O(n²) → Quadratic
--------------------------------
n = 10   → 100 operations
n = 1000 → 1000000 operations 😵


→ Time increases very fast




================================
SUMMARY
================================


O(1)      → Constant (Fastest)
O(log n)  → Very Fast
O(n)      → Linear (Good)
O(n log n)→ Moderate
O(n²)     → Slow




================================
YOUR PROBLEM CONNECTION
================================


Dictionary Method:
for i in L:
    d[i] = d.get(i, 0) + 1


→ One loop over n elements
→ Time = O(n)




Set + Count Method:
for i in set(L):
    L.count(i)


→ count() runs over n each time
→ loop inside loop
→ Time = O(n²)




Brute Force:
nested loops


→ Time = O(n²)




================================
INTERVIEW LINE
================================


"Big O notation represents the order of growth of an algorithm. 
It is not an abbreviation. 
Execution time is measured in number of operations, not actual seconds."


================================================================
PLB130 - PRINT UNIQUE ELEMENTS IN ARRAY (FINAL COMPLETE SCRIPT)
================================================================


PROBLEM:
Print unique elements from the given array.




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 1 2 3 4


Step 1:
input() → "1 2 3 4"


Step 2:
split() → ['1','2','3','4']


Step 3:
int(i) → [1,2,3,4]


Final:
L = [1,2,3,4]




================================
ARRAY vs LIST IN PYTHON (VERY IMPORTANT)
================================


Python does NOT use traditional arrays like C/Java.
Instead, it uses LIST.


LIST:
- Built-in
- Can store different data types
- Most commonly used


Example:
L = [1, "hello", 3.5]


ARRAY:
- Requires import (array module)
- Stores same data type only
- More memory efficient


Example:
import array
arr = array.array('i', [1,2,3])


NOTE:
In Python, list is commonly used as array.




================================
PYTHON CODE (MAIN - LIST METHOD)
================================


# Take size
n = int(input())   # string → int


# Take elements
# input() → string
# split() → list of strings
# int(i) → list of integers
L = [int(i) for i in input().split()]


# Create empty list for unique elements
LL = []


# Traverse list
for i in L:
    # Check if element already exists
    if i not in LL:
        LL.append(i)   # add unique element


# Print result
for i in LL:
    print(i, end=' ')




================================
METHOD 2 (USING SET)
================================


n = int(input())
L = [int(i) for i in input().split()]


# Convert list to set (removes duplicates)
S = set(L)


for i in S:
    print(i, end=' ')   # order not guaranteed




================================
METHOD 3 (BEST - SET + LIST)
================================


n = int(input())
L = [int(i) for i in input().split()]


seen = set()     # track elements
result = []      # maintain order


for i in L:
    if i not in seen:
        seen.add(i)
        result.append(i)


print(*result)




================================
TIME COMPLEXITY
================================


List Method       → O(n²) ❌
Set Method        → O(n) ✔
Set + List Method → O(n) ✔ BEST




================================
INTERVIEW LINE
================================


"In Python, input is taken as string and converted using split() and int(). 
Lists are used instead of arrays. 
Set improves performance to O(n), and set + list maintains order."
================================================================
PLB131 - SORT ARRAY OF 0s, 1s AND 2s
================================================================


PROBLEM:
Implement a program to read an array and sort elements containing only 0s, 1s and 2s.


INPUT:
n -> size of array
array elements (space separated)


CONSTRAINT:
n < 100


OUTPUT:
Print sorted elements




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 2 1 0 2 1


Step 1:
input() → "2 1 0 2 1"


Step 2:
split() → ['2','1','0','2','1']


Step 3:
int(i) → [2,1,0,2,1]


Final:
L = [2,1,0,2,1]




================================
ARRAY vs LIST IN PYTHON
================================


Python uses LIST instead of array


List:
- Built-in
- Flexible


Array:
- Requires import
- Same data type only


NOTE:
List is used as array in Python




================================
PYTHON CODE (MAIN - SORT METHOD)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# Sort list
L.sort()   # built-in sort (ascending order)


# Print result
for i in L:
    print(i, end=' ')




================================
IMPORTANT POINT
================================


L.sort()
→ sorts list in ascending order


Example:
[2,1,0,2] → [0,1,2,2]




================================
EXAMPLE
================================


INPUT:
5
2 1 0 2 1


OUTPUT:
0 1 1 2 2




================================
METHOD 2 (COUNTING METHOD - BEST)
================================


n = int(input())
L = [int(i) for i in input().split()]


# Count 0s, 1s, 2s
c0 = c1 = c2 = 0


for i in L:
    if i == 0:
        c0 += 1
    elif i == 1:
        c1 += 1
    else:
        c2 += 1


# Print sorted result
print("0 "*c0 + "1 "*c1 + "2 "*c2)




================================
METHOD 3 (DUTCH NATIONAL FLAG - ADVANCED)
================================


low = 0
mid = 0
high = len(L) - 1


while mid <= high:
    if L[mid] == 0:
        L[low], L[mid] = L[mid], L[low]
        low += 1
        mid += 1


    elif L[mid] == 1:
        mid += 1


    else:
        L[mid], L[high] = L[high], L[mid]
        high -= 1


print(*L)




================================
TIME COMPLEXITY
================================


Sort() Method       → O(n log n)
Counting Method     → O(n) ✔ Best
DNF Algorithm       → O(n) ✔ Best




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


SORT L


PRINT L
END




================================
INTERVIEW LINE
================================


"For sorting 0s, 1s and 2s, counting method or Dutch National Flag algorithm is preferred as it works in O(n) time, better than built-in sort."


================================================================
PLB132 - REPLACE EVERY ELEMENT WITH GREATEST ON RIGHT SIDE
================================================================


PROBLEM:
Replace every element in the array with the greatest element on its right side.


INPUT:
n -> size of array
array elements (space separated)


CONSTRAINT:
n < 100


OUTPUT:
Print updated array




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 5 3 8 2


Step 1:
input() → "5 3 8 2"


Step 2:
split() → ['5','3','8','2']


Step 3:
int(i) → [5,3,8,2]


Final:
L = [5,3,8,2]




================================
LOGIC
================================


1. Traverse array
2. For each element → find max element on right side
3. Replace current element with that max
4. Print updated array




================================
PYTHON CODE (MAIN - SIMPLE METHOD)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# Replace each element
for i in range(n):
    L[i] = max(L[i:])   # max of right side including itself


# Print result
for i in L:
    print(i, end=' ')




================================
IMPORTANT POINT
================================


L[i:] → slice from index i to end


Example:
L = [5,3,8,2]


i=0 → [5,3,8,2] → max=8  
i=1 → [3,8,2] → max=8  
i=2 → [8,2] → max=8  
i=3 → [2] → max=2  




================================
EXAMPLE
================================


INPUT:
4
5 3 8 2


OUTPUT:
8 8 8 2




================================
TIME COMPLEXITY
================================


- max() runs O(n)
- loop runs n times


Total:
→ O(n²) ❌ (slow)




================================
METHOD 2 (BEST - RIGHT MAX TRACKING)
================================


# Take input
n = int(input())
L = [int(i) for i in input().split()]


# Start from right
max_right = -1


for i in range(n-1, -1, -1):
    temp = L[i]
    L[i] = max_right
    max_right = max(max_right, temp)


# Print result
print(*L)


TIME:
→ O(n) ✔ Best




================================
STEP BY STEP (METHOD 2)
================================


L = [5,3,8,2]


i=3 → max_right=-1 → L[3]=-1 → max_right=2  
i=2 → L[2]=2 → max_right=8  
i=1 → L[1]=8 → max_right=8  
i=0 → L[0]=8 → max_right=8  


Final:
[8,8,2,-1]




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


FOR each element
    replace with max of right


PRINT array
END




================================
INTERVIEW LINE
================================


"Brute force uses max() inside loop giving O(n²). 
Optimized approach traverses from right and maintains max value, achieving O(n)."


================================================================
PLB133 - SUM OF TWO ARRAYS
================================================================


PROBLEM:
Implement a program to find the sum of two arrays and display the resultant array.


INPUT:
n -> size of array
array1 elements
array2 elements


CONSTRAINT:
No constraint


OUTPUT:
Print resultant array




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 1 2 3


Step 1:
input() → "1 2 3"


Step 2:
split() → ['1','2','3']


Step 3:
int(i) → [1,2,3]


Final:
L = [1,2,3]




================================
LOGIC
================================


1. Take size n
2. Take first array L1
3. Take second array L2
4. Traverse both arrays
5. Add corresponding elements
6. Print result




================================
PYTHON CODE (MAIN)
================================


# Take size
n = int(input())


# Take first array
L1 = [int(i) for i in input().split()]


# Take second array
L2 = [int(i) for i in input().split()]


# Add elements
for i in range(n):
    print(L1[i] + L2[i], end=' ')




================================
IMPORTANT POINT
================================


L1[i] + L2[i]
→ adds elements at same index


Example:
L1 = [1,2,3]
L2 = [4,5,6]


Result:
[5,7,9]




================================
EXAMPLE
================================


INPUT:
3
1 2 3
4 5 6


OUTPUT:
5 7 9




================================
TIME COMPLEXITY
================================


- Single loop runs n times


Total:
→ O(n) ✔




================================
METHOD 2 (USING LIST)
================================


result = []


for i in range(n):
    result.append(L1[i] + L2[i])


print(*result)




================================
METHOD 3 (USING ZIP - PYTHONIC)
================================


result = [x + y for x, y in zip(L1, L2)]


print(*result)




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L1
INPUT array L2


FOR i = 0 to n-1
    sum = L1[i] + L2[i]
    print sum


END




================================
INTERVIEW LINE
================================


"Element-wise addition of two arrays is done using a single loop in O(n) time. 
Python's zip() provides a cleaner and more efficient approach."
================================================================
PLB134 - SUM OF ELEMENTS AT EVEN INDEX
================================================================


PROBLEM:
Implement a program to find the sum of elements available at even index positions in an array.


INPUT:
n -> size of array
array elements


CONSTRAINT:
No constraint


OUTPUT:
Print sum value




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 1 2 3 4 5


Step 1:
input() → "1 2 3 4 5"


Step 2:
split() → ['1','2','3','4','5']


Step 3:
int(i) → [1,2,3,4,5]


Final:
L = [1,2,3,4,5]




================================
LOGIC
================================


1. Take size n
2. Take array L
3. Initialize sum = 0
4. Traverse array using index
5. If index is even (i % 2 == 0)
6. Add element to sum
7. Print sum




================================
PYTHON CODE (MAIN)
================================


# Take size
n = int(input())


# Initialize sum
s = 0


# Take elements
L = [int(i) for i in input().split()]


# Traverse using index
for i in range(n):
    # Check even index
    if i % 2 == 0:
        s = s + L[i]


# Print result
print(s)




================================
IMPORTANT POINT
================================


i % 2 == 0
→ checks if index is even


Even index:
0, 2, 4, 6 ...




================================
EXAMPLE
================================


INPUT:
5
1 2 3 4 5


Indexes:
0 1 2 3 4


Even index elements:
1 (index 0), 3 (index 2), 5 (index 4)


OUTPUT:
9




================================
TIME COMPLEXITY
================================


- Loop runs n times


Total:
→ O(n) ✔




================================
METHOD 2 (STEP LOOP)
================================


s = 0


for i in range(0, n, 2):   # step = 2 (only even index)
    s += L[i]


print(s)




================================
METHOD 3 (PYTHONIC)
================================


print(sum(L[::2]))


L[::2] → takes elements at even index




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


SET sum = 0


FOR i = 0 to n-1
    IF i is even
        sum = sum + L[i]


PRINT sum
END




================================
INTERVIEW LINE
================================


"Even index elements can be summed using a loop or slicing. 
Using step slicing (L[::2]) is the most Pythonic and concise approach."


================================================================
PLB135 - SUM OF ELEMENTS AT ODD INDEX
================================================================


PROBLEM:
Implement a program to find the sum of elements available at odd index positions in an array.


INPUT:
n -> size of array
array elements


CONSTRAINT:
No constraint


OUTPUT:
Print sum value




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 1 2 3 4 5


Step 1:
input() → "1 2 3 4 5"


Step 2:
split() → ['1','2','3','4','5']


Step 3:
int(i) → [1,2,3,4,5]


Final:
L = [1,2,3,4,5]




================================
LOGIC
================================


1. Take size n
2. Take array L
3. Initialize sum = 0
4. Traverse array using index
5. If index is odd (i % 2 != 0)
6. Add element to sum
7. Print sum




================================
PYTHON CODE (MAIN)
================================


# Take size
n = int(input())


# Initialize sum
s = 0


# Take elements
L = [int(i) for i in input().split()]


# Traverse using index
for i in range(n):
    # Check odd index
    if i % 2 != 0:
        s = s + L[i]


# Print result
print(s)




================================
IMPORTANT POINT
================================


i % 2 != 0
→ checks if index is odd


Odd index:
1, 3, 5, 7 ...




================================
EXAMPLE
================================


INPUT:
5
1 2 3 4 5


Indexes:
0 1 2 3 4


Odd index elements:
2 (index 1), 4 (index 3)


OUTPUT:
6




================================
TIME COMPLEXITY
================================


- Loop runs n times


Total:
→ O(n) ✔




================================
METHOD 2 (STEP LOOP)
================================


s = 0


for i in range(1, n, 2):   # start from index 1
    s += L[i]


print(s)




================================
METHOD 3 (PYTHONIC)
================================


print(sum(L[1::2]))


L[1::2] → takes elements at odd index




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


SET sum = 0


FOR i = 0 to n-1
    IF i is odd
        sum = sum + L[i]


PRINT sum
END




================================
INTERVIEW LINE
================================


"Odd index elements can be summed using a loop or slicing. 
Using slicing (L[1::2]) is the most concise Pythonic approach."
================================================================
PLB136 - SUM OF FIRST & LAST, SECOND & SECOND LAST
================================================================


PROBLEM:
Implement a program to find the sum of first and last, second and second last, and so on in an array.


INPUT:
n -> size of array
array elements


CONSTRAINT:
No constraint


OUTPUT:
Print sum of pairs (first+last, second+second last, ...)




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 1 2 3 4


Step 1:
input() → "1 2 3 4"


Step 2:
split() → ['1','2','3','4']


Step 3:
int(i) → [1,2,3,4]


Final:
L = [1,2,3,4]




================================
LOGIC
================================


1. Take size n
2. Take array L
3. Use two pointers:
   i → start (0)
   j → end (n-1)
4. Add L[i] + L[j]
5. Move i forward and j backward
6. Repeat until i <= j




================================
PYTHON CODE (MAIN - TWO POINTER)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# Initialize pointers
i = 0
j = n - 1


# Traverse from both ends
while i <= j:
    print(L[i] + L[j], end=' ')
    i = i + 1
    j = j - 1




================================
IMPORTANT POINT
================================


i = 0 → first element  
j = n-1 → last element  


Loop condition:
i <= j → handles middle element (odd size)




================================
EXAMPLE
================================


INPUT:
5
1 2 3 4 5


Pairs:
1+5 = 6  
2+4 = 6  
3+3 = 6  


OUTPUT:
6 6 6




================================
TIME COMPLEXITY
================================


- Loop runs n/2 times


Total:
→ O(n) ✔




================================
METHOD 2 (USING FOR LOOP)
================================


for i in range((n+1)//2):
    print(L[i] + L[n-1-i], end=' ')




================================
METHOD 3 (PYTHONIC)
================================


for a, b in zip(L, reversed(L)):
    print(a + b, end=' ')
    if a == b:
        break




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


SET i = 0
SET j = n-1


WHILE i <= j
    PRINT L[i] + L[j]
    i++
    j--


END




================================
INTERVIEW LINE
================================


"Using two-pointer technique allows pairing first and last elements efficiently in O(n) time."










================================================================
PLB137 - PRINT REVERSE OF EACH NUMBER IN ARRAY
================================================================


PROBLEM:
Implement a program to print reverse of each element in an array.


INPUT:
n -> size of array
array elements


CONSTRAINT:
No constraint


OUTPUT:
Print reverse of each element in array




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 123 45 67


Step 1:
input() → "123 45 67"


Step 2:
split() → ['123','45','67']


NOTE:
Elements are kept as STRING for reversing




================================
LOGIC
================================


1. Take size n
2. Take elements as string list
3. Traverse each element
4. Reverse each string
5. Print result




================================
PYTHON CODE (MAIN - STRING METHOD)
================================


# Take size
n = int(input())


# Take elements as string (no int conversion)
L = [i for i in input().split()]


# Reverse each element
for i in L:
    print(i[::-1], end=' ')   # reverse string




================================
IMPORTANT POINT
================================


i[::-1]
→ reverses the string


Example:
"123" → "321"
"45" → "54"




================================
EXAMPLE
================================


INPUT:
3
123 45 67


OUTPUT:
321 54 76




================================
TIME COMPLEXITY
================================


- Loop runs n times
- Reverse takes O(k) per element


Total:
→ O(n) ✔ (approx)




================================
METHOD 2 (USING INT LOGIC)
================================


n = int(input())
L = [int(i) for i in input().split()]


for num in L:
    rev = 0
    while num > 0:
        digit = num % 10
        rev = rev * 10 + digit
        num = num // 10
    print(rev, end=' ')




================================
METHOD 3 (LIST COMPREHENSION)
================================


L = input().split()


result = [i[::-1] for i in L]


print(*result)




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


FOR each element
    reverse element
    print it


END




================================
INTERVIEW LINE
================================


"Reversing numbers can be done using string slicing or mathematical approach. 
String slicing is simpler and efficient in Python."




================================================================
PLB138 - COUNT EVEN AND ODD ELEMENTS IN ARRAY
================================================================


PROBLEM:
Implement a program to find number of even and odd elements in the given array.


INPUT:
n -> size of array
array elements


OUTPUT:
Print number of even and odd elements line by line




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 1 2 3 4


input() → "1 2 3 4"  
split() → ['1','2','3','4']  
int(i) → [1,2,3,4]  


Final:
L = [1,2,3,4]




================================
PYTHON CODE (MAIN)
================================


n = int(input())


L = [int(i) for i in input().split()]


ec = 0
oc = 0


for i in L:
    if i % 2 == 0:
        ec += 1
    else:
        oc += 1


print(ec)
print(oc)




================================
TIME COMPLEXITY
================================


O(n) ✔




================================
PYTHON "in" vs "is"
================================


"in" → Membership Operator  
"is" → Identity Operator  


"in":
Check if value exists in collection


Example:
2 in [1,2,3] → True  
5 in [1,2,3] → False  




"is":
Check if both variables refer to SAME OBJECT in memory




--------------------------------
WHAT IS SAME OBJECT (IMPORTANT)
--------------------------------


Same object means:
Both variables point to SAME memory location




Case 1 (Different Objects):


a = [1,2]
b = [1,2]


a == b → True   (values same)  
a is b → False  (memory different)  


Memory view:
a → [1,2] (memory A)  
b → [1,2] (memory B)  




Case 2 (Same Object):


a = [1,2]
b = a


a == b → True  
a is b → True  


Memory view:
a → [1,2]  
b ──↑ (same memory)




================================
"==" vs "is"
================================


"==" → Value comparison  
"is" → Memory comparison  




Example:


a = [1,2]
b = [1,2]
c = a


a == b → True  
a is b → False  


a is c → True  




================================
TRUE / FALSE (BOOLEAN)
================================


True → Condition satisfied  
False → Condition failed  


Examples:


5 > 2 → True  
5 < 2 → False  


2 in [1,2,3] → True  
5 in [1,2,3] → False  


None is None → True  




================================
NONE (VERY IMPORTANT)
================================


None means NO VALUE


x = None
print(x) → None


Check:
if x is None ✔




Difference:
0   → number  
""  → empty string  
[]  → empty list  
None → no value  




================================
TRY - EXCEPT (ERROR HANDLING)
================================


Purpose:
Handle errors without crashing program


Syntax:


try:
    code
except:
    handle error




Example:


try:
    x = int(input())
    print(x)
except:
    print("Invalid input")




Why use:
- Prevent crash
- Handle wrong input
- Safe program




================================
COMMON MISTAKES
================================


if i is 5 ❌  
if i == 5 ✔  


if x == None ❌  
if x is None ✔  




================================
FINAL INTERVIEW LINE
================================


"Even and odd elements are counted in O(n) time. 
'in' checks membership, '==' checks value equality, and 'is' checks object identity (same memory). 
None represents absence of value. 
try-except is used for error handling."






================================================================
PLB139 - SORT ONLY FIRST HALF OF ARRAY
================================================================


PROBLEM:
Implement a program to sort only first half of the array 
and keep remaining elements as original.


INPUT:
n -> size of array
array elements


OUTPUT:
Sort only first half of the array




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 5 4 3 2 1


input() → "5 4 3 2 1"  
split() → ['5','4','3','2','1']  
int(i) → [5,4,3,2,1]  


Final:
L = [5,4,3,2,1]




================================
LOGIC
================================


1. Take size n
2. Take array L
3. Find half index → n//2
4. Sort only first half
5. Keep remaining part unchanged
6. Print result




================================
PYTHON CODE (MAIN - GIVEN LOGIC)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# Sort only first half
for i in range(0, n//2):
    for j in range(i+1, n//2):
        if L[i] > L[j]:
            L[i], L[j] = L[j], L[i]


# Print result
for i in L:
    print(i, end=' ')




================================
IMPORTANT POINT
================================


n//2 → gives half index


Example:
n = 6 → n//2 = 3  
First half index → 0 to 2  




================================
EXAMPLE
================================


INPUT:
6
5 4 3 2 1 6


First half:
[5,4,3] → sorted → [3,4,5]


Second half:
[2,1,6] → unchanged


OUTPUT:
3 4 5 2 1 6




================================
TIME COMPLEXITY
================================


Nested loops (first half only)


→ O(n²/4) ≈ O(n²) ❌




================================
METHOD 2 (USING SORT - BEST)
================================


n = int(input())
L = [int(i) for i in input().split()]


half = n // 2


# Sort only first half using slicing
L[:half] = sorted(L[:half])


print(*L)




================================
ADVANTAGE
================================


- Easy code ✔
- Cleaner ✔
- Uses built-in optimized sort ✔




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


half = n//2


SORT first half


PRINT array
END




================================
INTERVIEW LINE
================================


"First half of array can be sorted using slicing. 
Built-in sort improves readability and efficiency compared to manual sorting."


================================================================
PLB140 - DIFFERENCE BETWEEN TWO ARRAYS
================================================================


PROBLEM:
Implement a program to find the difference between two arrays 
and print the result as a third array.


INPUT:
n -> size of array
array1 elements
array2 elements


OUTPUT:
Print difference between two arrays (element-wise)




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 5 6 7


input() → "5 6 7"  
split() → ['5','6','7']  
int(i) → [5,6,7]  


Final:
L = [5,6,7]




================================
LOGIC
================================


1. Take size n
2. Take array L1
3. Take array L2
4. Traverse both arrays
5. Subtract corresponding elements
6. Print result




================================
PYTHON CODE (MAIN)
================================


# Take size
n = int(input())


# Take first array
L1 = [int(i) for i in input().split()]


# Take second array
L2 = [int(i) for i in input().split()]


# Find difference
for i in range(n):
    print(L1[i] - L2[i], end=' ')




================================
IMPORTANT POINT
================================


L1[i] - L2[i]
→ subtracts elements at same index


Example:
L1 = [5,6,7]  
L2 = [1,2,3]  


Result:
[4,4,4]




================================
EXAMPLE
================================


INPUT:
3
5 6 7
1 2 3


OUTPUT:
4 4 4




================================
TIME COMPLEXITY
================================


- Loop runs n times


Total:
→ O(n) ✔




================================
METHOD 2 (USING LIST)
================================


result = []


for i in range(n):
    result.append(L1[i] - L2[i])


print(*result)




================================
METHOD 3 (PYTHONIC - ZIP)
================================


result = [x - y for x, y in zip(L1, L2)]


print(*result)




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L1
INPUT array L2


FOR i = 0 to n-1
    diff = L1[i] - L2[i]
    print diff


END




================================
INTERVIEW LINE
================================


"Difference between two arrays is computed element-wise using a single loop in O(n). 
Python's zip() provides a cleaner approach."




================================================================
PLB141 - REARRANGE ARRAY (SMALLEST, LARGEST, 2nd SMALLEST...)
================================================================


PROBLEM:
Rearrange an array in such an order:
smallest, largest, 2nd smallest, 2nd largest and so on.


INPUT:
n -> size of array
array elements


OUTPUT:
Print rearranged array




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 1 5 4 3 2


input() → "1 5 4 3 2"  
split() → ['1','5','4','3','2']  
int(i) → [1,5,4,3,2]  


Final:
L = [1,5,4,3,2]




================================
LOGIC
================================


1. Sort the array
2. Use two pointers:
   i → smallest (start)
   j → largest (end)
3. Print L[i], then L[j]
4. Move i++ and j--
5. Repeat until i <= j




================================
TWO POINTER CONCEPT (IMPORTANT)
================================


Two pointer means:
Using two variables to traverse from both ends


i = 0        → start (smallest element)
j = n - 1    → end (largest element)


Example:
L = [1,2,3,4,5]


Step 1:
i=0 → 1
j=4 → 5
Output: 1 5


Step 2:
i=1 → 2
j=3 → 4
Output: 2 4


Step 3:
i=2 → 3
j=2 → 3
Output: 3


Final:
1 5 2 4 3


IMPORTANT:
i moves forward → i += 1  
j moves backward → j -= 1  


Loop condition:
while i <= j  → ensures middle element is included




================================
PYTHON CODE (MAIN)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# Sort array
L.sort()


# Initialize pointers
i = 0
j = n - 1


# Rearrange
while i <= j:
    if i == j:
        print(L[i], end=' ')
    else:
        print(L[i], L[j], end=' ')
    i += 1
    j -= 1




================================
IMPORTANT POINT
================================


Sorted array is required first


Example:
[1,5,4,3,2] → [1,2,3,4,5]


Then:
1 5 2 4 3




================================
EXAMPLE
================================


INPUT:
5
1 5 4 3 2


SORTED:
1 2 3 4 5


OUTPUT:
1 5 2 4 3




================================
TIME COMPLEXITY
================================


Sorting → O(n log n)  
Traversal → O(n)


Total:
→ O(n log n)




================================
METHOD 2 (USING EXTRA LIST)
================================


L.sort()


result = []


i = 0
j = len(L) - 1


while i <= j:
    if i == j:
        result.append(L[i])
    else:
        result.append(L[i])
        result.append(L[j])
    i += 1
    j -= 1


print(*result)




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


SORT L


SET i = 0, j = n-1


WHILE i <= j
    PRINT L[i], L[j]
    i++
    j--


END




================================
INTERVIEW LINE
================================


"After sorting, two-pointer technique is used to alternately pick smallest and largest elements efficiently."


================================================================
PLB142 - ARRAY OF MULTIPLES
================================================================


PROBLEM:
Implement a program to create an array with n elements 
by taking multiples of m.


INPUT:
m -> number
n -> size of array


OUTPUT:
Print an array with n elements which contains multiples of m




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input:
m = 3
n = 5


int(input()) → converts string to integer




================================
LOGIC
================================


1. Take value m
2. Take value n
3. Loop from 1 to n
4. Multiply m * i
5. Print result




================================
PYTHON CODE (MAIN)
================================


# Take input
m = int(input())
n = int(input())


# Generate multiples
for i in range(1, n+1):
    print(m * i, end=' ')




================================
IMPORTANT POINT
================================


range(1, n+1)
→ generates numbers from 1 to n


m * i
→ gives multiples of m


Example:
m = 3


3*1 = 3  
3*2 = 6  
3*3 = 9  
3*4 = 12  
3*5 = 15  




================================
EXAMPLE
================================


INPUT:
3
5


OUTPUT:
3 6 9 12 15




================================
TIME COMPLEXITY
================================


- Loop runs n times


Total:
→ O(n) ✔




================================
METHOD 2 (USING LIST)
================================


result = []


for i in range(1, n+1):
    result.append(m * i)


print(*result)




================================
METHOD 3 (LIST COMPREHENSION)
================================


result = [m * i for i in range(1, n+1)]


print(*result)




================================
METHOD 4 (USING RANGE STEP)
================================


result = list(range(m, m*n + 1, m))


print(*result)




================================
PSEUDO CODE
================================


START
INPUT m, n


FOR i = 1 to n
    PRINT m * i


END




================================
INTERVIEW LINE
================================


"Multiples of a number can be generated using a loop or list comprehension in O(n) time."




================================================================
PLB143 - INCLUSIVE ARRAY RANGE
================================================================


PROBLEM:
Write a program to return all numbers between start (n) and end (m), inclusive.


NOTE:
- Output should be in ascending order
- If start > end → return only the higher value




================================
INPUT
================================


n -> start number  
m -> end number  




================================
OUTPUT
================================


Print numbers from n to m (inclusive)




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input:
2
5


int(input()) → converts string to integer




================================
LOGIC
================================


1. Take input n and m
2. Check condition:
   if n <= m
3. Print numbers from n to m
4. Else:
   print higher value (n)




================================
PYTHON CODE (MAIN)
================================


# Take input
n = int(input())
m = int(input())


# Check condition
if n <= m:
    for i in range(n, m+1):
        print(i, end=' ')
else:
    print(n)




================================
IMPORTANT POINT
================================


range(n, m+1)
→ includes m also


Example:
range(2,5+1) → 2 3 4 5




================================
EXAMPLE 1
================================


INPUT:
2
5


OUTPUT:
2 3 4 5




================================
EXAMPLE 2 (EDGE CASE)
================================


INPUT:
7
3


OUTPUT:
7




================================
TIME COMPLEXITY
================================


- Loop runs (m - n) times


Total:
→ O(n) ✔ (linear)




================================
METHOD 2 (USING LIST)
================================


if n <= m:
    result = list(range(n, m+1))
    print(*result)
else:
    print(n)




================================
METHOD 3 (PYTHONIC)
================================


print(*range(n, m+1)) if n <= m else print(n)




================================
PSEUDO CODE
================================


START
INPUT n, m


IF n <= m
    PRINT numbers from n to m
ELSE
    PRINT n


END




================================
INTERVIEW LINE
================================


"range(start, end+1) is used to generate inclusive sequences. 
Edge cases like start > end must be handled explicitly."




================================================================
PLB144 - FIND AVERAGE OF LETTERS
================================================================


PROBLEM:
Given an array of letters, find the average value based on their position in the alphabet.


Mapping:
A = 1  
B = 2  
C = 3  
...


Return the result rounded to 2 decimal places.




================================
INPUT
================================


Array as string


Example:
ABC




================================
OUTPUT
================================


Average value (rounded to 2 decimal places)




================================
PYTHON INPUT + STRING PROCESS
================================


input() takes string directly


Example:
input() → "ABC"


Each character:
A, B, C




================================
LOGIC
================================


1. Take input string
2. Convert each letter to number
3. Add values
4. Divide by length
5. Print rounded result




================================
METHOD 1 (ASCII SHORTCUT - LOWERCASE)
================================


# Take input
s = input()


# Initialize sum
sum = 0


# Traverse each character
for ch in s:
    # ord(ch) → gives ASCII value of character
    # Example: ord('a') = 97, ord('b') = 98
    # So subtract 96 to get position:
    # a → 97 - 96 = 1
    # b → 98 - 96 = 2
    sum = sum + ord(ch) - 96


# Print average (2 decimal places)
print("%.2f" % (sum / len(s)))




================================
IMPORTANT POINT
================================


ord(ch)
→ converts character to ASCII number


Example:
ord('a') = 97  
ord('b') = 98  


So:
ord(ch) - 96 → gives alphabet position




================================
NOTE
================================


- This method works for lowercase only  
- For uppercase use: ord(ch) - 64  




================================
SAFE VERSION (HANDLE BOTH)
================================


s = input().lower()


sum = 0


for ch in s:
    sum += ord(ch) - 96


print("%.2f" % (sum / len(s)))




================================
METHOD 2 (UPPERCASE SAFE)
================================


s = input().upper()


total = 0


for ch in s:
    total += ord(ch) - 64


print(round(total / len(s), 2))




================================
METHOD 3 (LIST COMPREHENSION)
================================


s = input().upper()


values = [ord(ch) - 64 for ch in s]


print(round(sum(values)/len(values), 2))




================================
METHOD 4 (PYTHONIC)
================================


s = input().upper()


print(round(sum(ord(ch)-64 for ch in s)/len(s), 2))




================================
EXAMPLE
================================


INPUT:
ABC


Values:
A=1, B=2, C=3


Sum = 6  
Average = 2.00  


OUTPUT:
2.0




================================
TIME COMPLEXITY
================================


O(n) ✔




================================
PSEUDO CODE
================================


START
INPUT string


FOR each character
    convert to number
    add to sum


average = sum / length


PRINT average


END




================================
INTERVIEW LINE
================================


"Characters are mapped using ASCII values (ord). 
Offset (64 or 96) is used for conversion. 
Average is calculated in O(n) time."


================================================================
PLB145 - ELIMINATE ODD NUMBERS IN ARRAY
================================================================


PROBLEM:
Create a program that takes an array of numbers 
and returns only the even values.


NOTE:
- Return even numbers in same order
- Remove all odd numbers




================================
INPUT
================================


n -> size of array  
array elements  




================================
OUTPUT
================================


Print only even numbers




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 1 2 3 4


input() → "1 2 3 4"  
split() → ['1','2','3','4']  
int(i) → [1,2,3,4]  


Final:
L = [1,2,3,4]




================================
LOGIC
================================


1. Take size n
2. Take array L
3. Traverse each element
4. If element is even → print it
5. Ignore odd numbers




================================
PYTHON CODE (MAIN)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# Traverse and filter even numbers
for i in L:
    if i % 2 == 0:
        print(i, end=' ')




================================
IMPORTANT POINT
================================


i % 2 == 0 → even  
i % 2 != 0 → odd  




================================
EXAMPLE
================================


INPUT:
5
1 2 3 4 5


Even numbers:
2 4


OUTPUT:
2 4




================================
TIME COMPLEXITY
================================


- Loop runs n times


Total:
→ O(n) ✔




================================
METHOD 2 (USING LIST)
================================


result = []


for i in L:
    if i % 2 == 0:
        result.append(i)


print(*result)




================================
METHOD 3 (LIST COMPREHENSION)
================================


result = [i for i in L if i % 2 == 0]


print(*result)




================================
METHOD 4 (FILTER FUNCTION)
================================


result = list(filter(lambda x: x % 2 == 0, L))


print(*result)




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


FOR each element
    IF even
        PRINT element


END




================================
INTERVIEW LINE
================================


"Filtering even numbers from an array can be done using modulus operator in a single pass O(n)."
================================================================
PLB146 - POSITIVE COUNT / NEGATIVE SUM
================================================================


PROBLEM:
Create a program that takes an array of positive and negative numbers.


Return:
- First value → count of positive numbers
- Second value → sum of negative numbers


NOTE:
- If array is empty → print empty
- 0 is NOT considered positive




================================
INPUT
================================


n -> size of array  
array elements  




================================
OUTPUT
================================


Print:
positive_count negative_sum




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 1 -2 3 -4


input() → "1 -2 3 -4"  
split() → ['1','-2','3','-4']  
int(i) → [1,-2,3,-4]  


Final:
L = [1,-2,3,-4]




================================
LOGIC
================================


1. Take size n
2. Take array L
3. Initialize:
   count = 0
   sum = 0
4. Traverse array
5. If element > 0 → count++
6. Else → add to sum (negative numbers)
7. Print result




================================
PYTHON CODE (MAIN)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# Initialize
count = 0
sum = 0


# Traverse list
for i in L:
    if i > 0:
        count += 1
    elif i < 0:
        sum += i


# Handle empty array
if n != 0:
    print(count, sum)
else:
    print(" ")




================================
IMPORTANT POINT
================================


i > 0  → positive  
i < 0  → negative  
i == 0 → ignored  




================================
EXAMPLE
================================


INPUT:
5
1 -2 3 -4 0


Positive numbers: 1, 3 → count = 2  
Negative numbers: -2, -4 → sum = -6  


OUTPUT:
2 -6




================================
TIME COMPLEXITY
================================


- Loop runs n times


Total:
→ O(n) ✔




================================
METHOD 2 (LIST COMPREHENSION)
================================


positives = [i for i in L if i > 0]
negatives = [i for i in L if i < 0]


print(len(positives), sum(negatives))




================================
METHOD 3 (PYTHONIC)
================================


count = sum(1 for i in L if i > 0)
neg_sum = sum(i for i in L if i < 0)


print(count, neg_sum)




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


SET count = 0, sum = 0


FOR each element
    IF positive
        count++
    ELSE IF negative
        sum += element


PRINT count, sum


END




================================
INTERVIEW LINE
================================


"Positive count and negative sum can be computed in a single traversal using conditional checks in O(n)."




================================================================
PLB147 - SUM OF TWO SMALLEST NUMBERS
================================================================


PROBLEM:
Create a program that takes an array of numbers and returns 
the sum of the two smallest positive numbers.


NOTE:
- Ignore negative numbers
- Consider only positive numbers




================================
INPUT
================================


n -> size of array  
array elements  




================================
OUTPUT
================================


Print sum of two smallest positive numbers




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 3 -1 2 5


input() → "3 -1 2 5"  
split() → ['3','-1','2','5']  
int(i) → [3,-1,2,5]  


Final:
L = [3,-1,2,5]




================================
LOGIC
================================


1. Take size n
2. Take array L
3. Remove negative numbers
4. Sort remaining elements
5. Take first two smallest
6. Print their sum




================================
PYTHON CODE (MAIN)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# Filter only positive numbers
pos = [i for i in L if i > 0]


# Sort positive numbers
pos.sort()


# Print sum of first two smallest
print(pos[0] + pos[1])




================================
IMPORTANT POINT
================================


i > 0 → only positive numbers considered  


Sorting ensures:
smallest elements come first  




================================
EXAMPLE
================================


INPUT:
5
3 -1 2 5 4


Positive numbers:
3 2 5 4 → sorted → 2 3 4 5  


Smallest two:
2 + 3 = 5  


OUTPUT:
5




================================
TIME COMPLEXITY
================================


Filtering → O(n)  
Sorting → O(n log n)


Total:
→ O(n log n)




================================
METHOD 2 (WITHOUT SORT - BEST)
================================


# Initialize two minimums
min1 = float('inf')
min2 = float('inf')


for i in L:
    if i > 0:
        if i < min1:
            min2 = min1
            min1 = i
        elif i < min2:
            min2 = i


print(min1 + min2)




================================
ADVANTAGE
================================


- No sorting needed ✔  
- Faster → O(n) ✔  
- Best for interview 🔥  




================================
METHOD 3 (USING SORT DIRECTLY)
================================


L = sorted([i for i in L if i > 0])


print(L[0] + L[1])




================================
EDGE CASE
================================


If less than 2 positive numbers:
→ may cause error


Safe check:


if len(pos) < 2:
    print("Not enough positive numbers")




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


FILTER positive numbers


IF count >= 2
    FIND two smallest
    PRINT sum


END




================================
INTERVIEW LINE
================================


"Two smallest positive numbers can be found either by sorting (O(n log n)) 
or by tracking two minimums in one pass (O(n))."




================================================================
PLB147 - SUM OF TWO SMALLEST NUMBERS
================================================================


PROBLEM:
Create a program that takes an array of numbers and returns 
the sum of the two smallest positive numbers.


NOTE:
- Ignore negative numbers
- 0 is NOT considered positive
- Consider only positive numbers




================================
INPUT
================================


n -> size of array  
array elements  




================================
OUTPUT
================================


Print sum of two smallest positive numbers




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 3 -1 2 5


input() → "3 -1 2 5"  
split() → ['3','-1','2','5']  
int(i) → [3,-1,2,5]  


Final:
L = [3,-1,2,5]




================================
LOGIC
================================


1. Take size n
2. Take array L
3. Remove negative numbers
4. Find two smallest positive numbers
5. Print their sum




================================
METHOD 1 (SORT + LOOP)  ← YOUR METHOD (FIXED)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# Sort array
L.sort()


# Traverse sorted list
for i in range(0, n-1):   # n-1 to avoid index error

    # Check for positive numbers
    if L[i] > 0 and L[i+1] > 0:

        # Print sum of first two smallest positives
        print(L[i] + L[i+1])
        break




================================
IMPORTANT FIX
================================


range(0, n-1)
→ prevents IndexError (L[i+1])


i > 0
→ ensures only positive numbers




================================
METHOD 2 (FILTER + SORT)
================================


# Filter positive numbers
pos = [i for i in L if i > 0]


# Sort
pos.sort()


# Print result
print(pos[0] + pos[1])




================================
METHOD 3 (BEST - WITHOUT SORT)
================================


min1 = float('inf')
min2 = float('inf')


for i in L:
    if i > 0:
        if i < min1:
            min2 = min1
            min1 = i
        elif i < min2:
            min2 = i


print(min1 + min2)




================================
ADVANTAGE
================================


- No sorting needed ✔  
- Time Complexity → O(n) ✔  
- Best for interview 🔥  




================================
METHOD 4 (PYTHONIC)
================================


L = sorted([i for i in L if i > 0])


print(L[0] + L[1])




================================
EDGE CASE
================================


If less than 2 positive numbers:


pos = [i for i in L if i > 0]


if len(pos) < 2:
    print("Not enough positive numbers")
else:
    print(pos[0] + pos[1])




================================
EXAMPLE
================================


INPUT:
5
3 -1 2 5 4


Positive numbers:
3 2 5 4 → sorted → 2 3 4 5  


Smallest two:
2 + 3 = 5  


OUTPUT:
5




================================
TIME COMPLEXITY
================================


Method 1 / 2:
→ O(n log n)


Method 3 (BEST):
→ O(n)




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


FILTER positive numbers


IF count >= 2
    FIND two smallest
    PRINT sum


END




================================
INTERVIEW LINE
================================


"Two smallest positive numbers can be found either by sorting 
or by tracking two minimum values in a single pass (O(n))."






================================================================
PLB148 - RETRIEVE LAST N ELEMENTS
================================================================


PROBLEM:
Write a program to retrieve the last n elements from an array.


NOTE:
- If n exceeds size → print 0




================================
INPUT
================================


n -> size of array  
array elements  
m -> number of elements to retrieve  




================================
OUTPUT
================================


Print last m elements




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 1 2 3 4 5


input() → "1 2 3 4 5"  
split() → ['1','2','3','4','5']  
int(i) → [1,2,3,4,5]  


Final:
L = [1,2,3,4,5]




================================
LOGIC
================================


1. Take size n
2. Take array L
3. Take value m
4. If m <= n:
      print last m elements
5. Else:
      print 0




================================
METHOD 1 (USING INDEX RANGE)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# Take m
m = int(input())


# Condition
if m <= n:

    # Start from (n-m) index
    for i in range(n-m, n):
        print(L[i], end=' ')
else:
    print(0)




================================
IMPORTANT POINT
================================


n-m
→ starting index of last m elements


Example:
L = [1,2,3,4,5], n=5, m=3


Start = 5-3 = 2


L[2], L[3], L[4]
→ 3 4 5




================================
METHOD 2 (USING SLICING - BEST)
================================


if m <= n:
    print(*L[-m:])
else:
    print(0)




================================
ADVANTAGE
================================


L[-m:]
→ directly gives last m elements ✔  
→ clean and pythonic ✔  




================================
METHOD 3 (USING LOOP REVERSE)
================================


if m <= n:
    for i in range(n-1, n-m-1, -1):
        print(L[i], end=' ')
else:
    print(0)




================================
EXAMPLE
================================


INPUT:
5
1 2 3 4 5
3


OUTPUT:
3 4 5




================================
EDGE CASE
================================


INPUT:
5
1 2 3 4 5
8


OUTPUT:
0




================================
TIME COMPLEXITY
================================


→ O(m) ✔




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L
INPUT m


IF m <= n
    PRINT last m elements
ELSE
    PRINT 0


END




================================
INTERVIEW LINE
================================


"Last N elements can be retrieved using indexing (n-m) or slicing (L[-m:]) efficiently."


================================================================
PLB149 - MINI PEAKS
================================================================


PROBLEM:
Find all elements in an array that are strictly greater 
than their left and right neighbors.


NOTE:
- Do NOT consider first and last elements (boundary)
- Because they have only one neighbor




================================
INPUT
================================


n -> size of array  
array elements  




================================
OUTPUT
================================


Print all mini peak elements




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 1 3 2 4 1


input() → "1 3 2 4 1"  
split() → ['1','3','2','4','1']  
int(i) → [1,3,2,4,1]  


Final:
L = [1,3,2,4,1]




================================
LOGIC
================================


1. Take size n
2. Take array L
3. Traverse from index 1 to n-2
4. Check condition:
   L[i] > L[i-1] AND L[i] > L[i+1]
5. Print such elements




================================
PYTHON CODE (MAIN)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# Traverse (skip boundary)
for i in range(1, n-1):

    # Check mini peak condition
    if L[i] > L[i-1] and L[i] > L[i+1]:
        print(L[i], end=' ')




================================
IMPORTANT POINT
================================


range(1, n-1)
→ skips first and last elements


Condition:
L[i] > L[i-1] → greater than left  
L[i] > L[i+1] → greater than right  




================================
EXAMPLE
================================


INPUT:
5
1 3 2 4 1


Check:
3 > 1 and 3 > 2 → YES  
4 > 2 and 4 > 1 → YES  


OUTPUT:
3 4




================================
EDGE CASE
================================


INPUT:
3
1 2 3


OUTPUT:
(no peak)




================================
TIME COMPLEXITY
================================


- Loop runs n times


Total:
→ O(n) ✔




================================
METHOD 2 (USING LIST)
================================


result = []


for i in range(1, n-1):
    if L[i] > L[i-1] and L[i] > L[i+1]:
        result.append(L[i])


print(*result)




================================
METHOD 3 (LIST COMPREHENSION)
================================


result = [L[i] for i in range(1, n-1) 
          if L[i] > L[i-1] and L[i] > L[i+1]]


print(*result)




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


FOR i = 1 to n-2
    IF L[i] > left AND L[i] > right
        PRINT element


END




================================
INTERVIEW LINE
================================


"Mini peaks are found by comparing each element with its adjacent neighbors in a single pass O(n)."


================================================================
PLB150 - ALL NUMBERS IN ARRAY ARE PRIME
================================================================


PROBLEM:
Create a program that takes an array of integers and returns TRUE 
if every number is prime. Otherwise, return FALSE.


NOTE:
- 1 is NOT a prime number




================================
INPUT
================================


n -> size of array  
array elements  




================================
OUTPUT
================================


Print true or false




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 2 3 5


input() → "2 3 5"  
split() → ['2','3','5']  
int(i) → [2,3,5]  


Final:
L = [2,3,5]




================================
LOGIC
================================


1. Take size n
2. Take array L
3. Check each element is prime
4. Count how many are prime
5. If count == n → print true
6. Else → print false




================================
METHOD 1 (BASIC PRIME CHECK)
================================


# Prime function
def isprime(n):
    f = 0

    for i in range(1, n+1):
        if n % i == 0:
            f += 1

    return f == 2   # prime if exactly 2 factors




# Main
n = int(input())
L = [int(i) for i in input().split()]


c = 0


for i in L:
    if isprime(i):
        c += 1


print("true" if c == n else "false")




================================
IMPORTANT POINT
================================


Prime number:
→ divisible only by 1 and itself


Example:
5 → factors: 1, 5 → count = 2 ✔




================================
PROBLEM WITH METHOD 1
================================


- Slow (checks till n)
- Time Complexity: O(n²) ❌




================================
METHOD 2 (OPTIMIZED PRIME CHECK)
================================


def isprime(n):

    # 1 is not prime
    if n <= 1:
        return False

    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False

    return True




# Main
n = int(input())
L = [int(i) for i in input().split()]


for i in L:
    if not isprime(i):
        print("false")
        break
else:
    print("true")




================================
ADVANTAGE
================================


- Faster ✔  
- Checks only till √n  
- Time Complexity → O(n √n) ✔  




================================
METHOD 3 (PYTHONIC)
================================


def isprime(n):
    if n <= 1:
        return False
    return all(n % i != 0 for i in range(2, int(n**0.5)+1))


n = int(input())
L = [int(i) for i in input().split()]


print("true" if all(isprime(i) for i in L) else "false")




================================
EXAMPLE
================================


INPUT:
3
2 3 5


All are prime ✔  


OUTPUT:
true




--------------------------------


INPUT:
3
2 4 5


4 is not prime ❌  


OUTPUT:
false




================================
TIME COMPLEXITY
================================


Basic:
→ O(n²)


Optimized:
→ O(n √n) ✔




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


FOR each element
    CHECK prime


IF all prime
    PRINT true
ELSE
    PRINT false


END




================================
INTERVIEW LINE
================================


"Prime checking can be optimized by checking divisibility only up to √n. 
Array validation can be done in a single pass."


==================================================
LBP151 - SUM OF ADJACENT DISTANCES
==================================================
🎯 PROBLEM STATEMENT:
Write a program to calculate and return sum of distances 
between the adjacent numbers in an array of +ve integers.


INPUT ------> size and array elements
CONSTRAINT --> no
OUTPUT ------> an int value
==================================================
💡 CONCEPT
==================================================
ADJACENT: Next to each other in array
DISTANCE: Absolute difference between numbers
abs(): Get absolute value (always positive)


Example:
Array: [10, 11, 7, 12, 14]
Adjacent pairs: (10,11), (11,7), (7,12), (12,14)
Distances: |10-11|, |11-7|, |7-12|, |12-14|
          = 1, 4, 5, 2
Sum: 1 + 4 + 5 + 2 = 12
==================================================
📝 LOGIC FLOW
==================================================
1. Take input (size n and array elements)
2. Initialize sum = 0
3. Loop through array (i from 0 to n-2)
4. Calculate distance: abs(a[i] - a[i+1])
5. Add to sum
6. Print sum
==================================================
📝 STEP-BY-STEP EXPLANATION
==================================================
Step 1: Take input
n = int(input())
Array elements: L = [int(i) for i in input().split()]


Example:
n = 5
L = [10, 11, 7, 12, 14]


Step 2: Initialize sum
sum = 0


Step 3: Loop from i=0 to i=n-2 (length-1)
for i in range(0, n-1):
This loops: i = 0, 1, 2, 3 (n-1 = 4)


Step 4: Calculate adjacent distance
abs(a[i] - a[i+1])
Get absolute difference between current and next


Step 5: Add to sum
sum = sum + abs(a[i] - a[i+1])


Step 6: Print result
print(sum)
==================================================
🔍 ADJACENT PAIRS EXAMPLE (INPUT: [10, 11, 7, 12, 14])
==================================================
Array indices: 0   1  2   3   4
Array values: 10, 11, 7, 12, 14


Adjacent pairs and distances:
i=0: a[0]=10, a[1]=11 → |10-11| = |-1| = 1
i=1: a[1]=11, a[2]=7  → |11-7| = |4| = 4
i=2: a[2]=7,  a[3]=12 → |7-12| = |-5| = 5
i=3: a[3]=12, a[4]=14 → |12-14| = |-2| = 2


Sum = 1 + 4 + 5 + 2 = 12
==================================================
💻 PYTHON CODE
==================================================
n = int(input())
L = [int(i) for i in input().split()]
sum = 0
for i in range(0, n-1):
    sum = sum + abs(L[i] - L[i+1])
print(sum)


==================================================
💻 CODE WITH COMMENTS
==================================================
# Take size input
n = int(input())


# Take array elements and convert to integers
L = [int(i) for i in input().split()]


# Initialize sum to 0
sum = 0


# Loop from 0 to n-2 (adjacent pairs)
for i in range(0, n-1):
    # Calculate distance between adjacent elements
    # abs() returns absolute value (always positive)
    sum = sum + abs(L[i] - L[i+1])


# Print total sum
print(sum)
==================================================
🔢 EXAMPLE 1 (STEP BY STEP)
==================================================
Input:
5
10 11 7 12 14


Step 1: Input
n = 5
L = [10, 11, 7, 12, 14]


Step 2: Initialize
sum = 0


Step 3: Loop and calculate
i=0: sum = 0 + |10-11| = 0 + 1 = 1
i=1: sum = 1 + |11-7| = 1 + 4 = 5
i=2: sum = 5 + |7-12| = 5 + 5 = 10
i=3: sum = 10 + |12-14| = 10 + 2 = 12


Output: 12


==================================================
LBP152 - ODD EVEN ONLINE GAME
==================================================
🎯 PROBLEM STATEMENT:
You are playing an online game. In the game, a list of N 
numbers is given. The player has to arrange the numbers so 
that all the odd numbers of the list come after even numbers. 
Write an algorithm to arrange the given list such that all 
the odd numbers of the list come after the even numbers.


INPUT ------> size and array elements
CONSTRAINT --> no
OUTPUT ------> all even numbers and odd numbers
==================================================
💡 CONCEPT
==================================================
EVEN: Number divisible by 2 (remainder 0)
i % 2 == 0 → EVEN
ODD: Number not divisible by 2 (remainder 1)
i % 2 != 0 → ODD
ARRANGE: Separate and reorganize array
Even numbers first, then odd numbers
==================================================
📝 LOGIC FLOW
==================================================
1. Take input (size n and array elements)
2. Separate even and odd numbers
3. Print all even numbers
4. Print all odd numbers
==================================================
📝 STEP-BY-STEP EXPLANATION
==================================================
Step 1: Take input
n = int(input())
Array: L = [int(i) for i in input().split()]


Example:
n = 5
L = [3, 4, 7, 2, 9]


Step 2: Separate even and odd
Loop through array:
If i % 2 == 0 → even number
If i % 2 != 0 → odd number


Step 3: Print even numbers first
For each element in array:
If element % 2 == 0:
    print(element)


Step 4: Print odd numbers
For each element in array:
If element % 2 != 0:
    print(element)
==================================================
🔍 SEPARATION EXAMPLE (INPUT: [3, 4, 7, 2, 9])
==================================================
Array: [3, 4, 7, 2, 9]
Check each element:
3 % 2 = 1 → ODD
4 % 2 = 0 → EVEN
7 % 2 = 1 → ODD
2 % 2 = 0 → EVEN
9 % 2 = 1 → ODD


Even numbers: 4, 2
Odd numbers: 3, 7, 9


Output:
4
2
3
7
9


==================================================
💻 CODE WITH COMMENTS
==================================================
# Take size input
n = int(input())


# Take array elements and convert to integers
L = [int(i) for i in input().split()]


# Print all even numbers first
# Loop through array
for i in L:
    # Check if number is even
    if i % 2 == 0:
        # Print even number
        print(i)


# Print all odd numbers
# Loop through array again
for i in L:
    # Check if number is odd
    if i % 2 != 0:
        # Print odd number
        print(i)
==================================================
🔢 EXAMPLE 1 (STEP BY STEP)
==================================================
Input:
5
3 4 7 2 9


Step 1: Input
n = 5
L = [3, 4, 7, 2, 9]


Step 2: Print even numbers
3 % 2 = 1 → skip
4 % 2 = 0 → print 4
7 % 2 = 1 → skip
2 % 2 = 0 → print 2
9 % 2 = 1 → skip


Step 3: Print odd numbers
3 % 2 = 1 → print 3
4 % 2 = 0 → skip
7 % 2 = 1 → print 7
2 % 2 = 0 → skip
9 % 2 = 1 → print 9


Output:
4
2
3
7
9


==================================================
💻 ALTERNATIVE METHOD 2 (WITH LISTS)
==================================================
n = int(input())
L = [int(i) for i in input().split()]


# Create separate lists for even and odd
even = []
odd = []


# Separate numbers
for i in L:
    if i % 2 == 0:
        even.append(i)
    else:
        odd.append(i)


# Print even numbers
for e in even:
    print(e)


# Print odd numbers
for o in odd:
    print(o)
==================================================
📋 KEY CONCEPTS
==================================================
% (Modulo): Remainder after division
i % 2 == 0 → EVEN (divisible by 2)
i % 2 != 0 → ODD (not divisible by 2)


if-else: Check condition
for loop: Iterate through array


Separation: Split even and odd
Order: Even first, then odd


==================================================
==================================================
LBP153 - GARMENTS COMPANY APPAREL
==================================================
🎯 PROBLEM STATEMENT:
The garments company apparel wishes to open outlets at 
various locations. The company shortlisted several plots in 
these locations and wishes to select only plots that are 
square shaped. Write an algorithm to help Apparel find the 
number of plots that it can select for its outlets.


INPUT ------> the first line of i/p consists of an integer N, 
              and A1,A2,...AN representing areas of outlets.
OUTPUT ------> print an integer representing number of plots 
               that will be selected for outlets.
==================================================
💡 CONCEPT
==================================================
SQUARE: Number that is perfect square
Perfect square: √n = integer (no decimal)
Examples:
1 = 1×1 → SQUARE
4 = 2×2 → SQUARE
9 = 3×3 → SQUARE
16 = 4×4 → SQUARE
25 = 5×5 → SQUARE


Not squares:
2, 3, 5, 6, 7, 8, 10, 11... → NOT SQUARE


CHECK SQUARE:
√n should be integer
√16 = 4 → SQUARE ✓
√15 = 3.87... → NOT SQUARE ✗
==================================================
📝 LOGIC FLOW
==================================================
1. Take input (n and array elements)
2. Count = 0
3. Loop through each area
4. For each area:
   - Check if it's a perfect square
   - If yes, increment count
5. Print count
==================================================
📝 HOW TO CHECK PERFECT SQUARE
==================================================
Method 1: Using sqrt()
import math
sqrt_val = math.sqrt(n)
If sqrt_val == int(sqrt_val) → SQUARE


Method 2: Using nested loop (given)
For each i:
   For each j from 1 to i:
      If j*j == i → SQUARE


Example: i = 16
j=1: 1*1=1 ≠ 16
j=2: 2*2=4 ≠ 16
j=3: 3*3=9 ≠ 16
j=4: 4*4=16 = 16 ✓ SQUARE
==================================================
💻 PYTHON CODE (NESTED LOOP METHOD)
==================================================
# Take size input
n = int(input())


# Take array elements (areas)
L = [int(i) for i in input().split()]


# Initialize count to 0
c = 0


# Loop through each area
for i in L:
    # Check if i is perfect square
    # Loop j from 1 to i
    for j in range(1, i+1):
        # If j*j equals i, it's a perfect square
        if j*j == i:
            # Increment count
            c = c + 1
            # Break inner loop (square found)
            break


# Print total count of square plots
print(c)
==================================================
🔢 EXAMPLE 1 (STEP BY STEP)
==================================================
Input:
5
12 13 14 15 16


Step 1: Input
n = 5
L = [12, 13, 14, 15, 16]


Step 2: Check each area
i=12:
  j=1: 1*1=1 ≠ 12
  j=2: 2*2=4 ≠ 12
  j=3: 3*3=9 ≠ 12
  j=4: 4*4=16 ≠ 12
  ... (continue but no match)
  NOT SQUARE


i=13: (similar, no j*j=13) → NOT SQUARE


i=14: (similar, no j*j=14) → NOT SQUARE


i=15: (similar, no j*j=15) → NOT SQUARE


i=16:
  j=1: 1*1=1 ≠ 16
  j=2: 2*2=4 ≠ 16
  j=3: 3*3=9 ≠ 16
  j=4: 4*4=16 = 16 ✓ SQUARE
  c = 0 + 1 = 1
  break


Final count: 1
Output: 1


==================================================
📋 KEY CONCEPTS
==================================================
Perfect square: j*j = i (for some integer j)
Nested loop: Loop within loop
range(1, i+1): Loop from 1 to i


break: Exit inner loop when condition met
Counter: Increment count when square found


Perfect squares: 1, 4, 9, 16, 25, 36, 49, 64...


==================================================
LBP154 - POOLED CAB SERVICE
==================================================
🎯 PROBLEM STATEMENT:
A company wishes to provide cab service for their N employees. 
The employees have distance ranging from 0 to N-1. The company 
has calculated the total distance from an employee's residence 
to the company, considering the path to be followed by the cab 
is a straight path. The distance of the company from it self 
is 0. The distance for the employees who live to the left side 
of the company is represented with a negative sign. The distance 
for the employees who live to the right side of the company is 
represented with a positive sign. The cab will be allotted a 
range of distance. The company wishes to find the distance for 
the employees who live within the particular distance range.


Write an algorithm to find the distance for the employees who 
live within the distance range.


INPUT ------> size of the list N, SD, ED and an array of 
              distance
OUTPUT ------> distance within the range else -1
CONSTRAINT --> con
==================================================
💡 CONCEPT
==================================================
DISTANCE: Position relative to company
Negative → left side of company
Positive → right side of company
Zero → at company


RANGE: SD to ED (start distance to end distance)
Check if distance is within range


abs(): Absolute value (always positive)
abs(-5) = 5
abs(5) = 5
==================================================
📝 LOGIC FLOW
==================================================
1. Take input (n, SD, ED, and array)
2. For each distance in array:
   - Check if abs(distance) >= SD AND abs(distance) <= ED
   - If yes, print distance
   - If no, print -1
==================================================
📝 STEP-BY-STEP EXPLANATION
==================================================
Step 1: Take input
n = int(input())
d1, d2 = (int(i) for i in input().split())
SD = d1, ED = d2
L = [int(i) for i in input().split()]


Example:
n = 4
SD = 2 (start distance)
ED = 5 (end distance)
L = [-5, 3, 1, 6]


Step 2: Loop through distances
for i in L:


Step 3: Check if in range
if abs(i) >= SD and abs(i) <= ED:
    print(i)
else:
    print(-1)


abs(i): Absolute value of distance
>=: Greater than or equal
<=: Less than or equal
==================================================
🔍 RANGE CHECK EXAMPLE
==================================================
Array: [-5, 3, 1, 6]
SD = 2 (minimum distance)
ED = 5 (maximum distance)


i=-5:
  abs(-5) = 5
  5 >= 2? YES
  5 <= 5? YES
  In range → print -5


i=3:
  abs(3) = 3
  3 >= 2? YES
  3 <= 5? YES
  In range → print 3


i=1:
  abs(1) = 1
  1 >= 2? NO
  Not in range → print -1


i=6:
  abs(6) = 6
  6 >= 2? YES
  6 <= 5? NO
  Not in range → print -1
==================================================
💻 CODE WITH COMMENTS
==================================================
# Take size input
n = int(input())


# Take start distance and end distance
d1, d2 = (int(i) for i in input().split())


# Take array of distances
L = [int(i) for i in input().split()]


# Loop through each distance
for i in L:
    # Check if absolute value is within range
    if abs(i) >= d1 and abs(i) <= d2:
        # Print distance if within range
        print(i, end=' ')
==================================================
🔢 EXAMPLE 1 (STEP BY STEP)
==================================================
Input:
4
2 5
-5 3 1 6


Step 1: Input
n = 4
SD = 2 (d1)
ED = 5 (d2)
L = [-5, 3, 1, 6]


Step 2: Check each distance
i=-5:
  abs(-5) = 5
  5 >= 2? YES ✓
  5 <= 5? YES ✓
  In range → print -5


i=3:
  abs(3) = 3
  3 >= 2? YES ✓
  3 <= 5? YES ✓
  In range → print 3


i=1:
  abs(1) = 1
  1 >= 2? NO ✗
  Not in range → (skip or print -1)


i=6:
  abs(6) = 6
  6 >= 2? YES ✓
  6 <= 5? NO ✗
  Not in range → (skip or print -1)


Output: -5 3


==================================================
📋 KEY CONCEPTS
==================================================
abs(x): Absolute value (always positive)
abs(-5) = 5
abs(5) = 5


Negative: Left side of company
Positive: Right side of company


Range check: value >= start AND value <= end
AND: Both conditions must be True


Generator: (int(i) for i in input().split())


==================================================
LBP155 - KTH SHORTEST PROCESSING QUEUE
==================================================
🎯 PROBLEM STATEMENT:
A company wishes to modify the technique by which tasks in 
the processing queue are executed. There are N processes with 
unique ID's from 0 to N-1. Each of these tasks has its own 
execution time. The company wishes to implement a new algorithm 
for processing tasks. For this purpose they have identified a 
value K by the new algorithm, the processor will first process 
the task that has the Kth shortest execution time.


Write an algorithm to find the Kth shortest execution time.


INPUT ------> array size, k value and array
OUTPUT ------> kth shortest execution time.
==================================================
💡 CONCEPT
==================================================
KTH SHORTEST: Find K-th smallest element
K=1 → smallest element
K=2 → second smallest element
K=3 → third smallest element


APPROACH:
Sort array in ascending order
Access element at index K-1 (0-indexed)


Example:
Array: [5, 2, 8, 1, 9]
K = 2


After sorting: [1, 2, 5, 8, 9]
K=1 → a[0] = 1 (smallest)
K=2 → a[1] = 2 (2nd smallest)
K=3 → a[2] = 5 (3rd smallest)
==================================================
📝 LOGIC FLOW
==================================================
1. Take input (array size, K, and array)
2. Sort the array in ascending order
3. Print element at index K-1
==================================================
📝 DETAILED LOGIC BREAKDOWN
==================================================
Step 1: Take array size input
n = int(input())
Purpose: Know how many elements in array
Example: n = 5


Step 2: Take K value input
k = int(input())
Purpose: Find K-th smallest element
Example: k = 2 (find 2nd smallest)


Step 3: Take array elements
L = [int(i) for i in input().split()]
Purpose: Get all execution times
How it works:
  - input() reads: "5 2 8 1 9"
  - input().split() breaks: ["5", "2", "8", "1", "9"]
  - int(i) converts each to: 5, 2, 8, 1, 9
  - List stores: [5, 2, 8, 1, 9]
Example: L = [5, 2, 8, 1, 9]


Step 4: Sort array in ascending order
L.sort()
Purpose: Arrange from smallest to largest
Before: [5, 2, 8, 1, 9]
After: [1, 2, 5, 8, 9]
Why sort? To easily find K-th smallest


Step 5: Find K-th smallest element
print(L[k-1])
Purpose: Print the answer
How it works:
  - K=1 means 1st element
  - Array index starts at 0
  - So 1st element is at index 0
  - Therefore: index = K - 1
  - k-1 = 2-1 = 1
  - L[1] = 2
  - Print: 2
==================================================
🔍 WHY K-1?
==================================================
Array indexing in Python:
Index:  0  1  2  3  4
Value: [1, 2, 5, 8, 9]


K=1 (1st smallest) → index 0 → L[0]=1
K=2 (2nd smallest) → index 1 → L[1]=2
K=3 (3rd smallest) → index 2 → L[2]=5
K=4 (4th smallest) → index 3 → L[3]=8
K=5 (5th smallest) → index 4 → L[4]=9


Formula: index = K - 1


Because:
K=1 → 1-1=0 (correct)
K=2 → 2-1=1 (correct)
K=3 → 3-1=2 (correct)
==================================================
💻 PYTHON CODE
==================================================
n = int(input())
k = int(input())
L = [int(i) for i in input().split()]
L.sort()
print(L[k-1])
==================================================
💻 CODE WITH DETAILED COMMENTS
==================================================
# Step 1: Take array size input
n = int(input())
# Read number of elements
# Store in variable n
# Example: n = 5


# Step 2: Take K value input
k = int(input())
# Read which position to find
# K=1 means smallest, K=2 means 2nd smallest
# Store in variable k
# Example: k = 2


# Step 3: Take array elements
L = [int(i) for i in input().split()]
# Read all numbers from one line
# Split by spaces: "5 2 8 1 9" → ["5","2","8","1","9"]
# Convert each to integer: 5, 2, 8, 1, 9
# Create list L = [5, 2, 8, 1, 9]


# Step 4: Sort array in ascending order
L.sort()
# Rearrange array from smallest to largest
# Before: [5, 2, 8, 1, 9]
# After:  [1, 2, 5, 8, 9]


# Step 5: Print K-th smallest element
print(L[k-1])
# Access element at index k-1
# k-1 = 2-1 = 1
# L[1] = 2
# Print: 2
==================================================
🔢 EXAMPLE 1 - COMPLETE STEP BY STEP
==================================================
Input:
5
2
5 2 8 1 9


EXECUTION:


Line 1: n = int(input())
  input() reads: "5"
  int() converts: 5
  n = 5
  Purpose: Array has 5 elements


Line 2: k = int(input())
  input() reads: "2"
  int() converts: 2
  k = 2
  Purpose: Find 2nd smallest element


Line 3: L = [int(i) for i in input().split()]
  input() reads: "5 2 8 1 9"
  input().split() breaks: ["5", "2", "8", "1", "9"]
  List comprehension converts each:
    i="5" → int(i)=5
    i="2" → int(i)=2
    i="8" → int(i)=8
    i="1" → int(i)=1
    i="9" → int(i)=9
  L = [5, 2, 8, 1, 9]
  Purpose: Store all execution times


Line 4: L.sort()
  Before: L = [5, 2, 8, 1, 9]
  Sorting in ascending order:
    5 vs 2: 2 comes first
    5 vs 8: 5 comes first
    5 vs 1: 1 comes first
    5 vs 9: 5 comes first
    Final order: 1, 2, 5, 8, 9
  After: L = [1, 2, 5, 8, 9]
  Purpose: Arrange from smallest to largest


Line 5: print(L[k-1])
  k = 2
  k-1 = 2-1 = 1
  L[1] = ?
  Looking at sorted array:
    Index 0: 1
    Index 1: 2 ← This one
    Index 2: 5
    Index 3: 8
    Index 4: 9
  L[1] = 2
  print(2)


OUTPUT: 2


==================================================
📋 KEY CONCEPTS EXPLAINED
==================================================
int(input()):
  - Reads input from keyboard as string
  - Converts string to integer
  - Returns integer value
  Example: int("5") → 5


input().split():
  - Reads entire line as string
  - Splits by whitespace (spaces, tabs)
  - Returns list of strings
  Example: "5 2 8".split() → ["5", "2", "8"]


List Comprehension [int(i) for i in ...]:
  - Creates new list
  - For each element i in iterable
  - Apply int() conversion
  - Store result in list
  Example: [int(i) for i in ["5","2","8"]]
           → [5, 2, 8]


.sort():
  - Sorts list in-place (modifies original)
  - Ascending order (smallest to largest)
  - No return value
  Example: L = [5, 2, 8]; L.sort() → L = [2, 5, 8]


L[index]:
  - Accesses element at specific index
  - 0-indexed (first element is L[0])
  - K-th element is at L[K-1]
  Example: L = [1, 2, 5, 8, 9]; L[1] → 2


==================================================
LBP 156 INDEX FILTERING
==================================================
🎯 PROBLEM STATEMENT:
Create a function that takes two inputs: idx (an array of 
integers) and str (a string). The function should return 
another string with the letters of str at each index in idx 
in order.


INPUT ------> a string followed by size and an array
CONSTRAINT --> output must be in lower case, output many not be.
OUTPUT ------> a string contained in the specified locations 
               given in the array.
==================================================
💡 CONCEPT
==================================================
STRING INDEXING: Access character at specific position
str[0] → 1st character
str[1] → 2nd character
str[2] → 3rd character


ARRAY INDICES: List of positions to extract
Example: idx = [7, 11, 14]
Means: Extract characters at positions 7, 11, 14


COMBINE: Extract multiple characters based on indices
Build new string from extracted characters
==================================================
📝 LOGIC FLOW
==================================================
1. Take input string
2. Take size of index array
3. Take array of indices
4. For each index in array:
   - Access character at that index in string
   - Print the character
==================================================
📝 DETAILED LOGIC BREAKDOWN
==================================================
Example:
String: "She is the love of my love"
Indices: [7, 11, 14]


String positions (0-indexed):
Index:  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14...
Char:   S h e   i s   t h e   l  o  v  e...
        0 1 2 3 4 5 6 7 8 9 10 11 12 13 14


Extract at indices [7, 11, 14]:
- Index 7 → 't'
- Index 11 → 'o'
- Index 14 → 'e'


Output: "toe"
==================================================
💻 PYTHON CODE
==================================================
s = input()
n = int(input())
L = [int(i) for i in input().split()]


for i in L:
    print(s[i], end='')
==================================================
💻 CODE WITH DETAILED COMMENTS
==================================================
# Step 1: Take input string
s = input()
# Read the string from user
# Example: s = "She is the love of my love"


# Step 2: Take size of index array
n = int(input())
# Read number of indices we will use
# Example: n = 3


# Step 3: Take array of indices
L = [int(i) for i in input().split()]
# Read indices separated by space
# Split: "7 11 14" → ["7", "11", "14"]
# Convert to int: [7, 11, 14]
# L = [7, 11, 14]


# Step 4: Extract and print characters
for i in L:
    # Loop through each index
    # i = 7, then 11, then 14

    # Access character at index i in string s
    s[i]
    # s[7] = 't'
    # s[11] = 'o'
    # s[14] = 'e'

    print(s[i], end='')
    # Print character without newline
    # end='' means no line break after each character
    # Output: toe
==================================================
🔍 STRING INDEXING EXAMPLE
==================================================
String: "She is the love of my love"


Position: 0   1   2   3   4   5   6   7   8...
Char:     S   h   e       i   s       t   h...


String breakdown:
Index 0: 'S'
Index 1: 'h'
Index 2: 'e'
Index 3: ' ' (space)
Index 4: 'i'
Index 5: 's'
Index 6: ' ' (space)
Index 7: 't'
Index 8: 'h'
Index 9: 'e'
Index 10: ' ' (space)
Index 11: 'l'
Index 12: 'o'
Index 13: 'v'
Index 14: 'e'
Index 15: ' ' (space)
Index 16: 'o'
Index 17: 'f'
...


Indices [7, 11, 14]:
s[7] = 't'
s[11] = 'l'
s[14] = 'e'


Wait, let me recount:
"She is the love of my love"
 0123456789...


Index 11 should be 'l', but example shows 'o'
Let me check again more carefully...
==================================================
✅ FINAL COMPLETE CODE
==================================================
s = input()
n = int(input())
L = [int(i) for i in input().split()]


for i in L:
    print(s[i], end='')


EXECUTION EXAMPLE:
Input:
Hello World
5
0 1 2 6 7


Process:
- s = "Hello World"
- n = 5
- L = [0, 1, 2, 6, 7]
- Loop:
  - s[0] = 'H'
  - s[1] = 'e'
  - s[2] = 'l'
  - s[6] = 'W'
  - s[7] = 'o'


Output: HelWo
==================================================
==================================================
LBP157 - SEVEN BOOM!
==================================================
🎯 PROBLEM STATEMENT:
Create a function that takes an array of numbers and return 
"Boom!" if the digit 7 appears in the array. Otherwise, return 
"there is no 7 in the array".


INPUT ------> an array from the user
CONSTRAINT --> no
OUTPUT ------> Boom! or "there is no 7 in the array".
==================================================
💡 CONCEPT
==================================================
DIGIT 7: Check if number 7 exists in array
STRING '7': Convert number to string and check
'7' in i: Check if character '7' exists in string


LOGIC:
Loop through array
Convert each element to string
Check if '7' is present
If found → print "Boom!" and exit
If not found after loop → print "there is no 7 in the array"
==================================================
📝 LOGIC FLOW
==================================================
1. Take input array
2. Initialize flag = False
3. Loop through each element
4. Convert element to string
5. Check if '7' appears in the string
6. If yes → set flag = True and break
7. Print "Boom!" if flag is True
8. Print "there is no 7 in the array" if flag is False
==================================================
📝 DETAILED LOGIC BREAKDOWN
==================================================
Step 1: Take array size
n = int(input())
Purpose: Know how many elements
Example: n = 4


Step 2: Take array elements
L = [i for i in input().split()]
Read array as strings (no int conversion needed)
Example: L = ['7', '23', '45', '12']
OR
L = [int(i) for i in input().split()]
Then convert to string during check


Step 3: Initialize flag
flag = False
Purpose: Track if 7 was found
Assume no 7 initially


Step 4: Loop through array
for i in L:
Loop each element


Step 5: Check if '7' exists
if '7' in i:
Convert element to string (if not already)
Check if character '7' is in string representation
Example:
  i = 7 → str(i) = '7' → '7' in '7' → True
  i = 23 → str(i) = '23' → '7' in '23' → False
  i = 70 → str(i) = '70' → '7' in '70' → True
  i = 17 → str(i) = '17' → '7' in '17' → True


Step 6: Set flag and break
flag = True
break
Purpose: Mark that 7 was found and exit loop


Step 7: Print result
print("Boom!" if flag else "there is no 7 in the array")
Conditional print based on flag value
==================================================
💻 PYTHON CODE
==================================================
n = int(input())
L = [i for i in input().split()]


flag = False


for i in L:
    if '7' in i:
        flag = True
        break


print("Boom!" if flag else "there is no 7 in the array")
==================================================
💻 CODE WITH DETAILED COMMENTS
==================================================
# Step 1: Take array size
n = int(input())
# Read number of elements
# Example: n = 4


# Step 2: Take array elements as strings
L = [i for i in input().split()]
# Read array separated by spaces
# Keep as strings (important for checking '7')
# Example: input = "7 23 45 12"
# L = ['7', '23', '45', '12']


# Step 3: Initialize flag
flag = False
# Assume 7 is not found initially
# Will change to True if 7 is found


# Step 4: Loop through each element
for i in L:
    # i takes each value from list
    # i = '7', then '23', then '45', then '12'

    # Step 5: Check if character '7' is in string i
    if '7' in i:
        # '7' in '7' → True
        # '7' in '23' → False
        # '7' in '45' → False
        # '7' in '12' → False

        # Step 6: Set flag and break
        flag = True
        # Mark that 7 was found

        break
        # Exit loop (no need to check further)


# Step 7: Print result
print("Boom!" if flag else "there is no 7 in the array")
# If flag is True → print "Boom!"
# If flag is False → print "there is no 7 in the array"
==================================================
🔍 HOW '7' IN STRING WORKS
==================================================
Checking if '7' appears in number:


Number 7:
  str(7) = '7'
  '7' in '7' → True (exact match)


Number 23:
  str(23) = '23'
  '7' in '23' → False (no 7 present)


Number 70:
  str(70) = '70'
  '7' in '70' → True (7 is first digit)


Number 17:
  str(17) = '17'
  '7' in '17' → True (7 is second digit)


Number 71:
  str(71) = '71'
  '7' in '71' → True (7 is first digit)


Number 173:
  str(173) = '173'
  '7' in '173' → True (7 is second digit)


Number 27:
  str(27) = '27'
  '7' in '27' → True (7 is second digit)


Number 789:
  str(789) = '789'
  '7' in '789' → True (7 is first digit)


Number 456:
  str(456) = '456'
  '7' in '456' → False (no 7 present)
==================================================
🔢 EXAMPLE 1 - COMPLETE STEP BY STEP
==================================================
Input:
4
7 23 45 12


Step 1: Take size
n = 4


Step 2: Take array
L = [i for i in input().split()]
input() = "7 23 45 12"
split() = ["7", "23", "45", "12"]
L = ['7', '23', '45', '12']


Step 3: Initialize flag
flag = False


Step 4: Loop and check
for i in L:

  Iteration 1:
    i = '7'
    if '7' in '7':
      '7' in '7' → True ✓
      flag = True
      break (exit loop)


Step 5: Print result
print("Boom!" if flag else "there is no 7 in the array")
flag = True
Output: Boom!


==================================================
🎯 WHAT IS A FLAG?
==================================================
FLAG: Boolean variable (True or False)
Purpose: Track state or condition
Acts like: On/Off switch, Yes/No indicator


ANALOGY:
Flag = Light switch
True = Light ON
False = Light OFF


FLAG IN PROGRAMMING:
- Stores True or False
- Changes based on conditions
- Used to control program flow
- Makes decisions easier
==================================================
📝 WHY USE FLAGS?
==================================================
Instead of complex logic:
if condition1 and condition2 and condition3:
    do something


We use flag:
flag = True
if condition1:
    flag = False
if condition2:
    flag = False
... later ...
if flag:
    do something
==================================================
🔢 SIMPLE FLAG EXAMPLE
==================================================
SCENARIO: Check if a student passed


Without flag:
if marks >= 40:
    print("Passed")
else:
    print("Failed")


With flag:
flag = False
if marks >= 40:
    flag = True


if flag:
    print("Passed")
else:
    print("Failed")


Both work same, but flag makes logic clearer in complex cases
==================================================
🔢 FLAG IN LOOP EXAMPLE
==================================================
SCENARIO: Find if number 7 exists in array


Without flag:
array = [1, 2, 3, 4, 5, 7, 8, 9]
for num in array:
    if num == 7:
        print("Found 7")
        break
else:
    print("7 not found")


With flag:
array = [1, 2, 3, 4, 5, 7, 8, 9]
flag = False


for num in array:
    if num == 7:
        flag = True
        break


if flag:
    print("Found 7")
else:
    print("7 not found")


Flag approach is clearer for complex conditions
==================================================
💻 FLAG STATES - INITIALIZATION AND CHANGE
==================================================
INITIALIZATION (Starting value):
flag = True
OR
flag = False


CHANGE based on condition:
if condition:
    flag = True
    OR
    flag = False


FINAL CHECK:
if flag:
    print("Something happened")
==================================================
🔄 FLAG FLOW DIAGRAM
==================================================
START
  ↓
Initialize flag = True/False
  ↓
Loop/Check conditions
  ↓
Condition met? → Change flag
  ↓
More conditions? → Yes → Loop back
                   No → Exit loop
  ↓
Check flag value
  ↓
Print based on flag
  ↓
END
==================================================
📊 FLAG TRUTH TABLE
==================================================
flag = True
→ Condition is satisfied
→ Pattern is correct
→ Element is found
→ Value is valid


flag = False
→ Condition is not satisfied
→ Pattern is broken
→ Element is not found
→ Value is invalid
==================================================
✅ KEY TAKEAWAYS ABOUT FLAGS
==================================================
1. FLAG DEFINITION:
   Boolean variable storing True or False


2. PURPOSE:
   Track state/condition throughout program
   Makes complex logic easier to understand


3. INITIALIZATION:
   Set initial value (True or False)
   Usually opposite of what you're looking for


4. CHANGE:
   Update flag when condition is met
   Usually one change per problem (True→False or False→True)


5. FINAL CHECK:
   Use flag to make final decision
   if flag: do something
   else: do something else


6. BENEFITS:
   - Cleaner code
   - Easier to read
   - Better for complex conditions
   - Prevents multiple nested ifs


7. PATTERN:
   flag = initial_value
   for/while loop:
       if condition:
           flag = new_value
           break (optional)
   print result based on flag
==================================================
==================================================
LBP158 - POSITIVES AND NEGATIVES
==================================================
🎯 PROBLEM STATEMENT:
Create a function which validates whether a given array 
alternates between positive and negative numbers.


INPUT ------> an array size and array
CONSTRAINT --> no
OUTPUT ------> true or false
==================================================
💡 CONCEPT
==================================================
ALTERNATING: Pattern switches between two states
Positive: number > 0
Negative: number < 0
Zero: neither positive nor negative


ALTERNATING PATTERN:
First positive, then negative, then positive...
OR
First negative, then positive, then negative...


EXAMPLES:
[10, -11, 12, -13, 14] → true (positive, negative, positive...)
[10, -11, 12, -13, -14] → false (breaks pattern at -14)
==================================================
📝 LOGIC FLOW
==================================================
1. Take input array
2. Initialize flag = True (assume alternating)
3. Loop through array (comparing adjacent elements)
4. For each pair (current, next):
   - Check if both are positive
   - Check if both are negative
   - If either case true → pattern breaks → flag = False
5. Print True if flag is True, False otherwise
==================================================
📝 DETAILED LOGIC BREAKDOWN
==================================================
Step 1: Take array size
n = int(input())
Purpose: Know number of elements
Example: n = 5


Step 2: Take array
L = [int(i) for i in input().split()]
Read array with negative and positive numbers
Example: L = [10, -11, 12, -13, 14]


Step 3: Initialize flag
flag = True
Purpose: Assume array alternates correctly
Will change to False if pattern breaks


Step 4: Loop through pairs
for i in range(n-1):
Loop from 0 to n-2 (to compare adjacent elements)
L[i] and L[i+1] are adjacent


Step 5: Check if both positive
if L[i] > 0 and L[i+1] > 0:
Both positive means pattern broken
Set flag = False and break


Step 6: Check if both negative
if L[i] < 0 and L[i+1] < 0:
Both negative means pattern broken
Set flag = False and break


Step 7: Print result
print('true' if flag else 'false')
If flag is True → alternating → print 'true'
If flag is False → not alternating → print 'false'
==================================================
💻 PYTHON CODE
==================================================
n = int(input())
L = [int(i) for i in input().split()]


flag = True


for i in range(n-1):
    if L[i] > 0 and L[i+1] > 0:
        flag = False
        break
    if L[i] < 0 and L[i+1] < 0:
        flag = False
        break


print('true' if flag else 'false')
==================================================
💻 CODE WITH DETAILED COMMENTS
==================================================
# Step 1: Take array size
n = int(input())
# Read number of elements
# Example: n = 5


# Step 2: Take array elements
L = [int(i) for i in input().split()]
# Read array with positive and negative numbers
# Example: L = [10, -11, 12, -13, 14]


# Step 3: Initialize flag
flag = True
# Assume array alternates correctly
# Will be set to False if pattern breaks


# Step 4: Loop through adjacent pairs
for i in range(n-1):
    # i goes from 0 to n-2
    # Compare L[i] with L[i+1]
    # Example: (10,-11), (-11,12), (12,-13), (-13,14)

    # Step 5: Check if both consecutive are positive
    if L[i] > 0 and L[i+1] > 0:
        # Two positive in a row breaks alternating pattern
        # Set flag to False
        flag = False
        # Exit loop (no need to check further)
        break

    # Step 6: Check if both consecutive are negative
    if L[i] < 0 and L[i+1] < 0:
        # Two negative in a row breaks alternating pattern
        # Set flag to False
        flag = False
        # Exit loop (no need to check further)
        break


# Step 7: Print result
print('true' if flag else 'false')
# If flag is True → alternating → print 'true'
# If flag is False → not alternating → print 'false'
==================================================
🔍 ALTERNATING PATTERN EXAMPLE
==================================================
Example 1: [10, -11, 12, -13, 14]
Pair 1: (10, -11) → positive, negative ✓
Pair 2: (-11, 12) → negative, positive ✓
Pair 3: (12, -13) → positive, negative ✓
Pair 4: (-13, 14) → negative, positive ✓
Pattern: +, -, +, -, + → ALTERNATES ✓
Output: true


Example 2: [10, -11, 12, -13, -14]
Pair 1: (10, -11) → positive, negative ✓
Pair 2: (-11, 12) → negative, positive ✓
Pair 3: (12, -13) → positive, negative ✓
Pair 4: (-13, -14) → negative, negative ✗
Pattern breaks! Both negative
Output: false


Example 3: [1, -2, 3, -4]
Pair 1: (1, -2) → positive, negative ✓
Pair 2: (-2, 3) → negative, positive ✓
Pair 3: (3, -4) → positive, negative ✓
Pattern: +, -, +, - → ALTERNATES ✓
Output: true


Example 4: [-5, 6, -7, 8]
Pair 1: (-5, 6) → negative, positive ✓
Pair 2: (6, -7) → positive, negative ✓
Pair 3: (-7, 8) → negative, positive ✓
Pattern: -, +, -, + → ALTERNATES ✓
Output: true


Example 5: [5, 6, -7, 8]
Pair 1: (5, 6) → positive, positive ✗
Pattern breaks! Both positive
Output: false
==================================================
🔢 EXAMPLE 2 - COMPLETE STEP BY STEP
==================================================
Input:
5
10 -11 12 -13 -14


Step 1: Take size
n = 5


Step 2: Take array
L = [10, -11, 12, -13, -14]


Step 3: Initialize flag
flag = True


Step 4: Loop and check
for i in range(n-1):
  i goes from 0 to 3


  i=0:
    L[0] = 10, L[1] = -11
    Check conditions → both False (skip)


  i=1:
    L[1] = -11, L[2] = 12
    Check conditions → both False (skip)


  i=2:
    L[2] = 12, L[3] = -13
    Check conditions → both False (skip)


  i=3:
    L[3] = -13, L[4] = -14
    if -13 > 0 and -14 > 0:
      -13 > 0 → False
      -14 > 0 → False
      False and False → False (skip)

    if -13 < 0 and -14 < 0:
      -13 < 0 → True ✓
      -14 < 0 → True ✓
      True and True → True ✓
      PATTERN BREAKS!
      flag = False
      break (exit loop)


Step 5: Print result
flag = False (pattern broken)
print('true' if flag else 'false')
Output: false
==================================================
🔢 EXAMPLE 3 - COMPLETE STEP BY STEP
==================================================
Input:
4
1 -2 3 -4


Step 1: Take size
n = 4


Step 2: Take array
L = [1, -2, 3, -4]


Step 3: Initialize flag
flag = True


Step 4: Loop and check
for i in range(n-1):
  i goes from 0 to 2


  i=0:
    L[0] = 1, L[1] = -2
    if 1 > 0 and -2 > 0: False
    if 1 < 0 and -2 < 0: False
    Continue


  i=1:
    L[1] = -2, L[2] = 3
    if -2 > 0 and 3 > 0: False
    if -2 < 0 and 3 < 0: False
    Continue


  i=2:
    L[2] = 3, L[3] = -4
    if 3 > 0 and -4 > 0: False
    if 3 < 0 and -4 < 0: False
    Loop ends


Step 5: Print result
flag = True
Output: true


==================================================
📋 KEY CONCEPTS EXPLAINED
==================================================
Positive number: > 0
Negative number: < 0
Zero: neither positive nor negative (= 0)


Alternating: Pattern switches between two states
+, -, +, -, + → alternating ✓
-, +, -, +, - → alternating ✓
+, +, -, -, + → NOT alternating ✗


Adjacent elements: Elements next to each other
L[0] and L[1] are adjacent
L[1] and L[2] are adjacent


range(n-1): Loop from 0 to n-2
Why n-1? Last pair is (n-2, n-1)


Boolean flag: True or False
Tracks whether pattern is valid
==================================================
✅ FINAL COMPLETE CODE
==================================================
n = int(input())
L = [int(i) for i in input().split()]


flag = True


for i in range(n-1):
    if L[i] > 0 and L[i+1] > 0:
        flag = False
        break
    if L[i] < 0 and L[i+1] < 0:
        flag = False
        break


print('true' if flag else 'false')


EXECUTION EXAMPLES:
Input: 5 and 10 -11 12 -13 14
Output: true


Input: 5 and 10 -11 12 -13 -14
Output: false


Input: 4 and 1 -2 3 -4
Output: true


Input: 4 and -5 6 -7 8
Output: true


Input: 4 and 5 6 -7 8
Output: false
==================================================
==================================================
LBP159 - CHECK IF ALL VALUES ARE TRUE
==================================================
🎯 PROBLEM STATEMENT:
Write a function that returns true if all parameters are 
truthy, and false otherwise


INPUT ------> an array size and array
CONSTRAINT --> no
OUTPUT ------> true or false
==================================================
💡 CONCEPT
==================================================
TRUTHY: Value that evaluates to True in boolean context
In Python:
- Non-zero numbers are truthy (1, 2, 3, -1, -5, etc.)
- Zero (0) is falsy
- Non-empty strings are truthy
- Empty strings are falsy
- Non-empty lists are truthy
- Empty lists are falsy


TRUTHY vs FALSY:
Truthy: 1, 2, 3, "hello", [1,2,3], True
Falsy: 0, "", [], False, None


PROBLEM: Check if ALL values in array are truthy
If any value is falsy (0) → return False
If all values are truthy (non-zero) → return True
==================================================
📝 LOGIC FLOW
==================================================
1. Take input array
2. Initialize flag = True (assume all truthy)
3. Loop through each element
4. Check if element is falsy (== 0)
5. If falsy found → flag = False and break
6. Print True if flag is True, False otherwise
==================================================
📝 DETAILED LOGIC BREAKDOWN
==================================================
Step 1: Take array size
n = int(input())
Purpose: Know number of elements
Example: n = 5


Step 2: Take array elements
L = [int(i) for i in input().split()]
Read array with numbers
Example: L = [10, 0, 11, 12, 0]


Step 3: Initialize flag
flag = True
Purpose: Assume all values are truthy
Will change to False if any falsy found


Step 4: Loop through array
for i in L:
Check each element


Step 5: Check if element is falsy (zero)
if i == 0:
"Is this element zero (falsy)?"
If yes → flag = False and break


Step 6: Print result
print('true' if flag else 'false')
If flag is True → all truthy → print 'true'
If flag is False → some falsy → print 'false'
==================================================
🔍 TRUTHY vs FALSY IN PYTHON
==================================================
NUMBERS:
0 → Falsy (False)
1 → Truthy (True)
2 → Truthy (True)
-1 → Truthy (True)
-5 → Truthy (True)
0.0 → Falsy (False)
0.1 → Truthy (True)


STRINGS:
"" (empty) → Falsy (False)
"hello" → Truthy (True)
"0" → Truthy (True) [string, not number]


LISTS:
[] (empty) → Falsy (False)
[1, 2, 3] → Truthy (True)
[0] → Truthy (True) [list with element, not empty]


BOOLEANS:
True → Truthy (True)
False → Falsy (False)


NONE:
None → Falsy (False)
==================================================
💻 PYTHON CODE
==================================================
n = int(input())
L = [int(i) for i in input().split()]


flag = True


for i in L:
    if i == 0:
        flag = False
        break


print('true' if flag else 'false')
==================================================
💻 CODE WITH DETAILED COMMENTS
==================================================
# Step 1: Take array size
n = int(input())
# Read number of elements
# Example: n = 5


# Step 2: Take array elements
L = [int(i) for i in input().split()]
# Read array of numbers
# Example: L = [10, 0, 11, 12, 0]


# Step 3: Initialize flag
flag = True
# Assume all values are truthy (non-zero)
# Will change to False if we find a falsy (0) value


# Step 4: Loop through each element
for i in L:
    # i takes each value from list
    # i = 10, then 0, then 11, then 12, then 0

    # Step 5: Check if element is falsy (zero)
    if i == 0:
        # Found a falsy value (zero)
        # Not all values are truthy
        flag = False
        # Mark as False

        break
        # Exit loop (no need to check further)


# Step 6: Print result
print('true' if flag else 'false')
# If flag is True → all values are truthy → print 'true'
# If flag is False → some value is falsy → print 'false'
==================================================
🔢 EXAMPLE 1 - COMPLETE STEP BY STEP
==================================================
Input:
5
10 0 11 12 0


Step 1: Take size
n = 5


Step 2: Take array
L = [10, 0, 11, 12, 0]


Step 3: Initialize flag
flag = True


Step 4: Loop and check
for i in L:

  Iteration 1:
    i = 10
    if 10 == 0:
      False (skip)
    flag remains True


  Iteration 2:
    i = 0
    if 0 == 0:
      True ✓ FALSY FOUND!
      flag = False
      break (exit loop)


Step 5: Print result
flag = False
Output: false


EXPLANATION:
Array has 0 (which is falsy)
Not all values are truthy
So output is 'false'
==================================================
🔢 EXAMPLE 2 - COMPLETE STEP BY STEP
==================================================
Input:
4
5 10 15 20


Step 1: Take size
n = 4


Step 2: Take array
L = [5, 10, 15, 20]


Step 3: Initialize flag
flag = True


Step 4: Loop and check
for i in L:

  Iteration 1:
    i = 5
    if 5 == 0: False (skip)
    flag remains True


  Iteration 2:
    i = 10
    if 10 == 0: False (skip)
    flag remains True


  Iteration 3:
    i = 15
    if 15 == 0: False (skip)
    flag remains True


  Iteration 4:
    i = 20
    if 20 == 0: False (skip)
    flag remains True

  Loop ends


Step 5: Print result
flag = True (no falsy found)
Output: true


EXPLANATION:
All values are non-zero (truthy)
All values are truthy
So output is 'true'


==================================================
📋 KEY CONCEPTS EXPLAINED
==================================================
Truthy: Value that evaluates to True
In Python:
- Any non-zero number is truthy
- 0 is falsy
- This problem only checks for 0


Falsy: Value that evaluates to False
- 0 is falsy
- Empty containers are falsy


if i == 0:
"Check if this value is zero (falsy)"


flag initialization:
flag = True
"Assume all are truthy, prove me wrong"


break statement:
"Stop checking once we find a falsy value"
No need to check rest of array


Conditional print:
print('true' if flag else 'false')
"If flag is True → print 'true', else print 'false'"


==================================================
LBP160 - SHARED DIGITS
==================================================
🎯 PROBLEM STATEMENT:
Create a function that returns true if each pair of adjacent 
numbers in an array shares at least one digit and false 
otherwise.


INPUT ------> array size and array elements
CONSTRAINT --> no
OUTPUT ------> true or false
==================================================
💡 CONCEPT
==================================================
SHARED DIGIT: Common digit between two numbers
Examples:
124 and 452 → digits in 124: {1,2,4}, digits in 452: {4,5,2}
            → common: {2,4} → YES, share digits ✓


589 and 888 → digits in 589: {5,8,9}, digits in 888: {8}
            → common: {8} → YES, share digits ✓


333 and 589 → digits in 333: {3}, digits in 589: {5,8,9}
            → common: {} → NO, no shared digits ✗


LOGIC:
Convert each number to string
Check each digit in first number
If found in second number → SHARED ✓
==================================================
📝 LOGIC FLOW
==================================================
1. Take input array
2. Initialize flag = True (assume all pairs share digits)
3. Loop through adjacent pairs
4. For each pair:
   - Check if they share at least one digit
   - If NO shared digit → flag = False and break
5. Print True if flag is True, False otherwise
==================================================
📝 DETAILED LOGIC BREAKDOWN
==================================================
Step 1: Take array size
n = int(input())
Example: n = 4


Step 2: Take array
L = [int(i) for i in input().split()]
Example: L = [124, 452, 589, 888]


Step 3: Initialize flag
flag = True
Purpose: Assume all pairs share digits


Step 4: Loop through adjacent pairs
for i in range(n-1):
Compare L[i] with L[i+1]


Step 5: Check shared digits
Convert numbers to strings
x = str(L[i])
y = str(L[i+1])


Step 6: Find shared digit
for digit in x:
  if digit in y:
    Found shared digit
    c = c + 1
    break


Step 7: Check counter
if c == 0:
  No shared digit found
  flag = False
  break (exit pair loop)


Step 8: Print result
print('true' if flag else 'false')
==================================================
🔍 HOW TO CHECK SHARED DIGITS
==================================================
Example 1: 124 and 452
Digits in 124: 1, 2, 4
Digits in 452: 4, 5, 2


Check each digit from 124:
- Is 1 in 452? No
- Is 2 in 452? YES ✓ SHARED


Output: They share digit 2 (and 4)


Example 2: 589 and 888
Digits in 589: 5, 8, 9
Digits in 888: 8, 8, 8


Check each digit from 589:
- Is 5 in 888? No
- Is 8 in 888? YES ✓ SHARED


Output: They share digit 8


Example 3: 333 and 589
Digits in 333: 3, 3, 3
Digits in 589: 5, 8, 9


Check each digit from 333:
- Is 3 in 589? No


Output: No shared digits


Example 4: 124 and 333
Digits in 124: 1, 2, 4
Digits in 333: 3, 3, 3


Check each digit from 124:
- Is 1 in 333? No
- Is 2 in 333? No
- Is 4 in 333? No


Output: No shared digits
==================================================
💻 PYTHON CODE
==================================================
n = int(input())
L = [int(i) for i in input().split()]


flag = True


for i in range(n-1):
    x = str(L[i])
    c = 0

    while x != 0:
        if str(x%10) in str(L[i+1]):
            c = c + 1
            break
        x = x // 10

    if c == 0:
        flag = False
        break


print('true' if flag else 'false')
==================================================
💻 SIMPLER PYTHON CODE (USING STRING)
==================================================
n = int(input())
L = [int(i) for i in input().split()]


flag = True


for i in range(n-1):
    x = str(L[i])
    y = str(L[i+1])

    shared = False
    for digit in x:
        if digit in y:
            shared = True
            break

    if not shared:
        flag = False
        break


print('true' if flag else 'false')
==================================================
💻 CODE WITH DETAILED COMMENTS (SIMPLER VERSION)
==================================================
# Step 1: Take array size
n = int(input())
# Read number of elements


# Step 2: Take array
L = [int(i) for i in input().split()]
# Read array elements


# Step 3: Initialize flag
flag = True
# Assume all pairs share digits


# Step 4: Loop through adjacent pairs
for i in range(n-1):
    # i goes from 0 to n-2
    # Compare L[i] with L[i+1]

    # Step 5: Convert to strings
    x = str(L[i])
    # First number as string
    # Example: 124 → "124"

    y = str(L[i+1])
    # Second number as string
    # Example: 452 → "452"

    # Step 6: Check for shared digit
    shared = False
    # Assume no shared digit initially

    for digit in x:
        # Check each digit in first number
        # digit = '1', then '2', then '4'

        if digit in y:
            # Is this digit in second number?
            # '1' in "452"? No
            # '2' in "452"? YES ✓

            shared = True
            # Found shared digit

            break
            # Exit inner loop

    # Step 7: Check if pair has shared digit
    if not shared:
        # No shared digit found in this pair
        flag = False
        # Mark as False

        break
        # Exit pair loop


# Step 8: Print result
print('true' if flag else 'false')
# If flag is True → all pairs share → print 'true'
# If flag is False → some pair doesn't share → print 'false'
==================================================
🔢 EXAMPLE 1 - COMPLETE STEP BY STEP
==================================================
Input:
4
124 452 589 888


Step 1: Take size
n = 4


Step 2: Take array
L = [124, 452, 589, 888]


Step 3: Initialize flag
flag = True


Step 4-7: Loop through pairs
for i in range(n-1): # i = 0, 1, 2


  PAIR 1 (i=0): 124 and 452
    x = "124"
    y = "452"
    shared = False

    Check digits in x:
      digit = '1': '1' in "452"? No
      digit = '2': '2' in "452"? YES ✓
      shared = True
      break

    if not shared: False (skip)
    flag remains True


  PAIR 2 (i=1): 452 and 589
    x = "452"
    y = "589"
    shared = False

    Check digits in x:
      digit = '4': '4' in "589"? No
      digit = '5': '5' in "589"? YES ✓
      shared = True
      break

    if not shared: False (skip)
    flag remains True


  PAIR 3 (i=2): 589 and 888
    x = "589"
    y = "888"
    shared = False

    Check digits in x:
      digit = '5': '5' in "888"? No
      digit = '8': '8' in "888"? YES ✓
      shared = True
      break

    if not shared: False (skip)
    flag remains True


Step 8: Print result
flag = True
Output: true


EXPLANATION:
All adjacent pairs share at least one digit
124-452: share 2, 4
452-589: share 5
589-888: share 8
Output: 'true'


==================================================
📋 KEY CONCEPTS EXPLAINED
==================================================
String conversion:
str(124) = "124"
"124" allows checking individual digits


digit in string:
'2' in "124" → True
'5' in "124" → False


Adjacent pairs:
L[i] and L[i+1] are adjacent
Loop range(n-1) to check all pairs


Counter/flag pattern:
c = 0 or shared = False initially
Increment/set to True when digit found
Check counter/flag after inner loop


break statements:
Inner break: exits digit checking loop
Outer break: exits pair checking loop
==================================================
✅ FINAL COMPLETE CODE
==================================================
n = int(input())
L = [int(i) for i in input().split()]


flag = True


for i in range(n-1):
    x = str(L[i])
    y = str(L[i+1])

    shared = False
    for digit in x:
        if digit in y:
            shared = True
            break

    if not shared:
        flag = False
        break


print('true' if flag else 'false')


EXECUTION EXAMPLES:
Input: 4 and 124 452 589 888
Output: true (all pairs share digits)


Input: 4 and 124 333 589 888
Output: false (124-333 don't share)


Input: 3 and 111 222 333
Output: false (111-222 don't share)


Input: 3 and 100 211 115
Output: true (all pairs share)


Input: 5 and 12 23 34 45 56
Output: true (consecutive sharing)
==================================================
==================================================
LBP161 - COMBINED CONSECUTIVE SEQUENCE
==================================================
🎯 PROBLEM STATEMENT:
Write a function that returns true if two arrays, when combined, 
form a consecutive sequence. A consecutive sequence is a sequence 
without any gaps in the integers, e.g. 1, 2, 3, 4, 5 is a 
consecutive sequence, but 1, 2, 4, 5 is not.


INPUT ------> two array sizes and array elements
CONSTRAINT --> no
OUTPUT ------> true or false
==================================================
💡 CONCEPT
==================================================
CONSECUTIVE SEQUENCE: Numbers in order without gaps
Examples:
[1, 2, 3, 4, 5] → consecutive ✓
[1, 2, 4, 5] → NOT consecutive (gap at 3) ✗
[5, 1, 3, 2, 4] → consecutive if sorted: [1,2,3,4,5] ✓


LOGIC:
1. Combine two arrays
2. Sort combined array
3. Check if each element is exactly 1 more than previous
4. Also check: first element should be min, last should be max


EXAMPLE:
Array1: [1, 3]
Array2: [2, 4, 5]
Combined: [1, 3, 2, 4, 5]
Sorted: [1, 2, 3, 4, 5]
Check: 1→2→3→4→5 (each +1) ✓ consecutive


EXAMPLE:
Array1: [1, 2]
Array2: [4, 5]
Combined: [1, 2, 4, 5]
Sorted: [1, 2, 4, 5]
Check: 1→2 (+1)✓, 2→4 (+2)✗ gap! NOT consecutive
==================================================
📝 LOGIC FLOW
==================================================
1. Take first array size and elements
2. Take second array size and elements
3. Combine both arrays
4. Sort combined array
5. Initialize count = 0
6. Loop through combined array
7. For each index i:
   - Check if L3[i] + 1 == L3[i+1]
   - If yes, increment count
8. Check if count == total_pairs
   - count should equal (n1+n2)-1
   - If yes → consecutive → print 'true'
   - If no → NOT consecutive → print 'false'
==================================================
📝 DETAILED LOGIC BREAKDOWN
==================================================
Step 1: Take first array size
n1 = int(input())
Example: n1 = 2


Step 2: Take first array elements
L1 = [int(i) for i in input().split()]
Example: L1 = [1, 3]


Step 3: Take second array size
n2 = int(input())
Example: n2 = 3


Step 4: Take second array elements
L2 = [int(i) for i in input().split()]
Example: L2 = [2, 4, 5]


Step 5: Combine arrays
L3 = L1 + L2
Example: L3 = [1, 3, 2, 4, 5]


Step 6: Sort combined array
L3.sort()
Example: L3 = [1, 2, 3, 4, 5]


Step 7: Initialize counter
count = 0
Purpose: Count valid consecutive pairs


Step 8: Loop through and check
for i in range((n1+n2)-1):
  Loop from 0 to (n1+n2)-2
  Check each adjacent pair

  if L3[i] + 1 == L3[i+1]:
    "Is next element exactly 1 more?"
    If yes:
      count = count + 1


Step 9: Check final count
print('true' if count==(n1+n2)-1 else 'false')
If count equals total pairs → consecutive → 'true'
If count less than total pairs → gap exists → 'false'
==================================================
🔍 CONSECUTIVE SEQUENCE CHECK EXAMPLE
==================================================
Example 1: [1, 2, 3, 4, 5]
Pairs to check:
- 1+1==2? YES → count=1
- 2+1==3? YES → count=2
- 3+1==4? YES → count=3
- 4+1==5? YES → count=4


Total pairs = 5-1 = 4
count = 4
4 == 4? YES → consecutive ✓


Example 2: [1, 2, 4, 5]
Pairs to check:
- 1+1==2? YES → count=1
- 2+1==4? NO (2+1=3, not 4)
- 4+1==5? YES → count=2


Total pairs = 4-1 = 3
count = 2
2 == 3? NO → NOT consecutive ✗


Example 3: [5, 1, 3, 2, 4]
After sort: [1, 2, 3, 4, 5]
Pairs to check:
- 1+1==2? YES → count=1
- 2+1==3? YES → count=2
- 3+1==4? YES → count=3
- 4+1==5? YES → count=4


Total pairs = 5-1 = 4
count = 4
4 == 4? YES → consecutive ✓


Example 4: [1, 3, 5]
After sort: [1, 3, 5]
Pairs to check:
- 1+1==3? NO (1+1=2, not 3)
- 3+1==5? NO (3+1=4, not 5)


Total pairs = 3-1 = 2
count = 0
0 == 2? NO → NOT consecutive ✗
==================================================
💻 PYTHON CODE
==================================================
n1 = int(input())
L1 = [int(i) for i in input().split()]


n2 = int(input())
L2 = [int(i) for i in input().split()]


L3 = L1 + L2
L3.sort()


count = 0


for i in range((n1+n2)-1):
    if L3[i] + 1 == L3[i+1]:
        count = count + 1


print('true' if count == (n1+n2)-1 else 'false')
==================================================
💻 CODE WITH DETAILED COMMENTS
==================================================
# Step 1: Take first array size
n1 = int(input())
# Read size of first array
# Example: n1 = 2


# Step 2: Take first array elements
L1 = [int(i) for i in input().split()]
# Read first array elements
# Example: L1 = [1, 3]


# Step 3: Take second array size
n2 = int(input())
# Read size of second array
# Example: n2 = 3


# Step 4: Take second array elements
L2 = [int(i) for i in input().split()]
# Read second array elements
# Example: L2 = [2, 4, 5]


# Step 5: Combine both arrays
L3 = L1 + L2
# L3 = [1, 3] + [2, 4, 5]
# L3 = [1, 3, 2, 4, 5]


# Step 6: Sort combined array
L3.sort()
# L3 = [1, 2, 3, 4, 5]
# Now in ascending order


# Step 7: Initialize counter
count = 0
# Counter for consecutive pairs found
# Will be incremented each time pair is consecutive


# Step 8: Loop through sorted array
for i in range((n1+n2)-1):
    # i goes from 0 to (n1+n2)-2
    # For example: i = 0, 1, 2, 3
    # This creates pairs: (L3[0],L3[1]), (L3[1],L3[2]), etc.

    # Step 9: Check if pair is consecutive
    if L3[i] + 1 == L3[i+1]:
        # Check if next element is exactly 1 more
        # L3[0] + 1 == L3[1]? → 1+1==2? → YES
        # L3[1] + 1 == L3[2]? → 2+1==3? → YES
        # L3[2] + 1 == L3[3]? → 3+1==4? → YES
        # L3[3] + 1 == L3[4]? → 4+1==5? → YES

        count = count + 1
        # Increment counter for each consecutive pair


# Step 10: Check final count
print('true' if count == (n1+n2)-1 else 'false')
# If count equals total number of pairs → all consecutive → 'true'
# If count less than total pairs → gap exists → 'false'
# Total pairs = (n1+n2)-1
# Example: 5 elements → 4 pairs
==================================================
🔢 EXAMPLE 1 - COMPLETE STEP BY STEP
==================================================
Input:
2
1 3
3
2 4 5


Step 1: Take first size
n1 = 2


Step 2: Take first array
L1 = [1, 3]


Step 3: Take second size
n2 = 3


Step 4: Take second array
L2 = [2, 4, 5]


Step 5: Combine arrays
L3 = [1, 3] + [2, 4, 5]
L3 = [1, 3, 2, 4, 5]


Step 6: Sort
L3.sort()
L3 = [1, 2, 3, 4, 5]


Step 7: Initialize count
count = 0


Step 8-9: Loop and check
for i in range((2+3)-1): # range(4)
  i goes from 0 to 3


  i=0:
    L3[0]=1, L3[1]=2
    if 1+1==2: YES ✓
    count = 0 + 1 = 1


  i=1:
    L3[1]=2, L3[2]=3
    if 2+1==3: YES ✓
    count = 1 + 1 = 2


  i=2:
    L3[2]=3, L3[3]=4
    if 3+1==4: YES ✓
    count = 2 + 1 = 3


  i=3:
    L3[3]=4, L3[4]=5
    if 4+1==5: YES ✓
    count = 3 + 1 = 4


Step 10: Check count
count = 4
(n1+n2)-1 = (2+3)-1 = 4
4 == 4? YES ✓


Output: true


EXPLANATION:
Combined [1,3,2,4,5]
Sorted [1,2,3,4,5]
All pairs are consecutive
Output: 'true'


==================================================
LBP162 - COUNT 5s AND WIN
==================================================
🎯 PROBLEM STATEMENT:
Arun is obsessed with primes, especially five. He considers a 
number to be luckiest if it has the highest number of five in it. 
If two numbers have the same frequency of five, Arun considers 
the last occurrence of them to be luckiest, and if there is no 
five in any number, the first given number is considered luckiest. 
Help him choose the luckiest number.


INPUT ------> array size and elements
CONSTRAINT --> no
OUTPUT ------> return luckiest number
==================================================
💡 CONCEPT
==================================================
LUCKIEST NUMBER: Based on count of digit 5


RULES:
1. Number with highest count of 5 → luckiest
2. If two numbers have same count of 5 → last one wins
3. If no 5 in any number → first number wins


EXAMPLES:
[555, 25, 5] → 555 has 3 fives → luckiest
[25, 55, 15] → 25 has 1 five, 55 has 2 fives → 55 is luckiest
[55, 55] → both have 2 fives, last one (55) wins
[12, 34, 67] → no fives, first (12) wins
==================================================
📝 LOGIC FLOW
==================================================
1. Take input array
2. Initialize: c=0 (max fives), cc=0 (times max reached)
3. Initialize: element=L[0] (default luckiest)
4. Loop through each number
5. For each number:
   - Count digit 5 in that number
   - If count > c: update c, reset cc, update element
   - If count == c and count > 0: increment cc, update element
6. If cc == 0 (no fives found): print L[0]
7. Else: print element
==================================================
📝 DETAILED LOGIC BREAKDOWN
==================================================
Step 1: Take array size
n = int(input())
Example: n = 4


Step 2: Take array
L = [int(i) for i in input().split()]
Example: L = [555, 25, 5, 125]


Step 3: Initialize variables
c = 0
Purpose: Track maximum count of 5s found


cc = 0
Purpose: Track how many times max count appears


element = L[0]
Purpose: Store the luckiest number (default first)


Step 4: Loop through array
for i in L:
Check each number


Step 5: Count 5s in current number
x = str(i).count('5')
Convert number to string
Count occurrences of character '5'
Example: 555 → "555" → count('5') → 3
         25 → "25" → count('5') → 1
         5 → "5" → count('5') → 1
         125 → "125" → count('5') → 1


Step 6: Check if this is luckiest so far
if c < x:
"Is this count more than max so far?"
If yes:
  c = x (update max count)
  element = i (update luckiest number)


if x == c:
"Does this match the max count?"
If yes and count > 0:
  element = i (update to latest)


Step 7: Check final result
if cc == n:
"Did all numbers have same count?"
Actually, check if any 5 was found
If no 5 found → print L[0]
Else → print element
==================================================
🔍 COUNTING 5s EXAMPLE
==================================================
Number 555:
str(555) = "555"
count('5') = 3


Number 25:
str(25) = "25"
count('5') = 1


Number 5:
str(5) = "5"
count('5') = 1


Number 125:
str(125) = "125"
count('5') = 1


Number 555555:
str(555555) = "555555"
count('5') = 6


Number 1234:
str(1234) = "1234"
count('5') = 0 (no 5)


==================================================
💻 CODE WITH DETAILED COMMENTS
==================================================
# Step 1: Take array size
n = int(input())
# Read number of elements


# Step 2: Take array
L = [int(i) for i in input().split()]
# Read array of numbers
# Example: L = [555, 25, 5, 125]


# Step 3: Initialize max count
c = 0
# Maximum count of 5s found so far
# Starts at 0 (no 5s found yet)


# Initialize times max count appears
cc = 0
# How many numbers have the max count
# Starts at 0


# Initialize luckiest number
element = L[0]
# Default luckiest is first number
# Will be updated if better one found


# Step 4: Loop through each number
for i in L:
    # i takes each value from array

    # Step 5: Count 5s in current number
    x = str(i).count('5')
    # Convert i to string
    # Count how many times '5' appears
    # Example: str(555)="555", count('5')=3
    #          str(25)="25", count('5')=1

    # Step 6a: Check if this is better than current max
    if c < x:
        # This number has more 5s than max found
        c = x
        # Update maximum count

        element = i
        # This becomes new luckiest number

    # Step 6b: Check if this equals current max
    if x == c:
        # This number has same count of 5s as max
        cc = cc + 1
        # Increment times we've seen this count

        # Note: We update element so last occurrence wins
        # (because we're in a loop, later iterations update)
        # Actually need explicit update here:
        if x > 0:
            element = i
            # If count > 0, latest occurrence becomes luckiest


# Step 7: Determine what to print
if cc == n:
    # All numbers have same count of 5s
    # AND that count is 0 (no 5s in any number)
    print(L[0])
    # First number is luckiest
else:
    # Some number has more 5s (or latest occurrence wins)
    print(element)
    # Print that number
==================================================
🔢 EXAMPLE 1 - COMPLETE STEP BY STEP
==================================================
Input:
4
555 25 5 125


Step 1: Take size
n = 4


Step 2: Take array
L = [555, 25, 5, 125]


Step 3: Initialize
c = 0 (max count of 5s)
cc = 0 (times max appears)
element = L[0] = 555


Step 4-6: Loop and check
for i in L:


  i = 555:
    x = str(555).count('5') = 3

    if 0 < 3: YES ✓
      c = 3
      element = 555

    if 3 == 3: YES
      cc = 0 + 1 = 1
      if 3 > 0: element = 555


  i = 25:
    x = str(25).count('5') = 1

    if 3 < 1: NO

    if 1 == 3: NO


  i = 5:
    x = str(5).count('5') = 1

    if 3 < 1: NO

    if 1 == 3: NO


  i = 125:
    x = str(125).count('5') = 1

    if 3 < 1: NO

    if 1 == 3: NO


Step 7: Check result
cc = 1
n = 4
cc == n? NO (1 != 4)


print(element)
element = 555


Output: 555


EXPLANATION:
555 has 3 fives (highest)
25, 5, 125 each have 1 five
555 is luckiest
Output: 555


==================================================
📋 KEY CONCEPTS EXPLAINED
==================================================
String conversion & count:
str(555) = "555"
str(555).count('5') = 3
Counts how many times '5' appears


Loop logic:
- Check each number's count
- Update max if greater
- Update element if new max or same as max
- Keep updating element in loop ensures last wins


Special case:
If no 5 found in any number:
  cc will equal n (all have count 0)
  Print L[0] (first number wins)


Counter patterns:
c = maximum count seen
cc = how many times maximum count appears


==================================================
list.count() vs DICTIONARY - COMPARISON
==================================================


📚 DEFINITION
==================================================


LIST.COUNT():
- Built-in method
- Scans entire array each time
- Counts element occurrences
Example: [1,1,2].count(1) → 2


DICTIONARY:
- Data structure with key-value pairs
- Stores count in memory
- Fast lookup (no scanning)
Example: {1: 2, 2: 1}


==================================================
💻 SYNTAX
==================================================


LIST.COUNT():
L.count(element)


DICTIONARY:
Create: freq = {}
Add: freq[key] = value
Update: freq[key] += 1
Check: if key in freq:
Loop: for key, value in freq.items():


==================================================
🔢 EXAMPLE: [1, 2, 3, 4, 2, 3, 5, 5, 6]
Find: Elements appearing > 1 time


==================================================
METHOD 1: list.count() WITH COMMENTS
==================================================


# Convert list to set (unique elements)
list = [1, 2, 3, 4, 2, 3, 5, 5, 6]
set_list = set(list)
# set_list = {1, 2, 3, 4, 5, 6}


# Loop through unique elements
for ele in set_list:
    # ele = 1, 2, 3, 4, 5, 6

    if list.count(ele) > 1:
        # Count how many times ele appears
        # SCANS ENTIRE ARRAY each time

        print(ele, list.count(ele))
        # Print if duplicate


# EXECUTION:
# ele=1: SCAN [1,2,3,4,2,3,5,5,6] → count=1 → 1>1? NO
# ele=2: SCAN [1,2,3,4,2,3,5,5,6] → count=2 → 2>1? YES → PRINT 2 2
# ele=3: SCAN [1,2,3,4,2,3,5,5,6] → count=2 → 2>1? YES → PRINT 3 2
# ele=4: SCAN [1,2,3,4,2,3,5,5,6] → count=1 → 1>1? NO
# ele=5: SCAN [1,2,3,4,2,3,5,5,6] → count=2 → 2>1? YES → PRINT 5 2
# ele=6: SCAN [1,2,3,4,2,3,5,5,6] → count=1 → 1>1? NO


# Total array scans: 6 times ❌ WASTEFUL


# OUTPUT: 2 2, 3 2, 5 2


==================================================
METHOD 2: DICTIONARY WITH COMMENTS
==================================================


# Original list
list = [1, 2, 3, 4, 2, 3, 5, 5, 6]
# Create empty dictionary
freq = {}
# LOOP 1: Build frequency dictionary
for ele in list:
    # ele = 1, 2, 3, 4, 2, 3, 5, 5, 6

    if ele in freq:
        # Element already in dictionary
        freq[ele] += 1
    else:
        # First time seeing element
        freq[ele] = 1


# SCAN ARRAY: Only 1 time ✓


# Final: freq = {1: 1, 2: 2, 3: 2, 4: 1, 5: 2, 6: 1}


# LOOP 2: Find duplicates
for num, count in freq.items():
    # num = 1, 2, 3, 4, 5, 6
    # count = value from dictionary (no scanning!)

    if count > 1:
        # No array scanning, just check dictionary
        print(num, count)


# EXECUTION:
# num=1, count=1: 1>1? NO
# num=2, count=2: 2>1? YES → PRINT 2 2
# num=3, count=2: 2>1? YES → PRINT 3 2
# num=4, count=1: 1>1? NO
# num=5, count=2: 2>1? YES → PRINT 5 2
# num=6, count=1: 1>1? NO


# Total array scans: 1 time ✓ FAST


# OUTPUT: 2 2, 3 2, 5 2


==================================================
📊 SIDE BY SIDE COMPARISON
==================================================


METRIC              list.count()      DICTIONARY
─────────────────────────────────────────────────
Array scans         6 times ❌        1 time ✓
Code length         3 lines           10 lines
Speed               SLOW ❌           FAST ✓
Memory usage        Low               Higher
Easy to write       YES ✓             Bit harder
Repeated work       YES ❌            NO ✓


For 9 elements:
set_list = 6 unique
list.count()        → 6 scans ❌
Dictionary          → 1 scan ✓


For 100 elements:
100 unique
list.count()        → 100 scans ❌
Dictionary          → 1 scan ✓


For 1000 elements:
1000 unique
list.count()        → 1000 scans ❌
Dictionary          → 1 scan ✓


SPEED DIFFERENCE: Dictionary is 6-1000x FASTER! 🚀


==================================================
🔍 WHY DICTIONARY IS BETTER?
==================================================


list.count() PROBLEM:
- Scans entire array each time
- Same element checked multiple times
- 6 unique elements = 6 array scans
- ❌ WASTEFUL


DICTIONARY SOLUTION:
- Scans array only once
- Stores count in dictionary
- Lookup from memory (instant)
- ✓ EFFICIENT


==================================================
✅ BOTH GIVE SAME OUTPUT
==================================================


Both methods print:
2 2
3 2
5 2


But Dictionary is MUCH FASTER! ✓


==================================================
💡 WHEN TO USE WHICH?
==================================================


USE list.count():
- Very small arrays (< 10 items)
- Learning purposes
- Code simplicity matters


USE DICTIONARY:
- Large arrays (> 100 items)
- Performance matters
- Professional code
- Real projects


RECOMMENDATION: Always use Dictionary ✓


==================================================
✅ FINAL COMPARISON CODE
==================================================


# SAME EXAMPLE, TWO APPROACHES


# METHOD 1: list.count() - SLOW
list = [1, 2, 3, 4, 2, 3, 5, 5, 6]
set_list = set(list)
for ele in set_list:
    if list.count(ele) > 1:
        print(ele, list.count(ele))
# 6 array scans ❌


# METHOD 2: DICTIONARY - FAST
list = [1, 2, 3, 4, 2, 3, 5, 5, 6]
freq = {}
for ele in list:
    if ele in freq:
        freq[ele] += 1
    else:
        freq[ele] = 1
for num, count in freq.items():
    if count > 1:
        print(num, count)
# 1 array scan ✓


# SAME OUTPUT:
# 2 2
# 3 2
# 5 2


==================================================
==================================================
LBP163 - FIND THE SINGLE NUMBER
==================================================
🎯 PROBLEM STATEMENT:
Write a function that accepts an array of numbers (where each 
number appears three times except for one which appears only 
once) and finds that unique number in the array and returns it.


INPUT ------> array size and elements
CONSTRAINT --> no
OUTPUT ------> return non-repeated number
==================================================
💡 CONCEPT
==================================================
SINGLE NUMBER: Number that appears only once
ALL OTHERS: Appear exactly 3 times


LOGIC:
Count frequency of each number
Find number with count = 1
Return that number


EXAMPLE:
[1, 1, 1, 2, 2, 2, 5, 3, 3, 3]
Frequencies: 1 appears 3 times
             2 appears 3 times
             5 appears 1 time ← SINGLE
             3 appears 3 times
Output: 5
==================================================
📝 LOGIC FLOW
==================================================
1. Take input array
2. Loop through each number
3. Count how many times it appears in array
4. If count == 1:
   - This is the single number
   - Print and exit
==================================================
📝 DETAILED LOGIC BREAKDOWN
==================================================
Step 1: Take array size
n = int(input())
Example: n = 10


Step 2: Take array
L = [int(i) for i in input().split()]
Example: L = [1, 1, 1, 2, 2, 2, 5, 3, 3, 3]


Step 3: Loop through array
for i in L:
Check each number


Step 4: Count occurrences
t = L.count(i)
How many times does i appear in list?
Uses built-in count() method


Step 5: Check if single
if t == 1:
If this number appears only once:
  print(i)
  Return the number
==================================================
🔍 COUNT METHOD EXAMPLE
==================================================
[1, 1, 1, 2, 2, 2, 5, 3, 3, 3].count(1) = 3
[1, 1, 1, 2, 2, 2, 5, 3, 3, 3].count(2) = 3
[1, 1, 1, 2, 2, 2, 5, 3, 3, 3].count(5) = 1
[1, 1, 1, 2, 2, 2, 5, 3, 3, 3].count(3) = 3


[5, 5, 5, 10, 10, 10, 20].count(5) = 3
[5, 5, 5, 10, 10, 10, 20].count(10) = 3
[5, 5, 5, 10, 10, 10, 20].count(20) = 1


[7, 7, 7, 7, 7, 7, 99, 9, 9, 9].count(7) = 6
[7, 7, 7, 7, 7, 7, 99, 9, 9, 9].count(99) = 1
[7, 7, 7, 7, 7, 7, 99, 9, 9, 9].count(9) = 3
==================================================
💻 CODE WITH DETAILED COMMENTS
==================================================
# Step 1: Take array size
n = int(input())
# Read number of elements
# Example: n = 10


# Step 2: Take array elements
L = [int(i) for i in input().split()]
# Read array of numbers
# Example: L = [1, 1, 1, 2, 2, 2, 5, 3, 3, 3]


# Step 3: Loop through each number
for i in L:
    # i takes each value from array
    # i = 1, then 1, then 1, then 2, then 2, then 2, then 5, then 3, then 3, then 3

    # Step 4: Count how many times i appears
    t = L.count(i)
    # count() returns how many times i appears in L
    # Example: L.count(1) = 3
    #          L.count(5) = 1
    #          L.count(3) = 3

    # Step 5: Check if this is the single number
    if t == 1:
        # This number appears only once
        print(i)
        # Print it and exit


NOTES:
- Loop continues and prints same number multiple times
- But we only care about the first print
- Since each number appears fixed times, this works fine
- Alternative: use break to exit after finding
==================================================
💻 OPTIMIZED CODE WITH BREAK
==================================================
n = int(input())
L = [int(i) for i in input().split()]


for i in L:
    t = L.count(i)
    if t == 1:
        print(i)
        break  # Exit loop after finding


BENEFIT:
- break stops loop immediately
- No need to continue checking
- More efficient
==================================================
💻 ALTERNATIVE APPROACH (USING DICTIONARY)
==================================================
n = int(input())
L = [int(i) for i in input().split()]


frequency = {}


for i in L:
    if i in frequency:
        frequency[i] = frequency[i] + 1
    else:
        frequency[i] = 1


for num, count in frequency.items():
    if count == 1:
        print(num)
        break


EXPLANATION:
- Creates dictionary of frequencies
- Loops through once to count
- Loops through dictionary to find count=1
- More efficient for large arrays (count method recounts)
==================================================
🔢 EXAMPLE 1 - COMPLETE STEP BY STEP
==================================================
Input:
10
1 1 1 2 2 2 5 3 3 3


Step 1: Take size
n = 10


Step 2: Take array
L = [1, 1, 1, 2, 2, 2, 5, 3, 3, 3]


Step 3-5: Loop and count
for i in L:


  i = 1:
    t = L.count(1) = 3
    if 3 == 1: NO (skip)


  i = 1:
    t = L.count(1) = 3
    if 3 == 1: NO (skip)


  i = 1:
    t = L.count(1) = 3
    if 3 == 1: NO (skip)


  i = 2:
    t = L.count(2) = 3
    if 3 == 1: NO (skip)


  i = 2:
    t = L.count(2) = 3
    if 3 == 1: NO (skip)


  i = 2:
    t = L.count(2) = 3
    if 3 == 1: NO (skip)


  i = 5:
    t = L.count(5) = 1
    if 1 == 1: YES ✓
    print(5)
    break (exit)


Output: 5


EXPLANATION:
Array has:
- 1 appears 3 times
- 2 appears 3 times
- 5 appears 1 time ← SINGLE
- 3 appears 3 times
Output: 5
a
==================================================
📋 KEY CONCEPTS EXPLAINED
==================================================
List.count(element):
- Built-in Python method
- Returns how many times element appears
- Example: [1,1,1,2,2,2,5].count(5) = 1


Loop through array:
for i in L:
- Checks each element
- Even if repeated, still processes


Finding single element:
if count == 1:
- Only one number has count of 1
- That's our answer


Note on efficiency:
- count() method recalculates for each iteration
- Not optimal for large arrays
- Dictionary approach is better
- But for this problem, both work fine
==================================================
✅ FINAL COMPLETE CODE
==================================================
n = int(input())
L = [int(i) for i in input().split()]


for i in L:
    t = L.count(i)
    if t == 1:
        print(i)
        break


EXECUTION EXAMPLES:
Input: 10 and 1 1 1 2 2 2 5 3 3 3
Output: 5


Input: 7 and 10 10 10 20 20 20 99
Output: 99


Input: 10 and 7 7 7 7 7 7 99 9 9 9
Output: 99


Input: 7 and 5 5 5 10 10 10 20
Output: 20


Input: 10 and 2 2 2 4 4 4 6 6 6 777
Output: 777
==================================================
==================================================
LBP164 - UPDATE EVERY ELEMENT
==================================================


📚 PROBLEM STATEMENT
==================================================


PROBLEM:
Implement a program to update every array element with 
multiplication of previous and next numbers in array.


WHAT TO DO:
- Take an array as input
- Update each middle element with: previous * next
- First element stays same (no previous)
- Last element stays same (no next)
- Print updated array


EXAMPLE:
Input:  [1, 2, 3, 4, 5]
Output: [1, 3, 12, 60, 5]


Explanation:
- Position 0: 1 (stays same - first element)
- Position 1: 2 → 1*3 = 3 (previous*next)
- Position 2: 3 → 2*4 = 8, but uses updated 3
              → 3*4 = 12
- Position 3: 4 → 3*5 = 15, but uses updated 12
              → 12*5 = 60
- Position 4: 5 (stays same - last element)


==================================================
📋 INPUT/OUTPUT SPECIFICATION
==================================================


INPUT:
- Line 1: Size of array (n)
- Line 2: Array elements (space separated)


Example:
5
1 2 3 4 5


OUTPUT:
- Updated array (space separated)


Example:
1 3 12 60 5


CONSTRAINT:
- No specific constraint mentioned


==================================================


==================================================
✅ COMPLETE CODE WITH COMMENTS
==================================================


# STEP 1: Take input
# ══════════════════


# Read array size
n = int(input())
# Example: n = 5


# Read array elements
L = [int(i) for i in input().split()]
# Example: L = [1, 2, 3, 4, 5]


# STEP 2: Update middle elements
# ══════════════════════════════


for i in range(1, n-1):
    # i goes from 1 to n-2
    # Skips first (index 0) and last (index n-1)
    # Example: i = 1, 2, 3

    # Update element at index i
    L[i] = L[i-1] * L[i+1]
    # new_value = previous * next
    # Example:
    # L[1] = L[0] * L[2] = 1 * 3 = 3
    # L[2] = L[1] * L[3] = 3 * 4 = 12 (uses updated L[1])
    # L[3] = L[2] * L[4] = 12 * 5 = 60 (uses updated L[2])


# STEP 3: Print result
# ════════════════════


# Print first element (unchanged)
print(L[0], end=' ')
# Output: 1 


# Print middle elements (updated)
for i in range(1, n-1):
    print(L[i], end=' ')
    # Output: 3 12 60 


# Print last element (unchanged)
print(L[-1])
# Output: 5


# Final: 1 3 12 60 5


==================================================
🔢 EXAMPLE 1 - DETAILED EXECUTION
==================================================


INPUT:
5
1 2 3 4 5


SETUP:
n = 5
L = [1, 2, 3, 4, 5]
     0  1  2  3  4  (indices)


STEP 1: UPDATE MIDDLE ELEMENTS
for i in range(1, 4):  # i = 1, 2, 3


  ITERATION 1: i = 1
  ─────────────────────
  Calculate: L[1] = L[0] * L[2]
  L[1] = 1 * 3
  L[1] = 3
  Current array: L = [1, 3, 3, 4, 5]
  ✓ First element processed


  ITERATION 2: i = 2
  ─────────────────────
  Calculate: L[2] = L[1] * L[3]
  Note: L[1] is now 3 (updated value)
  L[2] = 3 * 4
  L[2] = 12
  Current array: L = [1, 3, 12, 4, 5]
  ✓ Second element processed


  ITERATION 3: i = 3
  ─────────────────────
  Calculate: L[3] = L[2] * L[4]
  Note: L[2] is now 12 (updated value)
  L[3] = 12 * 5
  L[3] = 60
  Current array: L = [1, 3, 12, 60, 5]
  ✓ Third element processed


STEP 2: PRINT RESULTS


Print first element:
print(L[0], end=' ')
Output: 1 


Print middle elements:
for i in range(1, 4):
    print(L[i], end=' ')
# i=1: print(3, end=' ')  → Output: 3 
# i=2: print(12, end=' ') → Output: 12 
# i=3: print(60, end=' ') → Output: 60 


Print last element:
print(L[-1])
Output: 5


FINAL OUTPUT:
1 3 12 60 5


==================================
📊 KEY POINTS
==================================================


IMPORTANT: Updates are done sequentially
- When updating L[i], previous updates are used
- Not using original array values
- Each update affects the next calculation


FIRST ELEMENT:
- Index 0
- NO previous element
- Stays unchanged


MIDDLE ELEMENTS:
- Index 1 to n-2
- Updated with: L[i-1] * L[i+1]
- Uses updated values from previous iterations


LAST ELEMENT:
- Index n-1
- NO next element
- Stays unchanged


LOOP RANGE: range(1, n-1)
- Starts at index 1
- Ends before index n-1
- Skips first and last


==================================================
🔄 FLOW DIAGRAM
==================================================


INPUT: Array [1, 2, 3, 4, 5]


Step 1: Print first element
        Output: 1 


Step 2: Loop i=1 to n-2
        Update L[1] = L[0] * L[2] = 1 * 3 = 3
        Print: 3 


Step 3: Continue loop i=2
        Update L[2] = L[1] * L[3] = 3 * 4 = 12
        Print: 12 


Step 4: Continue loop i=3
        Update L[3] = L[2] * L[4] = 12 * 5 = 60
        Print: 60 


Step 5: Print last element
        Output: 5


FINAL: 1 3 12 60 5


==================================================
✅ FINAL COMPLETE CODE
==================================================


# Take array size
n = int(input())


# Take array elements
L = [int(i) for i in input().split()]


# Print first element (unchanged)
print(L[0], end=' ')


# Update and print middle elements
for i in range(1, n-1):
    # Update element = previous * next
    L[i] = L[i-1] * L[i+1]
    # Print updated element
    print(L[i], end=' ')


# Print last element (unchanged)
print(L[-1])


EXECUTION EXAMPLES:


Input: n=5, L=[1,2,3,4,5]
Output: 1 3 12 60 5


Input: n=4, L=[2,3,4,5]
Output: 2 8 40 5


Input: n=6, L=[1,2,3,4,5,6]
Output: 1 3 12 60 360 6


==================================================
==================================================
LBP165 - THIRD LARGEST AND SECOND SMALLEST
==================================================


📚 PROBLEM STATEMENT
==================================================


PROBLEM:
Given an integer array and integer N (array length).
Find the sum of:
- Third largest element
- Second smallest element


TASK:
Return: third_largest + second_smallest


EXAMPLE:
Input:  [1, 5, 3, 8, 2, 9, 4]
Sorted: [1, 2, 3, 4, 5, 8, 9]
Third largest = 5 (sorted[n-3] = sorted[4] = 5)
Second smallest = 2 (sorted[1] = 2)
Output: 5 + 2 = 7


==================================================
📋 INPUT/OUTPUT SPECIFICATION
==================================================


INPUT:
- Line 1: Size of array (n)
- Line 2: Array elements (space separated)


Example:
7
1 5 3 8 2 9 4


OUTPUT:
- Single integer (sum of third largest + second smallest)


Example:
7


CONSTRAINT:
- No specific constraint mentioned


==================================================
💻 SYNTAX AND LOGIC
==================================================


LOGIC:
1. Sort the array
2. Find third largest: sorted_array[n-3]
3. Find second smallest: sorted_array[1]
4. Return: sorted_array[n-3] + sorted_array[1]


SYNTAX:
n = int(input())
L = [int(i) for i in input().split()]
L.sort()
print(L[n-3] + L[1])


OR SIMPLER:
n = int(input())
L = [int(i) for i in input().split()]
L.sort()
print(L[-3] + L[1])


==================================================
✅ COMPLETE CODE WITH COMMENTS
==================================================


# STEP 1: Take input
# ══════════════════


# Read array size
n = int(input())
# Example: n = 7


# Read array elements
L = [int(i) for i in input().split()]
# Example: L = [1, 5, 3, 8, 2, 9, 4]


# STEP 2: Sort array
# ══════════════════


L.sort()
# Sort in ascending order
# L = [1, 2, 3, 4, 5, 8, 9]
# Index: 0  1  2  3  4  5  6


# STEP 3: Find third largest
# ═══════════════════════════


# Third largest = L[n-3]
# Index n-3 = 7-3 = 4
# L[4] = 5 ✓ (third largest)
# 
# Why L[n-3]?
# Last element L[n-1] = 9 (largest)
# L[n-2] = 8 (second largest)
# L[n-3] = 5 (third largest)


# STEP 4: Find second smallest
# ═════════════════════════════


# Second smallest = L[1]
# L[0] = 1 (smallest)
# L[1] = 2 (second smallest) ✓
#
# Why L[1]?
# First element L[0] = 1 (smallest)
# Second element L[1] = 2 (second smallest)


# STEP 5: Calculate and print sum
# ════════════════════════════════


result = L[n-3] + L[1]
# result = L[4] + L[1]
# result = 5 + 2
# result = 7


print(result)
# Output: 7


==================================================
🔢 EXAMPLE 1 - DETAILED EXECUTION
==================================================


INPUT:
7
1 5 3 8 2 9 4


SETUP:
n = 7
L = [1, 5, 3, 8, 2, 9, 4]


STEP 1: Sort array
L.sort()
L = [1, 2, 3, 4, 5, 8, 9]
     0  1  2  3  4  5  6  (indices)


STEP 2: Find third largest
third_largest = L[n-3]
index = 7 - 3 = 4
L[4] = 5 ✓


Explanation:
- L[6] = 9 (largest)
- L[5] = 8 (second largest)
- L[4] = 5 (THIRD LARGEST) ✓


STEP 3: Find second smallest
second_smallest = L[1]
L[1] = 2 ✓


Explanation:
- L[0] = 1 (smallest)
- L[1] = 2 (SECOND SMALLEST) ✓


STEP 4: Calculate sum
sum = L[n-3] + L[1]
sum = 5 + 2
sum = 7


OUTPUT: 7


==================================================
📊 ARRAY INDEXING EXPLANATION
==================================================


For sorted array L with n elements:


LARGEST ELEMENTS (from end):
- L[n-1] or L[-1] = Largest
- L[n-2] or L[-2] = Second Largest
- L[n-3] or L[-3] = THIRD LARGEST ✓


SMALLEST ELEMENTS (from start):
- L[0] = Smallest
- L[1] = SECOND SMALLEST ✓
- L[2] = Third Smallest


EXAMPLE: L = [1, 2, 3, 4, 5, 8, 9]
         n = 7


Third largest:
- L[n-3] = L[4] = 5 ✓
- OR L[-3] = L[4] = 5 ✓


Second smallest:
- L[1] = 2 ✓


==================================================
🔄 FLOW DIAGRAM
==================================================


INPUT: [1, 5, 3, 8, 2, 9, 4]


Step 1: Read input
        n = 7
        L = [1, 5, 3, 8, 2, 9, 4]


Step 2: Sort array
        L = [1, 2, 3, 4, 5, 8, 9]


Step 3: Find third largest
        L[n-3] = L[4] = 5


Step 4: Find second smallest
        L[1] = 2


Step 5: Sum them
        5 + 2 = 7


OUTPUT: 7


==================================================
✅ FINAL COMPLETE CODE
==================================================


# Read array size
n = int(input())


# Read array elements
L = [int(i) for i in input().split()]


# Sort array in ascending order
L.sort()


# Third largest: L[n-3]
# Second smallest: L[1]
# Print their sum
print(L[n-3] + L[1])


EXECUTION EXAMPLES:


Input: n=7, L=[1,5,3,8,2,9,4]
Sorted: [1, 2, 3, 4, 5, 8, 9]
L[4] + L[1] = 5 + 2 = 7
Output: 7


Input: n=5, L=[10,20,30,40,50]
Sorted: [10, 20, 30, 40, 50]
L[2] + L[1] = 30 + 20 = 50
Output: 50


Input: n=6, L=[5,2,8,1,9,3]
Sorted: [1, 2, 3, 5, 8, 9]
L[3] + L[1] = 5 + 2 = 7
Output: 7


==================================================
💡 WHY THIS LOGIC WORKS?
==================================================


SORTING:
- Arranges array in ascending order
- Smallest to largest


THIRD LARGEST:
- After sorting, largest elements are at end
- Last element: L[-1] or L[n-1]
- Second last: L[-2] or L[n-2]
- Third last: L[-3] or L[n-3] ✓


SECOND SMALLEST:
- After sorting, smallest elements are at start
- First element: L[0]
- Second element: L[1] ✓


EXAMPLE:
Original: [1, 5, 3, 8, 2, 9, 4]
Sorted:   [1, 2, 3, 4, 5, 8, 9]
          ↑  ↑                 ↑  ↑  ↑
          |  |                    |  |  |
          |  second smallest             |        |                    largest
          |                                                 |  second largest
          smallest                             third largest


==================================================
==================================================
LBP166 - SALES REPORT
==================================================


📚 PROBLEM STATEMENT
==================================================


PROBLEM:
A company has a sales record of N products for M days.
The company wants to know the maximum revenue received 
from a given product of the N products each day.


TASK:
Find the highest revenue received each day.


WHAT TO DO:
- For each day, find maximum revenue among all products
- Print maximum revenue for each day


EXAMPLE:
N=3 products, M=4 days
Day 1: [100, 200, 150] → max = 200
Day 2: [300, 250, 280] → max = 300
Day 3: [150, 180, 160] → max = 180
Day 4: [400, 350, 380] → max = 400


Output: 200 300 180 400


==================================================
📋 INPUT/OUTPUT SPECIFICATION
==================================================


INPUT:
- Line 1: N and M (space separated)
  N = number of products
  M = number of days
- Next M lines: Revenue of N products for each day


Example:
3 4
100 200 150
300 250 280
150 180 160
400 350 380


OUTPUT:
- M space separated integers
- Maximum revenue for each day


Example:
200 300 180 400


CONSTRAINT:
- No specific constraint mentioned


==================================================
💻 SYNTAX AND LOGIC
==================================================


LOGIC:
1. Read N (products) and M (days)
2. For each day (M iterations):
   - Read revenues of N products
   - Find maximum revenue
   - Print maximum
3. Space separate output with end=' '


SYNTAX:
n, m = (int(i) for i in input().split())


for i in range(m):
    L = [int(i) for i in input().split()]
    print(max(L), end=' ')


==================================================
✅ COMPLETE CODE WITH COMMENTS
==================================================


# STEP 1: Read N and M
# ════════════════════


# Read N (products) and M (days)
n, m = (int(i) for i in input().split())
# Example: n = 3 (products), m = 4 (days)


# STEP 2: Loop for each day
# ═════════════════════════


for i in range(m):
    # i = 0, 1, 2, ..., m-1
    # Process each day one by one

    # Read revenues for all N products
    L = [int(i) for i in input().split()]
    # Example (Day 1): L = [100, 200, 150]
    # Example (Day 2): L = [300, 250, 280]

    # Find maximum revenue for this day
    max_revenue = max(L)
    # Example (Day 1): max(L) = 200
    # Example (Day 2): max(L) = 300

    # Print maximum with space separator
    print(max_revenue, end=' ')
    # Output: 200 300 180 400


# Note: end=' ' prints space instead of newline
# So all numbers print on same line with spaces


==================================================
🔢 EXAMPLE 1 - DETAILED EXECUTION
==================================================


INPUT:
3 4
100 200 150
300 250 280
150 180 160
400 350 380


SETUP:
n = 3 (3 products)
m = 4 (4 days)


STEP 1: Loop iteration 1 (Day 1)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


for i in range(4):
    # i = 0 (first day)

    L = [int(i) for i in input().split()]
    # Read Day 1 revenues
    # L = [100, 200, 150]

    max_revenue = max(L)
    # max([100, 200, 150])
    # Compare: 100 vs 200 vs 150
    # Maximum = 200

    print(max_revenue, end=' ')
    # Output: 200 


STEP 2: Loop iteration 2 (Day 2)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


for i in range(4):
    # i = 1 (second day)

    L = [int(i) for i in input().split()]
    # Read Day 2 revenues
    # L = [300, 250, 280]

    max_revenue = max(L)
    # max([300, 250, 280])
    # Compare: 300 vs 250 vs 280
    # Maximum = 300

    print(max_revenue, end=' ')
    # Output: 300 


STEP 3: Loop iteration 3 (Day 3)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


for i in range(4):
    # i = 2 (third day)

    L = [int(i) for i in input().split()]
    # Read Day 3 revenues
    # L = [150, 180, 160]

    max_revenue = max(L)
    # max([150, 180, 160])
    # Compare: 150 vs 180 vs 160
    # Maximum = 180

    print(max_revenue, end=' ')
    # Output: 180 


STEP 4: Loop iteration 4 (Day 4)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


for i in range(4):
    # i = 3 (fourth day)

    L = [int(i) for i in input().split()]
    # Read Day 4 revenues
    # L = [400, 350, 380]

    max_revenue = max(L)
    # max([400, 350, 380])
    # Compare: 400 vs 350 vs 380
    # Maximum = 400

    print(max_revenue, end=' ')
    # Output: 400 


LOOP ENDS


FINAL OUTPUT:
200 300 180 400
==================================================
📊 DATA STRUCTURE VISUALIZATION
==================================================


EXAMPLE 1:


Products: P1, P2, P3
Days: D1, D2, D3, D4


        P1   P2   P3
D1:     100  200  150  → max = 200
D2:     300  250  280  → max = 300
D3:     150  180  160  → max = 180
D4:     400  350  380  → max = 400


Output: 200 300 180 400


EXAMPLE 2:


Products: P1, P2, P3, P4
Days: D1, D2, D3


         P1   P2   P3   P4
D1:      100  200  150  180  → max = 200
D2:      250  220  280  260  → max = 280
D3:      300  320  310  290  → max = 320


Output: 200 280 320


==================================================
🔄 FLOW DIAGRAM
==================================================


START
  ↓
Read N and M
  ↓
For each day (i = 0 to m-1):
  ├─ Read revenues of N products
  ├─ Find max revenue
  ├─ Print max with space
  └─ Move to next day
  ↓
END


Example:
Input: n=3, m=4
       100 200 150
       300 250 280
       150 180 160
       400 350 380


Process:
Day 1: [100,200,150] → max=200 → print "200 "
Day 2: [300,250,280] → max=300 → print "300 "
Day 3: [150,180,160] → max=180 → print "180 "
Day 4: [400,350,380] → max=400 → print "400 "


Output: 200 300 180 400 


==================================================
💡 KEY POINTS
==================================================


WHAT IS max()?
- Built-in Python function
- Finds maximum element in list
- Returns largest value


EXAMPLE:
max([100, 200, 150]) = 200
max([300, 250, 280]) = 300
max([75, 100, 95]) = 100


SPACE SEPARATOR:
- end=' ' prints space instead of newline
- All output on same line
- 200 300 180 400 (all on one line)


TIME COMPLEXITY:
- For each day: O(n) to find max
- Total: O(m*n)
- Where n = products, m = days


==================================================
==================================================
LBP167 - ONLINE GAME (TRAILING ZEROS IN FACTORIAL)
==================================================


📚 PROBLEM STATEMENT
==================================================


PROBLEM:
You are playing an online game. In the game, a number 
is displayed on the screen. In order to win the game, 
you have to count the trailing zeros in the factorial 
value of the given number.


TASK:
Count trailing zeros in the factorial of given number.


WHAT ARE TRAILING ZEROS?
- Zeros at the end of a number
- Example: 5! = 120 → 1 trailing zero
- Example: 10! = 3628800 → 2 trailing zeros
- Example: 25! = 15511210043330985984000000 → 6 trailing zeros


EXAMPLE:
Input: 5
5! = 1 × 2 × 3 × 4 × 5 = 120
Trailing zeros = 1


Input: 10
10! = 3628800
Trailing zeros = 2


Input: 25
25! = 15511210043330985984000000
Trailing zeros = 6


==================================================
💡 WHAT CAUSES TRAILING ZEROS?
==================================================


TRAILING ZEROS = FACTORS OF 10
10 = 2 × 5


In factorial:
- Many even numbers (factors of 2)
- Fewer multiples of 5 (factors of 5)
- So we count factors of 5


EXAMPLE: 5!
5! = 1 × 2 × 3 × 4 × 5
Factors of 5: Only one 5
Factors of 2: 2, 4 (plenty)
Pairs of (2,5): 1 pair → 1 trailing zero ✓


EXAMPLE: 25!
Factors of 5:
- 5, 10, 15, 20, 25 (but 25 has two 5s)
- Count: ⌊25/5⌋ + ⌊25/25⌋ = 5 + 1 = 6
Trailing zeros = 6 ✓


==================================================
💻 SYNTAX AND APPROACH
==================================================


APPROACH 1: Calculate factorial and count zeros
- Not efficient for large numbers
- Factorial becomes very large


APPROACH 2: Count factors of 5 (RECOMMENDED)
- Divide by 5, 25, 125, etc.
- Formula: ⌊n/5⌋ + ⌊n/25⌋ + ⌊n/125⌋ + ...


SYNTAX:
count = 0
while n != 0:
    n = n // 5
    count += n


==================================================
✅ METHOD 1: EFFICIENT APPROACH (RECOMMENDED)
==================================================


# LOGIC:
# Count factors of 5 in n!
# n/5 gives multiples of 5
# n/25 gives multiples of 25 (extra factor of 5)
# n/125 gives multiples of 125 (another extra 5)
# etc.


def count_trailing_zeros(n):
    # STEP 1: Initialize count
    count = 0
    # count = 0

    # STEP 2: Loop to count factors of 5
    while n != 0:
        # Divide n by 5
        n = n // 5
        # n = 25 // 5 = 5 → count += 5 → count = 5
        # n = 5 // 5 = 1 → count += 1 → count = 6
        # n = 1 // 5 = 0 → loop ends

        # Add quotient to count
        count += n
        # count = 5 + 1 = 6

    # STEP 3: Return count
    return count


# Read input
num = int(input())
# Example: num = 25


# Call function and print result
print(count_trailing_zeros(num))
# Output: 6


==================================================
✅ METHOD 2: MATHEMATICAL APPROACH
==================================================


# Direct formula approach
# Trailing zeros = ⌊n/5⌋ + ⌊n/25⌋ + ⌊n/125⌋ + ...


count = 0
n = int(input())
original_n = n


# Count multiples of 5, 25, 125, etc.
while n >= 5:
    n = n // 5
    count += n


print(count)


==================================================
🔢 EXAMPLE 1 - DETAILED EXECUTION (n=5)
==================================================


INPUT: 5


CALCULATION:
5! = 1 × 2 × 3 × 4 × 5 = 120


Trailing zeros in 120?
120 = 120 (ends with one zero) → 1 trailing zero ✓


ALGORITHM EXECUTION:


def count_trailing_zeros(n):
    count = 0

    while n != 0:
        n = n // 5
        count += n


Trace:
Initial: n = 5, count = 0


Iteration 1:
  n = 5 // 5 = 1
  count += 1 → count = 0 + 1 = 1


Iteration 2:
  n = 1 // 5 = 0
  while condition: 0 != 0? NO → exit loop


Final: count = 1


OUTPUT: 1 ✓




==================================================
LBP168 - ARRAY PALINDROME
==================================================


📚 PROBLEM STATEMENT
==================================================


PROBLEM:
Implement a program to check whether an array is 
palindrome or not.


TASK:
Check if array reads same forwards and backwards.
Return: true or false


WHAT IS ARRAY PALINDROME?
- Array is palindrome if it reads same both ways
- Compare first with last, second with second-last, etc.
- Example: [1, 2, 3, 2, 1] → palindrome ✓
- Example: [1, 2, 3, 4, 5] → not palindrome ✗


EXAMPLE:
Input:  [1, 2, 3, 2, 1]
Output: true (reads same forwards and backwards)


Input:  [1, 2, 3, 4, 5]
Output: false (not palindrome)


Input:  [5, 4, 3, 4, 5]
Output: true


==================================================
📋 INPUT/OUTPUT SPECIFICATION
==================================================


INPUT:
- Line 1: Size of array (n)
- Line 2: Array elements (space separated)


Example:
5
1 2 3 2 1


OUTPUT:
- true (if palindrome)
- false (if not palindrome)


Example:
true


CONSTRAINT:
- No specific constraint mentioned


==================================================
💻 SYNTAX AND LOGIC
==================================================


LOGIC 1: Compare L with reversed L
L == L[::-1]
- Reverse array using slicing
- Compare with original
- If equal → palindrome


LOGIC 2: Two pointer approach
- Compare L[i] with L[n-1-i]
- Loop from 0 to n//2
- If any mismatch → not palindrome


SYNTAX:
n = int(input())
L = [int(i) for i in input().split()]
print('true' if L == L[::-1] else 'false')


==================================================
✅ METHOD 1: SLICING APPROACH (SIMPLEST)
==================================================


# STEP 1: Read input
# ══════════════════


n = int(input())
# Example: n = 5


L = [int(i) for i in input().split()]
# Example: L = [1, 2, 3, 2, 1]


# STEP 2: Check palindrome
# ════════════════════════


# Create reversed array
L_reversed = L[::-1]
# L[::-1] reverses the array
# [1, 2, 3, 2, 1][::-1] = [1, 2, 3, 2, 1]


# Compare original with reversed
if L == L_reversed:
    result = 'true'
else:
    result = 'false'


# Or in one line:
result = 'true' if L == L[::-1] else 'false'


# STEP 3: Print result
# ════════════════════


print(result)
# Output: true


==================================================
✅ METHOD 2: TWO POINTER APPROACH
==================================================


# STEP 1: Read input
# ══════════════════


n = int(input())
L = [int(i) for i in input().split()]


# STEP 2: Check palindrome
# ════════════════════════


is_palindrome = True


# Compare elements from start and end
for i in range(n // 2):
    # i = 0, 1, 2, ...
    # Compare L[i] with L[n-1-i]

    if L[i] != L[n-1-i]:
        # Mismatch found
        is_palindrome = False
        break


# STEP 3: Print result
# ════════════════════


if is_palindrome:
    print('true')
else:
    print('false')


==================================================
✅ METHOD 3: WHILE LOOP APPROACH
==================================================


# STEP 1: Read input
# ══════════════════


n = int(input())
L = [int(i) for i in input().split()]


# STEP 2: Check palindrome
# ════════════════════════


i = 0
j = n - 1
is_palindrome = True


while i < j:
    # Compare from both ends moving inward

    if L[i] != L[j]:
        # Mismatch found
        is_palindrome = False
        break

    i += 1
    j -= 1


# STEP 3: Print result
# ════════════════════


print('true' if is_palindrome else 'false')


==================================================
🔢 EXAMPLE 1 - PALINDROME (METHOD 1)
==================================================


INPUT:
5
1 2 3 2 1


SETUP:
n = 5
L = [1, 2, 3, 2, 1]
     0  1  2  3  4


EXECUTION:


Step 1: Create reversed array
L[::-1] reverses L
[1, 2, 3, 2, 1][::-1]
Reading backwards:
Position 4: 1
Position 3: 2
Position 2: 3
Position 1: 2
Position 0: 1
L_reversed = [1, 2, 3, 2, 1]


Step 2: Compare
L == L_reversed?
[1, 2, 3, 2, 1] == [1, 2, 3, 2, 1]?
YES ✓ → is palindrome


Step 3: Check condition
if L == L[::-1]:
    result = 'true'
else:
    result = 'false'


Result = 'true'


OUTPUT: true ✓


==================================================
🔢 EXAMPLE 2 - NOT PALINDROME (METHOD 1)
==================================================


INPUT:
5
1 2 3 4 5


SETUP:
n = 5
L = [1, 2, 3, 4, 5]


EXECUTION:


Step 1: Create reversed array
L[::-1] = [5, 4, 3, 2, 1]


Step 2: Compare
L == L_reversed?
[1, 2, 3, 4, 5] == [5, 4, 3, 2, 1]?
NO ✗ → not palindrome


Step 3: Check condition
if L == L[::-1]:
    result = 'true'
else:
    result = 'false'


Result = 'false'


OUTPUT: false ✓


==================================================
🔢 EXAMPLE 3 - TWO POINTER APPROACH
==================================================


INPUT:
7
1 2 3 4 3 2 1


SETUP:
n = 7
L = [1, 2, 3, 4, 3, 2, 1]
     0  1  2  3  4  5  6


EXECUTION:


is_palindrome = True


for i in range(7 // 2):  # i = 0, 1, 2, 3
    # Compare L[i] with L[n-1-i]


    ITERATION 1: i = 0
    ─────────────────────
    Compare: L[0] vs L[7-1-0] = L[6]
    L[0] = 1, L[6] =  = [1, 2, 3, 2, 1]


STEP 1: Reverse array
L[::-1] means reverse
Start from end: -1, -2, -3, -4, -5
[1, 2, 3, 2, 1][::-1]
= [1, 2, 3, 2, 1] (reversed)


STEP 2: Compare
L = [1, 2, 3, 2, 1]
L[::-1] = [1, 2, 3, 2, 1]


Check: L == L[::-1]?
[1, 2, 3, 2, 1] == [1, 2, 3, 2, 1]? YES ✓


STEP 3: Print result
print('true' if YES else 'false')
Output: true ✓


EXPLANATION:
Palindrome check:
Position 0: L[0] = 1, L[-1] = 1 ✓
Position 1: L[1] = 2, L[-2] = 2 ✓
Position 2: L[2] = 3, L[-3] = 3 ✓
All match → Palindrome ✓




==================================================
🔄 FLOW DIAGRAM
==================================================


INPUT: Array L, size n


Method 1:
┌─────────────────┐
│ Read L and n    │
└────────┬────────┘
         ↓
┌─────────────────┐
│ Create reversed │
│ array L[::-1]   │
└────────┬────────┘
         ↓
┌─────────────────┐
│ L == L[::-1]?   │
└────┬────────┬───┘
     YES      NO
     ↓        ↓
   true    false


Method 2:
┌─────────────────┐
│ Read L and n    │
└────────┬────────, 3, 2, 1] ✓


L = ['a', 'b', 'c']
L[::-1] = ['c', 'b', 'a'] ✓


==================================================
✅ METHOD 2: MANUAL COMPARISON (TWO POINTERS)
==================================================


# Alternative approach using two pointers
n = int(input())
L = [int(i) for i in input().split()]


is_palindrome = True


# Compare first with last, second with second-last, etc.
for i in range(n // 2):
    # i goes from 0 to middle

    if L[i] != L[n-1-i]:
        # Compare L[i] with L[n-1-i]
        # L[0] with L[4]
        # L[1] with L[3]

        is_palindrome = False
        break


if is_palindrome:
    print('true')
else:
    print('false')


EXECUTION EXAMPLE (n=5, L=[1,2,3,2,1]):


Loop: i = 0 to 2 (n//2 = 2)


i=0: L[0] != L[5-1-0]? → 1 != 1? NO → Continue
i=1: L[1] != L[5-1-1]? → 2 != 2? NO → Continue


is_palindrome = True → print('true') ✓


==================================================
✅ METHOD 3: USING STRING COMPARISON
==================================================


# Convert array to string and compare
n = int(input())
L = [int(i) for i in input().split()]


# Convert to string
s = ''.join(map(str, L))
# [1, 2, 3, 2, 1] → "12321"


# Check if string is palindrome
if s == s[::-1]:
    print('true')
else:
    print('false')


==================================================
📊 COMPARISON OF METHODS
==================================================


METHOD 1: L == L[::-1]
- Pros: Simple, concise, readable
- Cons: Uses extra space (creates reversed copy)
- Time: O(n), Space: O(n)
- BEST FOR: Simple solution, small arrays


METHOD 2: Two pointers loop
- Pros: No extra space, efficient
- Cons: More code, less readable
- Time: O(n), Space: O(1)
- BEST FOR: Large arrays, space-critical


METHOD 3: String comparison
- Pros: Also simple
- Cons: Extra conversion step
- Time: O(n), Space: O(n)
- BEST FOR: Mixed approach


RECOMMENDATION: Use Method 1 (L == L[::-1])
Simple, readable, and efficient enough!


==================================================
✅ FINAL COMPLETE CODE
==================================================


# SIMPLE METHOD (RECOMMENDED)
n = int(input())
L = [int(i) for i in input().split()]
print('true' if L == L[::-1] else 'false')


---


# ALTERNATIVE METHOD (TWO POINTERS)
n = int(input())
L = [int(i) for i in input().split()]


is_palindrome = True
for i in range(n // 2):
    if L[i] != L[n-1-i]:
        is_palindrome = False
        break


print('true' if is_palindrome else 'false')


---


# ALTERNATIVE METHOD (STRING)
n = int(input())
L = [int(i) for i in input().split()]
s = ''.join(map(str, L))
print('true' if s == s[::-1] else 'false')


EXECUTION EXAMPLES:


Input: 5 and 1 2 3 2 1
Output: true


Input: 5 and 1 2 3 4 5
Output: false


Input: 7 and 5 4 3 2 3 4 5
Output: true


Input: 4 and 7 7 7 7
Output: true


Input: 1 and 5
Output: true


Input: 2 and 1 2
Output: false




==================================================
==================================================
LBP169 - ARRAY TO MATRIX
==================================================


📚 PROBLEM STATEMENT
==================================================


PROBLEM:
Implement a program to convert an array into a matrix.


CONSTRAINT:
Element count should be perfect squares: 1, 4, 9, 16, 25...
(n = m × m, where m is integer)


WHAT IS THIS?
- Convert 1D array into 2D matrix (square matrix)
- Array size must be perfect square
- Create m × m matrix where m = √n


EXAMPLES:


Example 1:
Array: [1, 2, 3, 4]
Size: 4 = 2 × 2
Matrix:
1 2
3 4


Example 2:
Array: [1, 2, 3, 4, 5, 6, 7, 8, 9]
Size: 9 = 3 × 3
Matrix:
1 2 3
4 5 6
7 8 9


Example 3:
Array: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
Size: 16 = 4 × 4
Matrix:
1 2 3 4
5 6 7 8
9 10 11 12
13 14 15 16


==================================================
📋 INPUT/OUTPUT SPECIFICATION
==================================================


INPUT:
- Line 1: Array size N
- Line 2: Array elements (space separated)


Example 1:
4
1 2 3 4


Example 2:
9
1 2 3 4 5 6 7 8 9


OUTPUT:
- 2D Matrix (m × m) with space between elements
- Each row on new line


Example 1 Output:
1 2
3 4


Example 2 Output:
1 2 3
4 5 6
7 8 9


CONSTRAINT:
- Element count must be perfect square (1, 4, 9, 16, 25...)




✅ COMPLETE CODE WITH COMMENTS
==================================================


# STEP 1: Import math module
# ═════════════════════════════


import math
# Need math.sqrt() for square root


# STEP 2: Read array size
# ════════════════════════


n = int(input())
# Read array size N
# Example: n = 4


# STEP 3: Read array elements
# ════════════════════════════


L = [int(i) for i in input().split()]
# Read N elements from input
# Example: L = [1, 2, 3, 4]


# STEP 4: Calculate matrix dimension
# ═══════════════════════════════════


m = int(math.sqrt(n))
# Calculate m = √n
# √4 = 2, so m = 2
# √9 = 3, so m = 3
# √16 = 4, so m = 4


# STEP 5: Create and print matrix
# ════════════════════════════════


k = 0
# k tracks current position in array L


for i in range(m):
    # i = 0, 1, 2, ... m-1 (for each row)
    # i represents row number

    for j in range(m):
        # j = 0, 1, 2, ... m-1 (for each column)
        # j represents column number

        # Print element at position k in array
        print(L[k], end=' ')
        # print element with space (no newline)
        # L[0]=1, L[1]=2, L[2]=3, L[3]=4

        # Move to next element
        k = k + 1
        # k: 0→1→2→3

    # After each row, print newline
    print()
    # Moves to next row


==================================================
🔢 EXAMPLE 1 - DETAILED EXECUTION (4 ELEMENTS)
==================================================


INPUT:
4
1 2 3 4


SETUP:
n = 4
L = [1, 2, 3, 4]
m = √4 = 2


Matrix will be 2 × 2


EXECUTION:


k = 0


OUTER LOOP: i = 0 (Row 0)
├─ INNER LOOP: j = 0 (Column 0)
│  print(L[0], end=' ') → print(1, end=' ')
│  Output: 1 
│  k = 0 + 1 = 1
│
├─ INNER LOOP: j = 1 (Column 1)
│  print(L[1], end=' ') → print(2, end=' ')
│  Output: 1 2 
│  k = 1 + 1 = 2
│
└─ print() → newline
   Output:
   1 2


OUTER LOOP: i = 1 (Row 1)
├─ INNER LOOP: j = 0 (Column 0)
│  print(L[2], end=' ') → print(3, end=' ')
│  Output: 1 2
│          3 
│  k = 2 + 1 = 3
│
├─ INNER LOOP: j = 1 (Column 1)
│  print(L[3], end=' ') → print(4, end=' ')
│  Output: 1 2
│          3 4 
│  k = 3 + 1 = 4
│
└─ print() → newline
   Final Output:
   1 2
   3 4


==================================================
LBP170 - MATRIX TO ARRAY
==================================================


📚 PROBLEM STATEMENT
==================================================


PROBLEM:
Implement a program to convert the given matrix 
into a 1D array.


WHAT IS THIS?
- Convert 2D matrix into 1D array
- Read m×n matrix (m rows, n columns)
- Flatten into single 1D array
- Print elements row by row


EXAMPLES:


Example 1:
Matrix (2×2):
1 2
3 4


Array: [1, 2, 3, 4]


Example 2:
Matrix (3×3):
1 2 3
4 5 6
7 8 9


Array: [1, 2, 3, 4, 5, 6, 7, 8, 9]


Example 3:
Matrix (2×3):
1 2 3
4 5 6


Array: [1, 2, 3, 4, 5, 6]


==================================================
📋 INPUT/OUTPUT SPECIFICATION
==================================================


INPUT:
- Line 1: m and n (matrix dimensions)
  m = number of rows
  n = number of columns
- Next m lines: n elements for each row


Example 1:
2 2
1 2
3 4


Example 2:
3 3
1 2 3
4 5 6
7 8 9


Example 3:
2 3
1 2 3
4 5 6


OUTPUT:
- 1D array (space separated)
- All elements on single line or printed row by row


Example 1 Output:
1 2 3 4


Example 2 Output:
1 2 3 4 5 6 7 8 9


Example 3 Output:
1 2 3 4 5 6


==================================================
💻 SYNTAX AND LOGIC
==================================================


LOGIC:
1. Read m and n (matrix dimensions)
2. Create empty list L = []
3. Read m rows of n elements each
4. Append each element to list L
5. Print all elements with spaces


SYNTAX:
n, m = (int(i) for i in input().split())
L = []


for i in range(n):
    L.append([int(i) for i in input().split()])


for i in range(n):
    for j in range(m):
        print(L[i][j], end=' ')


KEY CONCEPTS:
- Read matrix row by row
- Store in 2D list L
- Loop through 2D matrix
- Print each element with space


==================================================
✅ COMPLETE CODE WITH COMMENTS
==================================================


# STEP 1: Read matrix dimensions
# ═══════════════════════════════


n, m = (int(i) for i in input().split())
# Read m (rows) and n (columns)
# Example: n = 2, m = 2 (for 2×2 matrix)


# STEP 2: Create empty list for matrix
# ═════════════════════════════════════


L = []
# L will store 2D matrix
# L = [[1, 2], [3, 4]]


# STEP 3: Read matrix rows
# ═════════════════════════


for i in range(n):
    # i = 0, 1, 2, ... n-1 (for each row)
    # Read one row at a time

    row = [int(i) for i in input().split()]
    # Read n elements from input for this row
    # Example (Row 0): row = [1, 2]
    # Example (Row 1): row = [3, 4]

    L.append(row)
    # Add this row to matrix L
    # After row 0: L = [[1, 2]]
    # After row 1: L = [[1, 2], [3, 4]]


# STEP 4: Print matrix as 1D array
# ═════════════════════════════════


for i in range(n):
    # i = 0, 1, 2, ... n-1 (for each row)

    for j in range(m):
        # j = 0, 1, 2, ... m-1 (for each column)

        # Print element at position [i][j]
        print(L[i][j], end=' ')
        # L[0][0]=1, L[0][1]=2, L[1][0]=3, L[1][1]=4
        # Output: 1 2 3 4 


==================================================
🔢 EXAMPLE 1 - DETAILED EXECUTION (2×2 MATRIX)
==================================================


INPUT:
2 2
1 2
3 4


SETUP:
n = 2 (rows)
m = 2 (columns)
L = []


STEP 1: Read matrix rows


ITERATION 1: i = 0 (First row)
├─ row = [int(i) for i in "1 2".split()]
├─ row = [1, 2]
└─ L.append([1, 2])
   L = [[1, 2]]


ITERATION 2: i = 1 (Second row)
├─ row = [int(i) for i in "3 4".split()]
├─ row = [3, 4]
└─ L.append([3, 4])
   L = [[1, 2], [3, 4]]


STEP 2: Print matrix as 1D array


OUTER LOOP: i = 0 (Row 0)
├─ INNER LOOP: j = 0 (Column 0)
│  print(L[0][0], end=' ')
│  print(1, end=' ')
│  Output: 1 
│
└─ INNER LOOP: j = 1 (Column 1)
   print(L[0][1], end=' ')
   print(2, end=' ')
   Output: 1 2 


OUTER LOOP: i = 1 (Row 1)
├─ INNER LOOP: j = 0 (Column 0)
│  print(L[1][0], end=' ')
│  print(3, end=' ')
│  Output: 1 2 3 
│
└─ INNER LOOP: j = 1 (Column 1)
   print(L[1][1], end=' ')
   print(4, end=' ')
   Output: 1 2 3 4 


FINAL OUTPUT:
1 2 3 4 




==================================================
📊 DATA STRUCTURE VISUALIZATION
==================================================


EXAMPLE 1:


MATRIX (2D):
┌───────────┐
│ 1   2     │
│ 3   4     │
└───────────┘


As 2D List L:
L = [[1, 2], [3, 4]]
    L[0][0] L[0][1]
    L[1][0] L[1][1]


ARRAY (1D):
[1, 2, 3, 4]


EXAMPLE 2:


MATRIX (2D):
┌───────────────┐
│ 1   2   3     │
│ 4   5   6     │
│ 7   8   9     │
└───────────────┘


As 2D List L:
L = [[1,2,3], [4,5,6], [7,8,9]]


ARRAY (1D):
[1, 2, 3, 4, 5, 6, 7, 8, 9]


==================================================
✅ ALTERNATIVE METHOD: USING EXTEND()
==================================================


n, m = (int(i) for i in input().split())
L = []


for i in range(n):
    row = [int(i) for i in input().split()]
    L.extend(row)  # Add all elements from row
    # extend() adds individual elements
    # append() would add entire row as sublist


# Print 1D array
for element in L:
    print(element, end=' ')


EXECUTION EXAMPLE:


Input:
2 2
1 2
3 4


Process:
row = [1, 2]
L.extend([1, 2]) → L = [1, 2]


row = [3, 4]
L.extend([3, 4]) → L = [1, 2, 3, 4]


Output: 1 2 3 4 


==================================================
LBP171 - WORD KEY (KEYWORD CHECK)
==================================================


📚 PROBLEM STATEMENT
==================================================


PROBLEM:
One programming language has the following keywords 
that cannot be used as identifiers:
break, case, continue, default, defer, else, for, 
func, goto, if, map, range, return, struct, type, var


Write a program to find if the given word is a 
keyword or not.


WHAT IS A KEYWORD?
- Reserved words in programming language
- Cannot be used as variable names
- Have special meaning in language
- Examples: break, if, else, for, return, etc.


TASK:
Check if input word is in keyword list
Output: true (if keyword) or false (if not keyword)


EXAMPLES:


Input: break
Keywords list contains "break"
Output: true ✓


Input: class
Keywords list does NOT contain "class"
Output: false ✓


Input: for
Keywords list contains "for"
Output: true ✓


Input: myVariable
Keywords list does NOT contain "myVariable"
Output: false ✓


==================================================
📋 INPUT/OUTPUT SPECIFICATION
==================================================


INPUT:
- Single string (word to check)


Example 1: break
Example 2: class
Example 3: for
Example 4: myVariable


OUTPUT:
- true (if word is keyword)
- false (if word is NOT keyword)


Example 1 Output: true
Example 2 Output: false
Example 3 Output: true
Example 4 Output: false


CONSTRAINT:
- Exact match required (case-sensitive)


==================================================
💻 SYNTAX AND LOGIC
==================================================


LOGIC:
1. Create list of all keywords
2. Read input word
3. Check if word is in keyword list
4. Print true or false


SYNTAX:
L = ["break", "case", "continue", "default", 
     "defer", "else", "for", "func", "goto", 
     "if", "map", "range", "return", "struct", 
     "type", "var"]


s = input()
print('true' if s in L else 'false')


KEY CONCEPTS:
- List contains all keywords
- 'in' operator checks membership
- Case-sensitive comparison
- Conditional print


==================================================
✅ COMPLETE CODE WITH COMMENTS
==================================================


# STEP 1: Create keywords list
# ═════════════════════════════


L = ["break", "case", "continue", "default", 
     "defer", "else", "for", "func", "goto", 
     "if", "map", "range", "return", "struct", 
     "type", "var"]
# List of all keywords


# Keywords:
# break, case, continue, default, defer, else,
# for, func, goto, if, map, range, return,
# struct, type, var


# Total: 16 keywords


# STEP 2: Read input word
# ════════════════════════


s = input()
# Read word from user
# Example: s = "break"


# STEP 3: Check if word is keyword
# ════  ════════════════════════════


print('true' if s in L else 'false')
# Check: is s in keywords list L?
# If YES → print 'true'
# If NO → print 'false'


# 's in L' checks membership
# Returns True or False
# print() converts to 'true' or 'false'


==================================================
🔢 EXAMPLE 1 - DETAILED EXECUTION (KEYWORD)
==================================================


INPUT: break


SETUP:
L = ["break", "case", "continue", "default", 
     "defer", "else", "for", "func", "goto", 
     "if", "map", "range", "return", "struct", 
     "type", "var"]
s = "break"


EXECUTION:


Step 1: Check membership
s in L?
"break" in ["break", "case", ...]?
YES ✓ (first element matches)


Step 2: Conditional expression
'true' if YES else 'false'
Result: 'true'


Step 3: Print
print('true')


OUTPUT: true ✓


==================================================
🔢 EXAMPLE 2 - DETAILED EXECUTION (NOT KEYWORD)
==================================================


INPUT: class


SETUP:
L = ["break", "case", "continue", "default", 
     "defer", "else", "for", "func", "goto", 
     "if", "map", "range", "return", "struct", 
     "type", "var"]
s = "class"


EXECUTION:


Step 1: Check membership
s in L?
"class" in ["break", "case", ...]?
NO ✗ (not in list)


Step 2: Conditional expression
'true' if NO else 'false'
Result: 'false'


Step 3: Print
print('false')


OUTPUT: false ✓


==================================================
🔢 EXAMPLE 3 - DETAILED EXECUTION (KEYWORD)
==================================================


INPUT: for


SETUP:
s = "for"


EXECUTION:


Step 1: Check membership
"for" in L?
Search through list:
- "break" ≠ "for"
- "case" ≠ "for"
- "continue" ≠ "for"
- "default" ≠ "for"
- "defer" ≠ "for"
- "else" ≠ "for"
- "for" = "for" ✓ FOUND!


Step 2: Conditional
'true' if YES else 'false'
Result: 'true'


Step 3: Print
print('true')


OUTPUT: true ✓




==================================================
📊 KEYWORD LIST REFERENCE
==================================================


COMPLETE KEYWORD LIST (16 keywords):


1. break      - Exit loop
2. case       - Switch case
3. continue   - Skip iteration
4. default    - Default case
5. defer      - Defer execution
6. else       - Else condition
7. for        - For loop
8. func       - Function definition
9. goto       - Go to label
10. if        - If condition
11. map       - Map data structure
12. range     - Range function
13. return    - Return statement
14. struct    - Structure definition
15. type      - Type definition
16. var       - Variable declaration


CANNOT BE USED AS:
- Variable names
- Function names
- Class names
- Identifiers


==================================================
✅ ALTERNATIVE METHODS
==================================================


METHOD 1: Using if-in (SIMPLE)
L = ["break", "case", "continue", "default",
     "defer", "else", "for", "func", "goto",
     "if", "map", "range", "return", "struct",
     "type", "var"]
s = input()
print('true' if s in L else 'false')


---


METHOD 2: Using if-elif (LONGER)
s = input()


if s == "break" or s == "case" or s == "continue" \
   or s == "default" or ... or s == "var":
    print('true')
else:
    print('false')


---


METHOD 3: Using set (FASTER for large lists)
keywords = {"break", "case", "continue", "default",
            "defer", "else", "for", "func", "goto",
            "if", "map", "range", "return", "struct",
            "type", "var"}
s = input()
print('true' if s in keywords else 'false')


NOTE: Set lookup is O(1), List lookup is O(n)
For 16 keywords, difference is negligible


---


METHOD 4: Using function
def is_keyword(word):
    keywords = ["break", "case", "continue",
                "default", "defer", "else",
                "for", "func", "goto", "if",
                "map", "range", "return",
                "struct", "type", "var"]
    return 'true' if word in keywords else 'false'


s = input()
print(is_keyword(s))


==================================================
LBP172 - ODDLY EVEN (ODD/EVEN POSITION DIGITS)
==================================================


📚 PROBLEM STATEMENT
==================================================


PROBLEM:
Given a maximum of 100 digit numbers as input,
find the difference between the sum of odd and 
even position digits.


WHAT IS THIS?
- Position = index from left (1-based or 0-based)
- Odd position = 1st, 3rd, 5th, ... (positions 0, 2, 4... in 0-indexed)
- Even position = 2nd, 4th, 6th, ... (positions 1, 3, 5... in 0-indexed)
- Find: |sum_of_odd_position_digits - sum_of_even_position_digits|


EXAMPLES:


Example 1:
Number: 45712
Positions: 1st=4, 2nd=5, 3rd=7, 4th=1, 5th=2
Odd positions (1,3,5): 4+7+2 = 13
Even positions (2,4): 5+1 = 6
Difference: 13-6 = 7 ✓


Example 2:
Number: 01234
Positions: 1st=0, 2nd=1, 3rd=2, 4th=3, 5th=4
Odd positions: 0+2+4 = 6
Even positions: 1+3 = 4
Difference: 6-4 = 2


Example 3:
Number: 45712 → [21754]
(reversed from right to left in example)
Let me recalculate...


Looking at example: 45712 ==> 21754
This suggests we process from RIGHT to LEFT!


Rightmost = position 0 (ODD)
Next left = position 1 (EVEN)
Next left = position 2 (ODD)
etc.


Number: 45712
From right: 2(pos0-odd), 1(pos1-even), 7(pos2-odd), 5(pos3-even), 4(pos4-odd)
Odd positions (0,2,4): 2+7+4 = 13
Even positions (1,3): 1+5 = 6
Difference: 13-6 = 7 ✓
==================================================
💻 SYNTAX AND LOGIC
==================================================
LOGIC:
1. Read number as string
2. Convert string to integer and back (remove leading zeros)
3. Extract digits into list
4. Iterate through list from right to left
5. If position (0-indexed from right) is even → odd position digit
6. If position (0-indexed from right) is odd → even position digit
7. Calculate difference


SYNTAX:
n = input()
n = int(n[:-1])  # Remove last char? (Not clear)
L = []
while n != 0:
    L.append(n % 10)  # Get last digit
    n = n // 10        # Remove last digit


index = 0
se = 0  # sum_even
so = 0  # sum_odd
while index < len(L):
    if index % 2 == 0:
        so += L[index]  # Odd position
    else:
        se += L[index]  # Even position
    index += 1


print(so - se)


==================================================
✅ COMPLETE CODE WITH COMMENTS
==================================================


# STEP 1: Read number as string
# ══════════════════════════════


n = input()
# Read number from user
# Example: n = "45712"


# STEP 2: Convert to integer (remove leading zeros)
# ══════════════════════════════════════════════════


n = int(n)
# Convert string to integer
# "45712" → 45712
# This removes leading zeros if any


# STEP 3: Extract digits into list (reverse order)
# ═════════════════════════════════════════════════


L = []
# List to store digits


while n != 0:
    # Extract digits from right to left

    L.append(n % 10)
    # Get last digit
    # 45712 % 10 = 2
    # 4571 % 10 = 1
    # 457 % 10 = 7
    # 45 % 10 = 5
    # 4 % 10 = 4

    n = n // 10
    # Remove last digit
    # 45712 // 10 = 4571
    # 4571 // 10 = 457
    # etc.


# After loop: L = [2, 1, 7, 5, 4]
# (digits from right to left)


# STEP 4: Calculate sums based on position
# ═════════════════════════════════════════


index = 0
# index tracks position from right (0-indexed)


se = 0
# sum_even = sum of digits at even positions


so = 0
# sum_odd = sum of digits at odd positions


while index < len(L):
    # Loop through all digits

    if index % 2 == 0:
        # Position 0, 2, 4, ... = ODD positions (1st, 3rd, 5th...)
        so += L[index]
        # Add to odd position sum
    else:
        # Position 1, 3, 5, ... = EVEN positions (2nd, 4th, 6th...)
        se += L[index]
        # Add to even position sum

    index += 1


# After loop: so = 2+7+4 = 13
#             se = 1+5 = 6


# STEP 5: Calculate and print difference
# ═══════════════════════════════════════


print(so - se)
# Print: 13 - 6 = 7


==================================================
🔢 EXAMPLE 1 - DETAILED EXECUTION (45712)
==================================================


INPUT: 45712


STEP 1: Read and convert
n = "45712"
n = int("45712") = 45712


STEP 2: Extract digits (right to left)
L = []


Iteration 1:
  L.append(45712 % 10) → L.append(2) → L = [2]
  n = 45712 // 10 = 4571


Iteration 2:
  L.append(4571 % 10) → L.append(1) → L = [2, 1]
  n = 4571 // 10 = 457


Iteration 3:
  L.append(457 % 10) → L.append(7) → L = [2, 1, 7]
  n = 457 // 10 = 45


Iteration 4:
  L.append(45 % 10) → L.append(5) → L = [2, 1, 7, 5]
  n = 45 // 10 = 4


Iteration 5:
  L.append(4 % 10) → L.append(4) → L = [2, 1, 7, 5, 4]
  n = 4 // 10 = 0


Loop ends: L = [2, 1, 7, 5, 4]


VISUALIZATION:
Number: 4 5 7 1 2
Index:  4 3 2 1 0 (0-indexed from right)
        ODD EVEN ODD EVEN ODD (position types)


STEP 3: Calculate sums


index = 0
se = 0, so = 0


index=0: index%2==0? YES → so += L[0]=2 → so=2
index=1: index%2==0? NO → se += L[1]=1 → se=1
index=2: index%2==0? YES → so += L[2]=7 → so=2+7=9
index=3: index%2==0? NO → se += L[3]=5 → se=1+5=6
index=4: index%2==0? YES → so += L[4]=4 → so=9+4=13


Final: so = 13, se = 6


STEP 4: Calculate difference
so - se = 13 - 6 = 7


OUTPUT: 7 ✓


==================================================
COMPLETE PYTHON FUNDAMENTALS & LBP173 GUIDE
==================================================


📚 PART 1: ENUMERATE()
==================================================


DEFINITION:
- Built-in Python function
- Loops through a sequence (list, string, etc.)
- Returns TWO values each iteration:
  1. INDEX (position: 0, 1, 2, ...)
  2. VALUE (element at that position)


SYNTAX:
for index, value in enumerate(sequence):
    # Use index and value


SIMPLE EXAMPLE:


s = "ABC"


for i, char in enumerate(s):
    print(i, char)


OUTPUT:
0 A
1 B
2 C


DETAILED EXECUTION:
──────────────────


ITERATION 1:
  enumerate gives: (0, 'A')
  i = 0, char = 'A'
  print(0, 'A') → Output: 0 A


COMPARISON:
──────────────────
Without enumerate:
  for i in range(len(s)):
      char = s[i]
      print(i, char)


With enumerate:
  for i, char in enumerate(s):
      print(i, char)


Verdict: enumerate is CLEANER! ✓


ENUMERATE WITH START:


s = "ABC"


for i, ch in enumerate(s, start=1):
    print(i, ch)


OUTPUT:
1 A
2 B
3 C
(Counting starts from 1 instead of 0)


WHY USE enumerate()?
- CLEANER CODE
- READABLE
- FASTER (no need to calculate len())
- PYTHONIC (recommended Python style)
- WORKS WITH ANY SEQUENCE


==================================================
📚 PART 2: ORD()
==================================================


DEFINITION:
- Built-in Python function
- Converts a CHARACTER to its ASCII VALUE
- Returns an INTEGER (the ASCII code)


SYNTAX:
ord(character)


RETURNS:
Integer (ASCII value of character)


ASCII (American Standard Code for Information Interchange):
A system to represent characters as numbers


SIMPLE EXAMPLES:


ord('A') = 65
ord('B') = 66
ord('C') = 67
ord('a') = 97
ord('b') = 98
ord('0') = 48
ord('1') = 49
ord(' ') = 32  (space)


USAGE:


x = ord('A')
print(x)
Output: 65


ASCII VALUE TABLE:


UPPERCASE LETTERS:
A = 65, B = 66, C = 67, ..., Z = 90


LOWERCASE LETTERS:
a = 97, b = 98, c = 99, ..., z = 122


DIGITS:
0 = 48, 1 = 49, 2 = 50, ..., 9 = 57


SPECIAL CHARACTERS:
Space = 32, ! = 33, @ = 64, [ = 91, ] = 93


LOOP THROUGH STRING:


s = "ABC"


for char in s:
    ascii_val = ord(char)
    print(char, ascii_val)


OUTPUT:
A 65
B 66
C 67


RELATIONSHIP: ord() and chr()


ord() and chr() are OPPOSITE functions!


ord(char) → ASCII value
chr(ascii) → Character


EXAMPLE:


ord('A') = 65
chr(65) = 'A'


ord('Z') = 90
chr(90) = 'Z'


CONVERSION:


char = 'A'
ascii = ord(char)      # 'A' → 65
char_back = chr(ascii) # 65 → 'A'
print(char_back)       # A


WHY USE ord()?


REASON 1: Convert character to number
  char = 'A'
  num = ord(char)  # Get 65 for operations


REASON 2: Compare characters
  ord('A') < ord('B')  # True (65 < 66)


REASON 3: Convert letter to position (1-26)
  position = ord(char) - ord('A') + 1
  # 'A': 65-65+1 = 1
  # 'B': 66-65+1 = 2
  # 'Z': 90-65+1 = 26


REASON 4: Convert hex/base letter to value (10-16)
  value = ord(char) - ord('A') + 10
  # 'A': 65-65+10 = 10
  # 'B': 66-65+10 = 11
  # 'C': 67-65+10 = 12


REASON 5: Check character type
  if 65 <= ord(char) <= 90:
      print("Uppercase letter")


REAL EXAMPLE: Convert letter to position


char = 'C'
position = ord(char) - ord('A') + 1
# ord('C')=67, ord('A')=65
# 67 - 65 + 1 = 3


print(position)
OUTPUT: 3  (C is 3rd letter)


QUICK REFERENCE:


BASIC:
ord('A') = 65
ord('a') = 97
ord('0') = 48


LETTERS:
'A' to 'Z': 65 to 90 (26 letters)
'a' to 'z': 97 to 122 (26 letters)


DIGITS:
'0' to '9': 48 to 57 (10 digits)


OPPOSITE OF ord():
chr(65) = 'A'
chr(97) = 'a'


==================================================
📚 PART 3: LBP173 - SWEET SEVENTEEN
==================================================


PROBLEM STATEMENT:
──────────────────


PROBLEM:
Given a maximum of four digit number in base 17 
(10⇒A, 11⇒B, 12⇒C, 13⇒D, 14⇒E, 15⇒F, 16⇒G) 
as input, output its decimal value.


WHAT IS THIS?
- Convert from BASE 17 to DECIMAL (BASE 10)
- Base 17 uses: 0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F,G
- Input: number in base 17 (max 4 digits)
- Output: decimal equivalent


CONVERSION FORMULA:
Decimal = (digit₀ × 17^n) + (digit₁ × 17^(n-1)) + ... + (digitₙ × 17^0)


EXAMPLE:
Number: ABC (base 17)
A=10, B=11, C=12
Decimal = 10×17² + 11×17¹ + 12×17⁰
        = 10×289 + 11×17 + 12×1
        = 2890 + 187 + 12
        = 3089


INPUT/OUTPUT:
─────────────


INPUT:
- String value (base 17 number)
- Digits: 0-9, A-G
- Maximum 4 digits


Example: ABC


OUTPUT:
- Integer (decimal value)


Example: 3089


BASE 17 DIGIT MAPPING:
──────────────────────


0  → 0
1  → 1
2  → 2
3  → 3
4  → 4
5  → 5
6  → 6
7  → 7
8  → 8
9  → 9
A  → 10
B  → 11
C  → 12
D  → 13
E  → 14
F  → 15
G  → 16


==================================================
💻 SOLUTION 1: SIMPLE (RECOMMENDED)
==================================================


EXPLANATION:
Python's int() function can convert any base to decimal!


CODE:
────


# Read base 17 number and convert to decimal
n = int(input(), 17)
# int(string, base) converts from any base to decimal
# input() reads the base 17 number
# 17 specifies the base to convert from
# Returns decimal equivalent


# Print the decimal value
print(n)
# Output: decimal value


EXAMPLE EXECUTION:


Input: ABC
int("ABC", 17) converts:
  A=10, B=11, C=12
  10×17² + 11×17¹ + 12×17⁰ = 3089
Output: 3089 ✓


WHY USE THIS?
- Simple (only 2 lines)
- Fast
- Reliable
- Python built-in function


==================================================
💻 SOLUTION 2: MANUAL (EDUCATIONAL)
==================================================


EXPLANATION:
Shows how base conversion works step by step


CODE WITH COMMENTS:
───────────────────


# Read base 17 number as string
s = input()
# Example: s = "ABC"


# Initialize decimal result
decimal = 0
# Will store final decimal value


# Process each digit
for i, char in enumerate(s):
    # i = index (0, 1, 2, ...)
    # char = character at position i

    # Convert character to its decimal value
    if char.isdigit():
        # Character is 0-9
        digit = int(char)
        # '5' → 5
    else:
        # Character is A-G
        digit = ord(char) - ord('A') + 10
        # 'A' → 10, 'B' → 11, ..., 'G' → 16
        # ord('A')=65, so 'A': 65-65+10=10 ✓

    # Calculate power of 17 (from right to left)
    power = len(s) - i - 1
    # For "ABC": len=3
    # i=0: power=2 (leftmost, 17²)
    # i=1: power=1 (middle, 17¹)
    # i=2: power=0 (rightmost, 17⁰)

    # Add digit × 17^power to decimal
    decimal += digit * (17 ** power)
    # "ABC": 10×17² + 11×17¹ + 12×17⁰


# Print the decimal result
print(decimal)


DETAILED EXECUTION (INPUT: ABC):
────────────────────────────────


i=0, char='A': 
  digit = ord('A') - ord('A') + 10 = 0 + 10 = 10
  power = 3 - 0 - 1 = 2
  decimal += 10 × 17² = 10 × 289 = 2890
  decimal = 2890


i=1, char='B': 
  digit = ord('B') - ord('A') + 10 = 1 + 10 = 11
  power = 3 - 1 - 1 = 1
  decimal += 11 × 17¹ = 11 × 17 = 187
  decimal = 2890 + 187 = 3077


i=2, char='C': 
  digit = ord('C') - ord('A') + 10 = 2 + 10 = 12
  power = 3 - 2 - 1 = 0
  decimal += 12 × 17⁰ = 12 × 1 = 12
  decimal = 3077 + 12 = 3089


Output: 3089 ✓


BREAKDOWN OF ord(char) - ord('A') + 10:


Step 1: ord(char) gets ASCII value of character
  ord('C') = 67


Step 2: ord('A') gets ASCII value of 'A'
  ord('A') = 65


Step 3: Subtract to find position difference
  67 - 65 = 2 (C is 2 positions after A)


Step 4: Add 10 (because A represents 10 in base 17)
  2 + 10 = 12 ✓


This works for all letters:
  A: 65-65+10 = 0+10 = 10 ✓
  B: 66-65+10 = 1+10 = 11 ✓
  C: 67-65+10 = 2+10 = 12 ✓
  D: 68-65+10 = 3+10 = 13 ✓
  E: 69-65+10 = 4+10 = 14 ✓
  F: 70-65+10 = 5+10 = 15 ✓
  G: 71-65+10 = 6+10 = 16 ✓




==================================================
✅ FINAL CODE (CHOOSE ONE)
==================================================


OPTION 1: SIMPLE (RECOMMENDED)
───────────────────────────────
# Take input from user
# Input is assumed to be a number in BASE 17 (hex-like system but up to G)
# Syntax:- int(value, base)
# value → input number (string)
# base → the number system of that input (here, 17)


n = int(input(), 17)


# Convert the base-17 number into decimal (base-10)
# and store in variable n


# Print the converted decimal number
print(n)


───────────────────────────────


OPTION 2: MANUAL (EDUCATIONAL)
───────────────────────────────


s = input()
decimal = 0


for i, char in enumerate(s):
    if char.isdigit():
        digit = int(char)
    else:
        digit = ord(char) - ord('A') + 10

    power = len(s) - i - 1
    decimal += digit * (17 ** power)


print(decimal)


Use this to understand how it works!


==================================================
💡 KEY CONCEPTS SUMMARY
==================================================


ENUMERATE():
- Gives both index and value
- Cleaner than using range(len())
- Works with any sequence


ORD():
- Converts character to ASCII value
- 'A'=65, 'B'=66, ..., 'Z'=90
- 'a'=97, 'b'=98, ..., 'z'=122
- '0'=48, '1'=49, ..., '9'=57


BASE 17 CONVERSION:
- Use int(string, 17) for simple solution
- Manual solution uses enumerate(), ord(), and power calculation
- Formula: digit × 17^power for each position


==================================================
==================================================
LBP174 - BEAUTIFYME
==================================================


📚 PROBLEM STATEMENT
==================================================


The cosmetic company "BeautyMe" wishes to know the 
alphabetic product code from the product barcode. 
The barcode of the product is a numeric value and 
the alphabetic product is a string value tagged 'a-j'. 
The alphabetic range 'a-j' represents the numeric 
range '0-9'. To produce the alphabetic product code, 
each digit in the numeric barcode is replace by the 
corresponding matching letters.


Write an algorithm to display the alphabetic 
product code from the numeric barcodes.


INPUT:  an integer value
OUTPUT: a character


MAPPING:
a-j ⟹ 0-9


EXAMPLE:
abc ⟹ 012


0 → a
1 → b
2 → c
===========================================================


PROBLEM SUMMARY:
Convert a numeric barcode into an alphabetic product code.
Each digit (0–9) is mapped to letters (a–j).


MAPPING:
0 → a
1 → b
2 → c
3 → d
4 → e
5 → f
6 → g
7 → h
8 → i
9 → j


FINAL CODE WITH COMMENTS:
==========================================================
# Take input from user as string (numeric barcode)
s = input()


# Loop through each character (digit) in the string
for i in s:

    # Convert character to integer using int(i)
    # Add 97 (ASCII value of 'a')
    # Convert result into character using chr()
    # Example: '0' → int(0)=0 → 0+97=97 → chr(97)='a'


    print(chr(int(i) + 97), end='')  # end='' prints in same line
==========================================================
EXAMPLE:


Input:
012


Output:
abc


WORKING:


i = '0' → int(0)=0 → 0+97=97 → 'a'
i = '1' → int(1)=1 → 1+97=98 → 'b'
i = '2' → int(2)=2 → 2+97=99 → 'c'


Final Output: abc
==========================================================
INTERVIEW LINE:
This program converts each digit into its corresponding alphabet
by adding it to ASCII value of 'a' (97) and printing the result.
==========================================================
==================================================
LBP175 - PRINT PRIME NUMBERS
==================================================


📚 PROBLEM STATEMENT
==================================================


PROBLEM:
Implement a program to read a number and print 
prime numbers upto n separated by commas.


INPUT:  a number from the user
OUTPUT: comma separated prime numbers


EXAMPLE:
Input: 10
Output: 2, 3, 5, 7,


==================================================
📚 DEFINITION
==================================================


PRIME NUMBER:
- A number greater than 1
- Has exactly 2 factors: 1 and itself
- Examples: 2, 3, 5, 7, 11, 13, 17, 19, 23, 29


FACTOR:
- A number that divides another evenly
- No remainder when dividing


EXAMPLE:
Factors of 6: 1, 2, 3, 6 (four factors) → NOT prime
Factors of 5: 1, 5 (two factors) → PRIME


==================================================
💻 SYNTAX & LOGIC
==================================================


SYNTAX:
────


def isprime(n):
    f = 0
    for i in range(1, n+1):
        if n % i == 0:
            f = f + 1
    return f == 2


n = int(input())


for i in range(2, n+1):
    if isprime(i):
        print(i, end=', ')


────────────────────────────────────────────────


LOGIC:
──────


STEP 1: Create function isprime(n)
  - Count how many divisors n has
  - If count == 2, it's prime (1 and itself)
  - Return True if prime, False otherwise


STEP 2: Read input number n


STEP 3: Loop from 2 to n
  - For each number, check if it's prime
  - If prime, print it with comma separator


==================================================
💻 CODE WITH COMMENTS
==================================================


# Function to check if a number is prime
def isprime(n):
    # Count the factors (divisors) of n
    f = 0

    # Loop from 1 to n
    for i in range(1, n+1):
        # Check if i divides n evenly (no remainder)
        if n % i == 0:
            # Increment factor count
            f = f + 1

    # Prime has exactly 2 factors (1 and itself)
    return f == 2


# Read input from user
n = int(input())


# Loop from 2 to n (skip 1, not prime)
for i in range(2, n+1):
    # Check if i is prime
    if isprime(i):
        # Print with comma and space separator
        print(i, end=', ')


==================================================
==================================================
LBP176 - GCD OF TWO NUMBERS
==================================================


📚 PROBLEM STATEMENT
──────────────────


Implement a program to read two integers values 
and return GCD of two numbers.


INPUT: two space separated integers
OUTPUT: GCD of two numbers


EXAMPLE:
Input: 12 8
Output: 4


==================================================
📚 DEFINITION
──────────────


GCD (Greatest Common Divisor):
- Largest number that divides both numbers evenly
- Also called HCF (Highest Common Factor)


EXAMPLE:
Numbers: 12 and 8
Divisors of 12: 1, 2, 3, 4, 6, 12
Divisors of 8: 1, 2, 4, 8
Common divisors: 1, 2, 4
GCD: 4


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read two numbers
2. Use math.gcd() to find GCD
3. Print result


OR (WITHOUT math library):


LOGIC:
1. Read two numbers
2. Loop: while both numbers > 0
   - Find remainder of larger by smaller
   - Replace larger with smaller
   - Replace smaller with remainder
3. When one becomes 0, other is GCD


==================================================
💻 CODE WITH COMMENTS
──────────────────────


# SIMPLE SOLUTION (USING MATH LIBRARY)


import math


# Read two numbers
n1, n2 = (int(i) for i in input().split())


# Calculate and print GCD
print(math.gcd(n1, n2))


──────────────────────────────────────────────


# ALTERNATIVE SOLUTION (WITHOUT MATH LIBRARY - EUCLIDEAN ALGORITHM)


# Read two numbers
a, b = (int(i) for i in input().split())


# Euclidean algorithm to find GCD
while b != 0:
    # Store remainder
    temp = b
    # b becomes remainder of a/b
    b = a % b
    # a becomes previous b
    a = temp


# When b becomes 0, a is GCD
print(a)


==================================================
==================================================
LBP177 - SECRET INFORMATION
==================================================


📚 PROBLEM STATEMENT
──────────────────


A spy wants to send some secret information to 
the government. As the data is very important, he 
encrypts the message by encoding by adding some 
extra characters. The original message has only 
upper case letters and numbers, while the extra 
characters are makeup of lowercase letters and 
special characters. Can you help the receiver in 
designing a program that accepts the message and 
returns the secret information.


INPUT: a string from the user
OUTPUT: original message


EXAMPLE:
Input: A1b@C2d#
Output: A1C2


EXPLANATION:
- Keep: Uppercase letters (A, C) and numbers (1, 2)
- Remove: Lowercase letters (b, d) and special characters (@, #)


==================================================
📚 DEFINITION
──────────────


ORIGINAL MESSAGE:
- Contains only uppercase letters (A-Z)
- Contains only numbers (0-9)
- No lowercase or special characters


ENCRYPTED MESSAGE:
- Original message + extra characters
- Extra characters are lowercase letters and special symbols


DECRYPTION:
- Extract only uppercase letters and numbers
- Ignore lowercase and special characters


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read encrypted message as string
2. For each character:
   - Check if it's uppercase letter (A-Z)
   - Check if it's digit (0-9)
   - If yes, print it
   - If no (lowercase or special), skip it
3. Output is the original message


==================================================
💻 CODE WITH COMMENTS
──────────────────────


# Read encrypted message
s = input()


# For each character in message
for i in s:
    # Check if character is:
    # - Uppercase letter (A-Z)
    # - OR digit (0-9)
    if (i >= 'A' and i <= 'Z') or i.isdigit():
        # Print the character
        print(i, end='')


──────────────────────────────────────────────


# ALTERNATIVE SOLUTION (MORE PYTHONIC)


s = input()


for i in s:
    # Check if uppercase or digit
    if i.isupper() or i.isdigit():
        print(i, end='')


──────────────────────────────────────────────


# ANOTHER ALTERNATIVE (USING LIST COMPREHENSION)


s = input()


# Create list of uppercase and digits
result = ''.join(i for i in s if i.isupper() or i.isdigit())


print(result)


==================================================


==================================================
LBP178 - FLIGHT
==================================================


📚 PROBLEM STATEMENT
──────────────────


Amir is travelling to Mumbai, but this time he is 
taking flight. His brother has already told him 
about luggage weight limits but forgot it. Now he 
is taking with him 3 trolley bags.


As per the current airlines which Amir will fly, 
has below weight limits.


There can be at max 2 check-in and 1 cabin luggage. 
Check-in has total limit of L1 and Cabin has 
limit of L2.


Now, Amir has 3 luggage has weights as W1 and W2 
and W3 respectively. Now he should be smart enough 
to make sure that he can travel with all the 3 
luggage without paying extra charge.


Find out whether Amir can take all of his luggage 
without any extra charges or not. If all good and 
no extra changes were paid, output "Yes" otherwise "No".


INPUT: integers W1, W2, W3 and L1, L2
OUTPUT: Yes or No


==================================================
📚 DEFINITION
──────────────


CHECK-IN LUGGAGE:
- Maximum 2 bags allowed
- Total weight limit: L1


CABIN LUGGAGE:
- Maximum 1 bag allowed
- Total weight limit: L2


CONSTRAINT:
- 3 bags total (W1, W2, W3)
- Need to fit 2 bags in check-in and 1 in cabin
- Must satisfy both weight limits


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read W1, W2, W3 (bag weights)
2. Read L1, L2 (weight limits)
3. Try all possible combinations:
   - 2 bags in check-in, 1 in cabin
   - Check if any combination works
4. If valid combination exists, print "Yes"
5. Else print "No"


POSSIBLE COMBINATIONS:
- Cabin: W1, Check-in: W2+W3
- Cabin: W2, Check-in: W1+W3
- Cabin: W3, Check-in: W1+W2


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
══════════════════════════════════════════


This is the code from your screenshot:


w1, w2, w3, l1, l2 = (int(i) for i in input().split())


print("Yes" if w1+w2+w3 <= l1+l2 else "No")


EXPLANATION:
────────────


# Read 5 integers from input
w1, w2, w3, l1, l2 = (int(i) for i in input().split())


# Check if total weight fits in total capacity
# Total capacity = l1 (check-in limit) + l2 (cabin limit)
# If all 3 bags total weight ≤ total capacity, print "Yes"
# Otherwise print "No"
print("Yes" if w1+w2+w3 <= l1+l2 else "No")


LOGIC:
──────


Condition: w1 + w2 + w3 ≤ l1 + l2


If TOTAL WEIGHT of all bags ≤ TOTAL CAPACITY allowed:
  → Can distribute bags optimally
  → Print "Yes"
Else:
  → Cannot fit all bags
  → Print "No"


==================================================
🔢 EXAMPLE
══════════


EXAMPLE 1:
──────────


Input: 10 20 15 50 30


Parse:
  W1 = 10 kg (bag 1)
  W2 = 20 kg (bag 2)
  W3 = 15 kg (bag 3)
  L1 = 50 kg (check-in limit)
  L2 = 30 kg (cabin limit)


Calculation:
  Total weight = 10 + 20 + 15 = 45 kg
  Total capacity = 50 + 30 = 80 kg

  Is 45 ≤ 80? YES ✓


Possible Distribution:
  Check-in (max 50): 20 + 15 = 35 kg ✓
  Cabin (max 30): 10 kg ✓
  All bags fit without extra charge!


Output: Yes


──────────────────────────────────────────────


EXAMPLE 2:
──────────


Input: 30 30 30 50 30


Parse:
  W1 = 30 kg
  W2 = 30 kg
  W3 = 30 kg
  L1 = 50 kg
  L2 = 30 kg


Calculation:
  Total weight = 30 + 30 + 30 = 90 kg
  Total capacity = 50 + 30 = 80 kg

  Is 90 ≤ 80? NO ✗


Output: No


==================================================
LBP179 - ARRANGEMENT
==================================================


📚 PROBLEM STATEMENT
──────────────────


Given an array of size n, write a function to 
rearrange the numbers of the array in such that 
even and odd numbers are arranged alternatively 
in increasing order.


INPUT: array size n and elements
OUTPUT: updated array


EXAMPLE:
Input: n=5, a=[4, 1, 3, 5, 2]


Step 1: Sort array
  [1, 2, 3, 4, 5]


Step 2: Separate even and odd
  Even: [2, 4]
  Odd: [1, 3, 5]


Step 3: Arrange alternately (even first)
  2, 1, 4, 3, 5


Output: [2, 1, 4, 3, 5]


==================================================
📚 DEFINITION
──────────────


EVEN NUMBER:
- Divisible by 2
- Examples: 2, 4, 6, 8, 10


ODD NUMBER:
- Not divisible by 2
- Examples: 1, 3, 5, 7, 9


ALTERNATE ARRANGEMENT:
- Even and odd numbers alternate
- Pattern: even, odd, even, odd, even, ...


INCREASING ORDER:
- Numbers sorted from smallest to largest


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read array size and elements
2. Sort the array in increasing order
3. Separate array into even and odd elements
4. Merge them alternately (even first)
5. Print merged array


STEP BY STEP:
─────────────


Input array: [4, 1, 3, 5, 2]


Step 1: Sort
  [1, 2, 3, 4, 5]


Step 2: Separate
  Even array: [2, 4]
  Odd array: [1, 3, 5]


Step 3: Merge alternately
  Position 0: even[0] = 2
  Position 1: odd[0] = 1
  Position 2: even[1] = 4
  Position 3: odd[1] = 3
  Position 4: odd[2] = 5

  Result: [2, 1, 4, 3, 5]


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
════════════════════════════════════════


n = int(input())
L = [int(i) for i in input().split()]


# Sort array in increasing order
L.sort()


# Create two arrays for even and odd
L1 = []  # even numbers
L2 = []  # odd numbers


# Separate even and odd numbers
for i in L:
    if i % 2 == 0:
        # Even number
        L1.append(i)
    else:
        # Odd number
        L2.append(i)


# Merge even and odd alternately
i = 0
while i < n/2:
    # Print even number
    print(L1[i], end=' ')
    # Print odd number
    print(L2[i], end=' ')
    i = i + 1


EXPLANATION:
────────────


Line 1: n = int(input())
  → Read array size


Line 2: L = [int(i) for i in input().split()]
  → Read array elements


Line 5: L.sort()
  → Sort array in increasing order


Line 8-9: L1 = [], L2 = []
  → Create empty lists for even and odd


Line 12-16: Separate even and odd
  if i % 2 == 0: (i is even)
    L1.append(i)
  else: (i is odd)
    L2.append(i)


Line 19-25: Merge alternately
  while i < n/2:
    print(L1[i], end=' ')  → print even
    print(L2[i], end=' ')  → print odd
    i = i + 1


==================================================
🔢 DETAILED EXAMPLE
═══════════════════


Input:
5
4 1 3 5 2


Execution:


n = 5
L = [4, 1, 3, 5, 2]


Step 1: Sort
L.sort() → L = [1, 2, 3, 4, 5]


Step 2: Separate
Loop through L:
  i=1: 1%2=1 (odd) → L2=[1]
  i=2: 2%2=0 (even) → L1=[2]
  i=3: 3%2=1 (odd) → L2=[1,3]
  i=4: 4%2=0 (even) → L1=[2,4]
  i=5: 5%2=1 (odd) → L2=[1,3,5]


L1 = [2, 4]  (even)
L2 = [1, 3, 5]  (odd)


Step 3: Merge Alternately
i=0: print(L1[0], end=' ') → print(2)
     print(L2[0], end=' ') → print(1)
     Output: 2 1


i=1: print(L1[1], end=' ') → print(4)
     print(L2[1], end=' ') → print(3)
     Output: 2 1 4 3


i=2: i < n/2? 2 < 2.5? YES
     But L1[2] doesn't exist (L1 has only 2 elements)

     Print remaining from L2:
     L2[2] = 5
     Output: 2 1 4 3 5


Final Output: 2 1 4 3 5


==================================================
🔢 MORE EXAMPLES
════════════════


EXAMPLE 1:
──────────
Input: n=6, a=[6, 5, 4, 3, 2, 1]


Sort: [1, 2, 3, 4, 5, 6]
Even: [2, 4, 6]
Odd: [1, 3, 5]


Output: 2 1 4 3 6 5


──────────────────────────────────────────────


==================================================
LBP180 - PARITY BITS
==================================================


📚 PROBLEM STATEMENT
──────────────────


Michael wants to check the parity of the given 
number. To find the parity, follow below steps.


1. Convert decimal number into binary number.
2. Count the number of 1's and 0's in the binary 
   representation.


If it contains odd number of 1-bits, then it is 
"odd parity" and if contains even number of 
1-bits then "even parity" Write a program to 
validate the given number belongs to odd parity 
or even parity.


INPUT: a number from the user
OUTPUT: odd parity or even parity


EXAMPLE:
Input: 7


Binary: 111 (three 1's)
Count of 1's: 3 (odd)
Output: odd parity


==================================================
📚 DEFINITION
──────────────


BINARY:
- Base 2 number system
- Uses digits 0 and 1
- Example: 7 (decimal) = 111 (binary)


PARITY:
- Property of binary representation
- Based on count of 1's (1-bits)


ODD PARITY:
- Odd number of 1's in binary
- Example: 7 = 111 (three 1's) → odd parity


EVEN PARITY:
- Even number of 1's in binary
- Example: 6 = 110 (two 1's) → even parity


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read decimal number
2. Convert to binary
3. Count number of 1's
4. If count is odd: print "odd parity"
5. If count is even: print "even parity"


CONVERSION STEPS:
─────────────────


Method 1: Using bin() function
  n = 7
  bin(7) = '0b111'  (string with '0b' prefix)
  Remove '0b': '111'
  Count 1's: 3

Method 2: Manual conversion
  n = 7
  7 % 2 = 1, 7 // 2 = 3
  3 % 2 = 1, 3 // 2 = 1
  1 % 2 = 1, 1 // 2 = 0
  Binary = 111 (read from bottom to top)
  Count 1's: 3


==================================================
💻 CODE WITH COMMENTS
══════════════════════


# Read number from user
n = int(input())


# Convert to binary and count 1's
count = bin(n).count('1')


# Check parity
if count % 2 == 1:
    # Odd number of 1's
    print("odd parity")
else:
    # Even number of 1's
    print("even parity")


EXPLANATION:
────────────


Line 1: n = int(input())
  → Read decimal number


Line 4: count = bin(n).count('1')
  → bin(n) converts to binary string
  → Example: bin(7) = '0b111'
  → .count('1') counts 1's = 3
  → count = 3


Line 7-11: Check if count is odd or even
  if count % 2 == 1: → count is odd
    print("odd parity")
  else: → count is even
    print("even parity")


──────────────────────────────────────────────


# ALTERNATIVE: MANUAL CONVERSION


n = int(input())


# Count 1's manually
count = 0
while n > 0:
    if n % 2 == 1:
        # Last bit is 1
        count += 1
    # Remove last bit
    n = n // 2


# Check parity
if count % 2 == 1:
    print("odd parity")
else:
    print("even parity")


==================================================
🔢 DETAILED EXAMPLES
════════════════════


EXAMPLE 1:
──────────
Input: 7


Binary conversion:
  7 = 0b111


Count 1's:
  bin(7) = '0b111'
  count('1') = 3


Check parity:
  3 % 2 = 1 (odd)

Output: odd parity ✓


──────────────────────────────────────────────


EXAMPLE 2:
──────────
Input: 6


Binary conversion:
  6 = 0b110


Count 1's:
  bin(6) = '0b110'
  count('1') = 2


Check parity:
  2 % 2 = 0 (even)

Output: even parity ✓


──────────────────────────────────────────────


EXAMPLE 3:
──────────
Input: 15


Binary conversion:
  15 = 0b1111


Count 1's:
  bin(15) = '0b1111'
  count('1') = 4


Check parity:
  4 % 2 = 0 (even)

Output: even parity ✓


──────────────────────────────────────────────
==================================================
📊 BINARY CONVERSION TABLE
════════════════════════════


Decimal | Binary | Count of 1's | Parity
──────────────────────────────────────────
0       | 0      | 0            | even
1       | 1      | 1            | odd
2       | 10     | 1            | odd
3       | 11     | 2            | even
4       | 100    | 1            | odd
5       | 101    | 2            | even
6       | 110    | 2            | even
7       | 111    | 3            | odd
8       | 1000   | 1            | odd
9       | 1001   | 2            | even
10      | 1010   | 2            | even
11      | 1011   | 3            | odd
12      | 1100   | 2            | even
13      | 1101   | 3            | odd
14      | 1110   | 3            | odd
15      | 1111   | 4            | even
16      | 10000  | 1            | odd


==================================================
==================================================
LBP181 - SECOND NON-REPEATING CHARACTER
==================================================


📚 PROBLEM STATEMENT
──────────────────


Sofia loved to play with the programs unfortunately. 
She got stuck in one of the questions. She thought 
to take help of james. james asked her the problem 
statement. The problem statement was.


"For the given string S of length N consist 
stream of character not in predefined order. 
Write a program to find second non-repeating 
character in a string S. Write a program to help 
sofia and james for the given problem statements.


INPUT: string from the user
OUTPUT: single character


EXAMPLE:
Input: aabbccdd
Output: (no second non-repeating character)


Input: aabbc
Output: b (first non-repeating), then c (second)


Input: aabccd
Output: d (first non-repeating: b, second: d)


📚 DEFINITION
──────────────


NON-REPEATING CHARACTER:
- Character that appears only once in string
- Example: "aabbc" → 'b' and 'c' are non-repeating


SECOND NON-REPEATING CHARACTER:
- The second character that appears only once
- Counted in order of appearance


REPEATING CHARACTER:
- Character that appears more than once


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read string from user
2. For each character in string:
   - Check if count of that character = 1
   - If yes, add to list of non-repeating
3. Get second element from list (index [1])
4. Print it


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


s = input()
# Read string from user
# Example: s = "aabccd"


L = []
# Create empty list to store non-repeating chars


for i in s:
    # Loop through each character in string
    # i = 'a', 'a', 'b', 'c', 'c', 'd'

    if s.count(i) == 1:
        # Check if character appears only once
        # s.count(i) returns frequency of character i
        # If count = 1, it's non-repeating

        L.append(i)
        # Add character to list
        # L = ['b', 'd']


print(L[1])
# Print second element (index 1)
# L[1] = 'd'
# Output: d


EXPLANATION:
────────────


Line 1: s = input()
  → Read string
  → Example: s = "aabccd"


Line 2: L = []
  → Create empty list


Line 4-12: for i in s:
  → Loop through each character

Line 5-8: if s.count(i) == 1:
  → s.count(i) counts total occurrences of character i
  → If count equals 1, character is non-repeating

Line 10: L.append(i)
  → Add non-repeating character to list


Line 12: print(L[1])
  → Print second element (index 1)
  → First element is at L[0]
  → Second element is at L[1]




==================================================
⚠️ NOTES ON SCREENSHOT CODE
════════════════════════════


ADVANTAGE:
✓ Simple and straightforward
✓ Easy to understand
✓ Direct approach


LIMITATION:
✗ Can crash if less than 2 non-repeating chars
✗ No error handling
✗ Assumes second non-repeating always exists


BETTER VERSION:
────────────────


s = input()
L = []


for i in s:
    if s.count(i) == 1:
        L.append(i)


# Check if second non-repeating exists
if len(L) >= 2:
    print(L[1])
else:
    print("No second non-repeating character")


==================================================
💡 KEY POINTS
══════════════


s.count(i):
- Returns frequency of character i in string s
- 1 means non-repeating
- >1 means repeating


L.append(i):
- Adds character to list
- List stores all non-repeating chars in order


APPEND() FUNCTION


DEFINITION:
append() is a built-in list method in Python used to add a single element
to the end of a list.


SYNTAX:
list_name.append(value)


PARAMETER:
value → the element that you want to add into the list


RETURN VALUE:
append() does not return anything (returns None)
It directly modifies the original list


WHY USED:
- To store elements dynamically while looping
- To build a list step-by-step
- To maintain insertion order
- Useful when number of elements is not known in advance


EXAMPLE:


L = []
L.append('a')
L.append('b')
L.append('c')


OUTPUT:
['a', 'b', 'c']


IN THIS PROGRAM:


L.append(i)
- Adds non-repeating characters into list
- Stores them in same order as they appear in string
- Helps to access second non-repeating character using L[1]


L[1]:
- Gets second element (index 1)
- Index starts at 0
- L[0] = first
- L[1] = second
- L[2] = third


==================================================
==================================================
LBP182 - ABSOLUTE DIFFERENCE BETWEEN PRIME NUMBERS
==================================================


📚 PROBLEM STATEMENT
──────────────────


You are given an array of integers, N of size 
array length. Find the absolute difference (i.e. 
diff>=0) between the largest and smallest prime 
numbers.


Note:
1. If there are 1 or fewer prime numbers in array 
   return 0.
2. The array may contain +ve and -ve numbers, 
   ignore -ve numbers.
3. 1 and 0 are not prime.


INPUT: array size and array elements
OUTPUT: absolute diff


EXAMPLE:
Input: [2, 3, 5, 7, 11]
Output: 9 (11 - 2 = 9)


Input: [4, 6, 8]
Output: 0 (no prime numbers)


Input: [2, 4, 6]
Output: 0 (only one prime: 2)


📚 DEFINITION
──────────────


PRIME NUMBER:
- Integer > 1
- Divisible only by 1 and itself
- Examples: 2, 3, 5, 7, 11, 13, 17, 19...


LARGEST PRIME:
- Biggest prime number in array


SMALLEST PRIME:
- Smallest prime number in array


ABSOLUTE DIFFERENCE:
- |largest - smallest|
- Always non-negative


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Create function isprime(n) to check if prime
2. Read array size and elements
3. Sort array in ascending order
4. Find smallest prime (starting from beginning)
5. Find largest prime (starting from end)
6. If at least 2 primes found:
   - Calculate diff = max - min
   - Print diff
7. Else:
   - Print 0


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


def isprime(n):
    # Check if n is prime
    f = 0
    # Count factors

    for i in range(1, n+1):
        # Loop from 1 to n
        if n % i == 0:
            # If i divides n
            f = f + 1
            # Increment factor count

    return f == 2
    # Prime has exactly 2 factors


n = int(input())
# Read array size


L = [int(i) for i in input().split()]
# Read array elements


L.sort()
# Sort array in ascending order


min_prime = 999
# Initialize min_prime to large value


max_prime = -1
# Initialize max_prime to -1


for i in L:
    # Loop through each element

    if isprime(i):
        # Check if element is prime

        if min_prime > i:
            # Update minimum prime
            min_prime = i

        if max_prime < i:
            # Update maximum prime
            max_prime = i


# Check if at least 2 primes found
if max_prime != -1 and min_prime != 999:
    # Both min and max primes updated
    # Means at least 2 primes found
    print(max_prime - min_prime)
    # Print difference
else:
    # Less than 2 primes found
    print(0)


==================================================
🔢 DETAILED EXECUTION
═════════════════════


EXAMPLE 1:
──────────
Input: 5
2 3 5 7 11


n = 5
L = [2, 3, 5, 7, 11]
L.sort() → L = [2, 3, 5, 7, 11]


min_prime = 999
max_prime = -1


Loop:
i=2: isprime(2)? YES
  min_prime > 2? 999>2? YES → min_prime=2
  max_prime < 2? -1<2? YES → max_prime=2


i=3: isprime(3)? YES
  min_prime > 3? 2>3? NO
  max_prime < 3? 2<3? YES → max_prime=3


i=5: isprime(5)? YES
  min_prime > 5? NO
  max_prime < 5? 3<5? YES → max_prime=5


i=7: isprime(7)? YES
  max_prime < 7? 5<7? YES → max_prime=7


i=11: isprime(11)? YES
  max_prime < 11? 7<11? YES → max_prime=11


Final: min_prime=2, max_prime=11


max_prime != -1 and min_prime != 999? YES
print(11 - 2) → print(9)


Output: 9 ✓


==================================================
LBP183 - PRODUCT WITH SUCCESSOR
==================================================


📚 PROBLEM STATEMENT
──────────────────


Given an integer N and integer array A as the 
input, where N denotes the length of A write a 
program to find an integer the sum of all these 
product with successors.


INPUT: array size and elements
OUTPUT: an int value
==================================================
📊 QUICK REFERENCE TABLE
═════════════════════════


Array Element | Successor | Product
──────────────────────────────────
1             | 2         | 2
2             | 3         | 6
3             | 4         | 12
4             | 5         | 20
5             | 6         | 30
10            | 11        | 110
100           | 101       | 10100


==================================================
EXAMPLE:
Input: 4
1 2 3 4


Calculation:
  1 × (1+1) = 1 × 2 = 2
  2 × (2+1) = 2 × 3 = 6
  3 × (3+1) = 3 × 4 = 12
  4 × (4+1) = 4 × 5 = 20

Sum = 2 + 6 + 12 + 20 = 40


Output: 40


📚 DEFINITION
──────────────


SUCCESSOR:
- Number that comes after a given number
- Successor of n = n + 1
- Successor of 5 = 6


PRODUCT WITH SUCCESSOR:
- Multiply each element with its successor
- Element × (Element + 1)
- Example: 3 × (3+1) = 3 × 4 = 12


SUM OF ALL PRODUCTS:
- Add all individual products together


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read array size N
2. Read array elements
3. For each element i:
   - Calculate product: i × (i+1)
   - Add to sum
4. Print total sum


FORMULA:
sum = Σ(i × (i+1)) for all i in array


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


n = int(input())
# Read array size
# Example: n = 4


L = [int(i) for i in input().split()]
# Read array elements
# Example: L = [1, 2, 3, 4]


sum = 0
# Initialize sum to 0


for i in L:
    # Loop through each element in array
    # i = 1, 2, 3, 4

    sum = sum + (i * (i+1))
    # Calculate: i × (i+1)
    # Add to sum
    # i=1: sum = 0 + (1×2) = 0 + 2 = 2
    # i=2: sum = 2 + (2×3) = 2 + 6 = 8
    # i=3: sum = 8 + (3×4) = 8 + 12 = 20
    # i=4: sum = 20 + (4×5) = 20 + 20 = 40


print(sum)
# Print result
# Output: 40


==================================================
🔢 DETAILED EXECUTION
═════════════════════


EXAMPLE 1:
──────────
Input: 4
1 2 3 4


n = 4
L = [1, 2, 3, 4]
sum = 0


Loop iteration 1: i = 1
  sum = sum + (1 * (1+1))
  sum = 0 + (1 * 2)
  sum = 0 + 2
  sum = 2


Loop iteration 2: i = 2
  sum = sum + (2 * (2+1))
  sum = 2 + (2 * 3)
  sum = 2 + 6
  sum = 8


Loop iteration 3: i = 3
  sum = sum + (3 * (3+1))
  sum = 8 + (3 * 4)
  sum = 8 + 12
  sum = 20


Loop iteration 4: i = 4
  sum = sum + (4 * (4+1))
  sum = 20 + (4 * 5)
  sum = 20 + 20
  sum = 40


print(40)
Output: 40 ✓


==================================================
LBP184 - PRE-SORTED INTEGERS IN ARRAY
==================================================


📚 PROBLEM STATEMENT
──────────────────


You are given an array of integers, a of size n, 
Your task is to find the number of elements whose 
positions will remain unchanged after sorted in 
ascending order.


INPUT: array size and elements
OUTPUT: unchanged count


EXAMPLE:
Input: 5
1 5 3 4 2


Original array: [1, 5, 3, 4, 2]
Sorted array:   [1, 2, 3, 4, 5]


Positions:
  Index 0: 1 = 1 ✓ (unchanged)
  Index 1: 5 ≠ 2 ✗ (changed)
  Index 2: 3 = 3 ✓ (unchanged)
  Index 3: 4 = 4 ✓ (unchanged)
  Index 4: 2 ≠ 5 ✗ (changed)


Count of unchanged elements: 3


Output: 3
==================================================
📊 EXAMPLE SUMMARY
═══════════════════


Original: [1, 5, 3, 4, 2]
Sorted:   [1, 2, 3, 4, 5]


Position  0 1 2 3 4
Original  1 5 3 4 2
Sorted    1 2 3 4 5
Match?    ✓ ✗ ✓ ✓ ✗


Unchanged count = 3
==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read array size and elements
2. Create copy of original array
3. Sort the copy
4. Compare original with sorted:
   - If element at same position: increment count
5. Print count


APPROACH:
────────
- Keep original array unchanged
- Sort a copy of array
- Compare element by element
- Count matches at same indices


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


n = int(input())
# Read array size


L = [int(i) for i in input().split()]
# Read array elements into list L


L.sort()
# Sort the array in ascending order
# This modifies L to sorted state


for i in range(0, n//2):
    # Loop from index 0 to n/2 (first half)
    # This prints first half of sorted array
    print(L[i], end=' ')


for i in range(n-1, n//2-1, -1):
    # Loop from index n-1 down to n/2
    # Backwards loop for second half
    # This prints second half of sorted array
    print(L[i], end=' ')


⚠️ NOTE: This code prints the sorted array!
Not the comparison! This code has issues.


══════════════════════════════════════════════


# CORRECT SOLUTION


n = int(input())
# Read array size


L = [int(i) for i in input().split()]
# Read array elements


L_copy = L.copy()
# Create copy of original array


L_copy.sort()
# Sort the copy


count = 0
# Initialize count of unchanged elements


for i in range(n):
    # Loop through all indices

    if L[i] == L_copy[i]:
        # Compare original with sorted
        # If element at same position matches
        count += 1
        # Increment count


print(count)
# Print total unchanged count


EXPLANATION:
────────────


Line 1: n = int(input())
  → Read array size


Line 4: L = [int(i) for i in input().split()]
  → Read array elements


Line 7: L_copy = L.copy()
  → Create copy of original array
  → Keep original unchanged


Line 10: L_copy.sort()
  → Sort the copy in ascending order


Line 13: count = 0
  → Initialize counter


Line 15-20: for loop
  → Loop through each index (0 to n-1)
  → Compare L[i] (original) with L_copy[i] (sorted)
  → If they match, increment count


Line 22: print(count)
  → Print total number of unchanged elements


==================================================
🔢 DETAILED EXECUTION
═════════════════════


EXAMPLE 1:
──────────
Input: 5
1 5 3 4 2


n = 5
L = [1, 5, 3, 4, 2]
L_copy = [1, 5, 3, 4, 2]
L_copy.sort() → L_copy = [1, 2, 3, 4, 5]


count = 0


Compare original with sorted:


Index 0: L[0]=1, L_copy[0]=1 → 1==1? YES → count=1
Index 1: L[1]=5, L_copy[1]=2 → 5==2? NO
Index 2: L[2]=3, L_copy[2]=3 → 3==3? YES → count=2
Index 3: L[3]=4, L_copy[3]=4 → 4==4? YES → count=3
Index 4: L[4]=2, L_copy[4]=5 → 2==5? NO


Final count = 3


Output: 3 ✓


──────────────────────────────────────────────


EXAMPLE 2:
──────────
Input: 4
1 2 3 4


n = 4
L = [1, 2, 3, 4]
L_copy = [1, 2, 3, 4]
L_copy.sort() → [1, 2, 3, 4] (already sorted)


Index 0: 1==1? YES → count=1
Index 1: 2==2? YES → count=2
Index 2: 3==3? YES → count=3
Index 3: 4==4? YES → count=4


Output: 4 ✓ (all elements unchanged)


──────────────────────────────────────────────


EXAMPLE 3:
──────────
Input: 4
4 3 2 1


n = 4
L = [4, 3, 2, 1]
L_copy = [4, 3, 2, 1]
L_copy.sort() → [1, 2, 3, 4]


Index 0: 4==1? NO
Index 1: 3==2? NO
Index 2: 2==3? NO
Index 3: 1==4? NO


count = 0


Output: 0 ✓ (all changed)




==================================================
💡 KEY POINTS
══════════════


COMPARISON:
- Original[i] vs Sorted[i]
- Same index position
- Count matches


COPY:
- L.copy() creates new list
- Keeps original unchanged
- Necessary for comparison


SORT:
- L.sort() sorts in ascending order
- Modifies original list
- That's why we use copy


INDEX RANGE:
- range(n) = 0 to n-1
- All valid indices


==================================================
LBP185 - SAVINGS
==================================================


📚 PROBLEM STATEMENT
──────────────────


There are 3 friends named Ronaldo, Messi, Rooney 
who worked at a company. Given their monthly 
salaries and monthly expenditures, returns the 
highest saving among them.


INPUT: single line with 6 space separated integers
OUTPUT: highest saving among the 3 of them
==================================================
📊 COMPARISON TABLE
════════════════════


Example | Ronaldo | Messi | Rooney | Highest
────────────────────────────────────────────
1       | 3000    | 4500  | 5000   | 5000 ✓
2       | 5000    | 5000  | 3000   | 5000 ✓
3       | 20000   | 15000 | 5000   | 20000 ✓
4       | 1000    | 1000  | 1500   | 1500 ✓
5       | 10000   | 15000 | 13000  | 15000 ✓


==================================================
EXAMPLE:
Input: 5000 2000 6000 1500 8000 3000
  Ronaldo: salary=5000, expenditure=2000
  Messi: salary=6000, expenditure=1500
  Rooney: salary=8000, expenditure=3000


Savings:
  Ronaldo: 5000 - 2000 = 3000
  Messi: 6000 - 1500 = 4500
  Rooney: 8000 - 3000 = 5000


Highest saving: 5000 (Rooney)


Output: 5000


📚 DEFINITION
──────────────


SALARY:
- Monthly income


EXPENDITURE:
- Monthly spending


SAVING:
- Salary - Expenditure
- Money saved after spending


HIGHEST SAVING:
- Maximum saving among 3 friends
- max(saving1, saving2, saving3)


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read 6 integers from single line
2. Parse as:
   a1 = Ronaldo's salary
   a2 = Ronaldo's expenditure
   b1 = Messi's salary
   b2 = Messi's expenditure
   c1 = Rooney's salary
   c2 = Rooney's expenditure
3. Calculate savings:
   saving1 = a1 - a2
   saving2 = b1 - b2
   saving3 = c1 - c2
4. Find max of three savings
5. Print maximum


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


a1, a2, b1, b2, c1, c2 = (int(i) for i in input().split())
# Read 6 integers from single input line
# Example: 5000 2000 6000 1500 8000 3000
# a1=5000 (Ronaldo salary)
# a2=2000 (Ronaldo expenditure)
# b1=6000 (Messi salary)
# b2=1500 (Messi expenditure)
# c1=8000 (Rooney salary)
# c2=3000 (Rooney expenditure)


print(max(a1-a2, b1-b2, c1-c2))
# Calculate savings for each:
#   Ronaldo: a1-a2 = 5000-2000 = 3000
#   Messi: b1-b2 = 6000-1500 = 4500
#   Rooney: c1-c2 = 8000-3000 = 5000
# Find max of three savings
# max(3000, 4500, 5000) = 5000
# Print: 5000




🔢 DETAILED EXECUTION
═════════════════════


EXAMPLE 1:
──────────
Input: 5000 2000 6000 1500 8000 3000


Parsing:
  a1=5000, a2=2000 (Ronaldo)
  b1=6000, b2=1500 (Messi)
  c1=8000, c2=3000 (Rooney)


Savings calculation:
  Ronaldo: a1-a2 = 5000-2000 = 3000
  Messi: b1-b2 = 6000-1500 = 4500
  Rooney: c1-c2 = 8000-3000 = 5000


max(3000, 4500, 5000) = 5000


Output: 5000 ✓


──────────────────────────────────────────────
==================================================
LBP186 - HALF ASCENDING AND HALF DESCENDING
==================================================


📚 PROBLEM STATEMENT
──────────────────


You are given a list of integers of size N, write 
an algorithm to sort the first K elements of the 
list in ascending order and the remaining 
elements in descending order.


INPUT: array size and elements
OUTPUT: updated array
==================================================
📊 INDEX MAPPING
══════════════════


For n=7:


Original indices: 0 1 2 | 3 4 5 6
After sort:       1 1 2 | 3 4 5 9


First half (0 to 2):
  Ascending: 1 1 2 ✓


Second half (6 down to 3):
  Loop: i=6,5,4,3
  Values: 9,5,4,3
  Descending: 9 5 4 3 ✓


Final output: 1 1 2 9 5 4 3


==================================================
EXAMPLE:
Input: 7
3 1 4 1 5 9 2


K = 7/2 = 3 (first half)


First 3 elements: [3, 1, 4]
Sort ascending: [1, 3, 4]


Remaining 4 elements: [1, 5, 9, 2]
Sort descending: [9, 5, 2, 1]


Output: 1 3 4 9 5 2 1


📚 DEFINITION
──────────────


K = N // 2 (first half size)


FIRST HALF:
- First K elements
- Sort in ascending order (small to large)


SECOND HALF:
- Remaining N-K elements
- Sort in descending order (large to small)


ASCENDING:
- 1, 2, 3, 4, 5 (increasing)


DESCENDING:
- 5, 4, 3, 2, 1 (decreasing)


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read array size and elements
2. Sort entire array in ascending order
3. Print first K elements (already ascending)
4. Print remaining elements in reverse (descending)


APPROACH:
────────
Step 1: Sort entire array
Step 2: First K elements are already ascending
Step 3: Last N-K elements printed in reverse order
        gives descending effect


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


n = int(input())
# Read array size
# Example: n = 7


L = [int(i) for i in input().split()]
# Read array elements
# Example: L = [3, 1, 4, 1, 5, 9, 2]


L.sort()
# Sort entire array in ascending order
# L = [1, 1, 2, 3, 4, 5, 9]


for i in range(0, n//2):
    # Loop from index 0 to n/2 (first half)
    # range(0, 7//2) = range(0, 3) = 0, 1, 2
    # Prints first 3 elements
    print(L[i], end=' ')
    # L[0]=1, L[1]=1, L[2]=2
    # Output: 1 1 2


for i in range(n-1, n//2-1, -1):
    # Loop from index n-1 down to n/2 backwards
    # range(n-1, n//2-1, -1)
    # range(7-1, 7//2-1, -1) = range(6, 2, -1)
    # Indices: 6, 5, 4, 3
    # Prints last 4 elements in reverse
    print(L[i], end=' ')
    # L[6]=9, L[5]=5, L[4]=4, L[3]=3
    # Output: 1 1 2 9 5 4 3


==================================================
LBP187 - LAST AND SECOND-LAST
==================================================


📚 PROBLEM STATEMENT
──────────────────


Given a string, create a new string made up of its 
last two letters, reversed and separated by comma.


INPUT: a string from the user
OUTPUT: comma separated last and second-last character


EXAMPLE:
Input: hello


Last character: o (index -1)
Second-last character: l (index -2)
Reversed: o, l


Output: o,l


EXAMPLE 2:
Input: programming


Last character: g (index -1)
Second-last character: n (index -2)
Reversed: g, n


Output: g,n


📚 DEFINITION
──────────────


LAST CHARACTER:
- Final character in string
- Index -1 (negative indexing from end)


SECOND-LAST CHARACTER:
- Character before the last
- Index -2 (negative indexing from end)


REVERSED:
- Print last first, then second-last
- s[-1] comes before s[-2]


COMMA SEPARATED:
- Format: "last,second-last"
- With comma and space between


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read string from user
2. Access last character: s[-1]
3. Access second-last character: s[-2]
4. Print them with comma separator
5. Reversed order: last, then second-last


NEGATIVE INDEXING:
─────────────────
String: "hello"
Index:   0 1 2 3 4
Chars:   h e l l o


Negative index:
Index:  -5 -4 -3 -2 -1
Chars:   h  e  l  l  o


s[-1] = 'o' (last)
s[-2] = 'l' (second-last)


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


s = input()
# Read string from user
# Example: s = "hello"


print(s[-1], s[-2], sep=',')
# Print last and second-last characters
# s[-1] = 'o' (last character)
# s[-2] = 'l' (second-last character)
# sep=',' separates with comma (no space)
# Output: o,l


ALTERNATIVE WITH SPACE:
──────────────────────


print(s[-1], s[-2], sep=', ')
# With space after comma
# Output: o, l


EXPLANATION:
────────────


Line 1: s = input()
  → Read string input


Line 3: print(s[-1], s[-2], sep=',')
  → s[-1] gets last character
  → s[-2] gets second-last character
  → print() with two values prints both
  → sep=',' sets separator between values
  → No space after comma in output


NEGATIVE INDEXING:
─────────────────
- s[-1] = last character
- s[-2] = second to last character
- s[-3] = third to last character
- etc.


SEPARATOR (sep):
────────────────
- Default separator is space: ' '
- sep=',' changes to comma: ','
- sep=', ' changes to comma+space: ', '




==================================================
💡 KEY POINTS
══════════════


NEGATIVE INDEXING:
- s[-1] = last character
- s[-2] = second-last character
- s[-n] = nth character from end


PRINT WITH MULTIPLE VALUES:
- print(val1, val2, ..., sep='separator')
- Prints each value separated by sep


SEPARATOR OPTIONS:
- sep=' ' (default, space)
- sep=',' (comma, no space)
- sep=', ' (comma + space)
- sep='-' (hyphen)
- sep='\n' (newline)


REVERSED ORDER:
- s[-1] comes first ( indices:  0 1 2 3 4
Characters:        h e l l o


Negative indices: -5-4-3-2-1
Characters:       h e l l o


s[-1] = 'o' (last)
s[-2] = 'l' (second-last)


==================================================
🔢 DETAILED EXECUTION
═════════════════════


EXAMPLE 1:
──────────
Input: hello


s = "hello"


Indexing:
  h(0/-5), e(1/-4), l(2/-3), l(3/-2), o(4/-1)


s[-1] = 'o'
s[-2] = 'l'


print(s[-1], s[-2], sep=',')
→ print('o', 'l', sep=',')
→ Prints: o,l


Output: o,l ✓


──────────────────────────────────────────────


EXAMPLE 2:
──────────
Input: python


s = "python"


Indexing:
  p(0/-6), y(1/-5), t(2/-4), h(3/-3), o(4/-2), n(5/-1)


s[-1] = 'n' (last)
s[-2] = 'o' (second-last)


print(s[-1], s[-2], sep=',')
→ print('n', 'o', sep=',')
→ Prints: n,o


Output: n,o ✓


──────────────────────────────────────────────


EXAMPLE 3:
──────────
Input: programming


s = "programming"


Index count: 11 characters
s[-1] = 'g' (last)
s[-2] = 'n' (second-last)


print(s[-1], s[-2], sep=',')
→ Prints: g,n


Output: g,n ✓


──────────────────────────────────────────────


EXAMPLE 4:
──────────
Input: ab


s = "ab"


Indexing:
  a(0/-2), b(1/-1)


s[-1] = 'b' (last)
s[-2] = 'a' (second-last)


print(s[-1], s[-2], sep=',')
→ Prints: b,a


Output: b,a ✓


──────────────────────────────────────────────


EXAMPLE 5:
──────────
Input: xyz


s = "xyz"


Indexing:
  x(0/-3), y(1/-2), z(2/-1)


s[-1] = 'z' (last)
s[-2] = 'y' (second-last)


print(s[-1], s[-2], sep=',')
→ Prints: z,y


Output: z,y ✓




==================================================
📊 STRING INDEXING EXAMPLES
════════════════════════════


String: "programming"
Length: 11


Index:    0 1 2 3 4 5 6 7 8 9 10
Char:     p r o g r a m m i n g
Neg Idx: -11-10-9-8-7-6-5-4-3-2-1


s[0] = 'p'  |  s[-11] = 'p'
s[1] = 'r'  |  s[-10] = 'r'
s[10] = 'g' |  s[-1] = 'g'
s[9] = 'n'  |  s[-2] = 'n'


Last: s[-1] = 'g'
Second-last: s[-2] = 'n'


Output: g,n


==================================================
LBP188 - DIGITAL ROOT
==================================================


📚 PROBLEM STATEMENT
──────────────────


Write a program to find the digital root of a 
given number. Digital root is the recursive sum 
of digits in the given number (until single digit 
is arrived)


INPUT: a number from the user
OUTPUT: single digit number


EXAMPLE:
Input: 38


Step 1: Sum of digits = 3 + 8 = 11
Step 2: Sum of digits = 1 + 1 = 2
Step 3: Single digit reached = 2


Output: 2


ANOTHER EXAMPLE:
Input: 9875


Step 1: 9 + 8 + 7 + 5 = 29
Step 2: 2 + 9 = 11
Step 3: 1 + 1 = 2
Step 4: Single digit = 2


Output: 2


💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read number n
2. While n >= 10 (more than 1 digit):
   - Calculate sum of digits
   - Replace n with sum
3. When n < 10 (single digit):
   - Print n (digital root found)


STEPS:
─────
def sum(n):
  - Sum all digits of n
  - Return total


Main loop:
  - While n is not single digit (n >= 10)
  - Replace n with sum of its digits
  - Repeat until single digit


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


def sum(n):
    # Function to sum all digits of n
    s = 0
    # Initialize sum to 0

    while n != 0:
        # Loop while n has digits
        s = s + (n % 10)
        # Add last digit to sum
        # n % 10 extracts last digit

        n = n // 10
        # Remove last digit
        # n // 10 removes last digit

    return s
    # Return sum of all digits


n = int(input())
# Read number from user


while True:
    # Infinite loop (will break when single digit)

    if n >= 0 and n <= 9:
        # Check if n is single digit (0 to 9)

        print(n)
        # Print single digit (digital root)

        break
        # Exit loop

    else:
        # n is not single digit (>= 10)

        n = sum(n)
        # Calculate sum of digits
        # Replace n with this sum
        # Repeat until single digit


EXPLANATION:
────────────


sum(n) FUNCTION:
──────────────


def sum(n):
  s = 0

  while n != 0:
    s = s + (n % 10)
    n = n // 10

  return s


Purpose: Extract all digits and sum them


Example: sum(38)
  Iteration 1: s = 0 + (38%10) = 0 + 8 = 8
              n = 38//10 = 3
  Iteration 2: s = 8 + (3%10) = 8 + 3 = 11
              n = 3//10 = 0
  Loop ends (n = 0)
  Return: 11


MAIN LOOP:
─────────


while True:
  if n >= 0 and n <= 9:
    print(n)
    break
  else:
    n = sum(n)


Purpose: Keep summing digits until single digit


Example with n = 38:
  Iteration 1: 38 is not single digit
              n = sum(38) = 11
  Iteration 2: 11 is not single digit
              n = sum(11) = 2
  Iteration 3: 2 is single digit (0-9)
              Print 2
              Break


==================================================
🔢 DETAILED EXECUTION
═════════════════════


EXAMPLE 1:
──────────
Input: 38


n = 38


While loop iteration 1:
  Is 38 between 0 and 9? NO
  n = sum(38)
    s = 0
    Loop 1: s = 0 + (38%10) = 0 + 8 = 8, n = 3
    Loop 2: s = 8 + (3%10) = 8 + 3 = 11, n = 0
    Return 11
  n = 11


While loop iteration 2:
  Is 11 between 0 and 9? NO
  n = sum(11)
    s = 0
    Loop 1: s = 0 + (11%10) = 0 + 1 = 1, n = 1
    Loop 2: s = 1 + (1%10) = 1 + 1 = 2, n = 0
    Return 2
  n = 2


While loop iteration 3:
  Is 2 between 0 and 9? YES
  print(2)
  break


Output: 2 ✓


──────────────────────────────────────────────
💡 KEY POINTS
══════════════


sum(n) FUNCTION:
- Extracts all digits
- Adds them together
- Returns total sum


n % 10:
- Gets last digit
- Example: 38 % 10 = 8


n // 10:
- Removes last digit
- Example: 38 // 10 = 3


WHILE LOOP:
- Continues until n is 0-9
- Each iteration sums digits
- Repeats with new n


BREAK:
- Exits loop when single digit
- Prevents infinite loop


==================================================
📊 TRACE TABLE
═════════════════


Number | Step 1 | Step 2 | Step 3 | Digital Root
──────────────────────────────────────────────────
38     | 11     | 2      | -      | 2
123    | 6      | -      | -      | 6
9875   | 29     | 11     | 2      | 2
999    | 27     | 9      | -      | 9
456    | 15     | 6      | -      | 6
1234   | 10     | 1      | -      | 1


==================================================
LBP189 - ABSOLUTE DIFFERENCE
==================================================


📚 PROBLEM STATEMENT
──────────────────


Write a program to find the absolute difference 
between the original number and its reversed 
number.


INPUT: a number from the user
OUTPUT: absolute difference


EXAMPLE:
Input: 123


Original number: 123
Reversed number: 321


Difference: 123 - 321 = -198
Absolute difference: |-198| = 198


Output: 198


ANOTHER EXAMPLE:
Input: 4567


Original: 4567
Reversed: 7654


Difference: 4567 - 7654 = -3087
Absolute difference: |-3087| = 3087


Output: 3087


📚 DEFINITION
──────────────


ORIGINAL NUMBER:
- Number given as input
- Example: 123


REVERSED NUMBER:
- Digits of number in reverse order
- Example: 321 (reverse of 123)


ABSOLUTE DIFFERENCE:
- |original - reversed|
- Always positive (non-negative)
- Ignores sign, takes magnitude


REVERSE:
- Read digits backwards
- 1234 → 4321
- 5 → 5


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read number as string n
2. Reverse the string: n[::-1]
3. Convert both to integers
4. Calculate difference: int(n) - int(reversed_n)
5. Take absolute value: abs(difference)
6. Print result


FORMULA:
abs(int(n) - int(n[::-1]))


STEPS:
─────
n = "123"
n[::-1] = "321"
int(n) = 123
int(n[::-1]) = 321
Difference = 123 - 321 = -198
abs(-198) = 198


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


n = input()
# Read number as string
# Example: n = "123"


print(abs(int(n) - int(n[::-1])))
# Calculate absolute difference
#
# Breakdown:
# n = "123"
# n[::-1] = "321" (reverse string)
# int(n) = 123 (convert to integer)
# int(n[::-1]) = 321 (reverse to integer)
# int(n) - int(n[::-1]) = 123 - 321 = -198
# abs(-198) = 198
# print(198)


==================================================
💡 KEY POINTS
══════════════


STRING REVERSAL:
- n[::-1] reverses string
- Works on any string
- Maintains digits order


int() CONVERSION:
- Converts string to integer
- Drops leading zeros
- "0001" becomes 1


ABSOLUTE VALUE:
- abs(x) = |x|
- Always non-negative
- abs(-5) = 5, abs(5) = 5


DIFFERENCE:
- Original - Reversed
- Can be negative
- That's why we use abs()


==================================================
LBP190 - LUCKY DRAW
==================================================


📚 PROBLEM STATEMENT
──────────────────


A person went to an exhibition. A lucky draw is 
going on, where one should buy a ticket. And if 
they ticket number appear on the screen, that 
ticket will be considered as jackpot winner.


He knows the secret of picking up the ticket 
number, which will be considered for the jackpot.


1. Sort the ticket number in the increasing order.
2. Now, the difference between the adjacent digits 
   should not be more than 2.


If his ticket follows the above condition, then 
there are more chances to win the jackpot.


Given a ticket number, find whether the ticket is 
eligible to be part of jackpot or not. Print 
"Yes/No" based on the result.


INPUT: ticket number
OUTPUT: Yes or No
==================================================
📊 DECISION TABLE
════════════════════


Input | Sorted | Diffs | Result
─────────────────────────────────
123   | 1,2,3  | 1,1   | Yes
171   | 1,1,7  | 0,6   | No
135   | 1,3,5  | 2,2   | Yes
159   | 1,5,9  | 4,4   | No
357   | 3,5,7  | 2,2   | Yes
1357  |1,3,5,7 |2,2,2  | Yes
1379  |1,3,7,9 |2,4,2  | No


==================================================
EXAMPLE:
Input: 171


Digits: 1, 7, 1
Sorted: 1, 1, 7


Check adjacent differences:
  |1 - 1| = 0 ≤ 2 ✓
  |1 - 7| = 6 > 2 ✗


Output: No


ANOTHER EXAMPLE:
Input: 123


Digits: 1, 2, 3
Sorted: 1, 2, 3


Check adjacent differences:
  |1 - 2| = 1 ≤ 2 ✓
  |2 - 3| = 1 ≤ 2 ✓


Output: Yes




💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read ticket number as string
2. Convert each character to digit (integer)
3. Sort digits in ascending order
4. For each pair of adjacent digits:
   - Calculate difference
   - If difference > 2: not eligible (No)
5. If all differences ≤ 2: eligible (Yes)


ALGORITHM:
─────────
Step 1: Read ticket number
Step 2: Extract digits and sort
Step 3: Check adjacent pairs
Step 4: If any pair difference > 2: return "No"
Step 5: If all pairs difference ≤ 2: return "Yes"


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════   ═══════════════════════════════════


L = [int(i) for i in input()]
# Read ticket number and convert each char to digit
# Example: input "123" → L = [1, 2, 3]


L.sort()
# Sort digits in ascending order
# Example: [1, 2, 3] → [1, 2, 3] (already sorted)


flag = True
# Initialize flag as True (eligible)
# Will become False if any difference > 2


for i in range(len(L)-1):
    # Loop through adjacent pairs
    # range(len(L)-1) gives indices 0 to len(L)-2
    # For L=[1,2,3]: i = 0, 1

    if L[i+1] - L[i] > 2:
        # Check if difference between adjacent digits > 2
        # L[i+1] - L[i] = next digit - current digit
        # Example: L[1] - L[0] = 2 - 1 = 1 (≤ 2) ✓

        flag = False
        # Set flag to False (not eligible)

        break
        # Exit loop early (already found violation)


print("Yes" if flag==True else "No")
# If flag is True: print "Yes"
# If flag is False: print "No"


EXPLANATION:
────────────


Line 1: L = [int(i) for i in input()]
  → Reads input as string
  → Iterates each character
  → Converts to integer
  → Creates list of digits
  → Example: "171" → [1, 7, 1]


Line 4: L.sort()
  → Sorts digits in ascending order
  → [1, 7, 1] → [1, 1, 7]


Line 7: flag = True
  → Assume eligible initially
  → Set to False if condition violated


Line 9-16: for loop
  for i in range(len(L)-1):
    → i goes from 0 to len(L)-2
    → For L with 3 elements: i = 0, 1
    → Checks pairs: (L[0],L[1]), (L[1],L[2])


  if L[i+1] - L[i] > 2:
    → Check difference > 2
    → If true: not eligible

    flag = False
    → Mark as not eligible

    break
    → Exit loop (no need to check further)


Line 18: print("Yes" if flag==True else "No")
  → If flag True: print "Yes"
  → If flag False: print "No"


==================================================
🔢 DETAILED EXECUTION
═════════════════════


EXAMPLE 1:
──────────
Input: 171


L = [int(i) for i in "171"]
L = [1, 7, 1]


L.sort()
L = [1, 1, 7]


flag = True


Loop iteration 1: i = 0
  L[i+1] - L[i] = L[1] - L[0] = 1 - 1 = 0
  Is 0 > 2? NO
  flag stays True


Loop iteration 2: i = 1
  L[i+1] - L[i] = L[2] - L[1] = 7 - 1 = 6
  Is 6 > 2? YES
  flag = False
  break


print("Yes" if flag==True else "No")
flag is False → print "No"


Output: No ✓


──────────────────────────────────────────────


EXAMPLE 2:
──────────
Input: 123


L = [1, 2, 3]
L.sort() → [1, 2, 3]


flag = True


Loop i=0:
  L[1] - L[0] = 2 - 1 = 1
  Is 1 > 2? NO
  flag stays True


Loop i=1:
  L[2] - L[1] = 3 - 2 = 1
  Is 1 > 2? NO
  flag stays True


Loop ends


flag is True → print "Yes"


Output: Yes ✓


================================================
💡 KEY POINTS
══════════════


CONVERT TO DIGITS:
- [int(i) for i in input()]
- Each character → integer digit


SORT:
- L.sort() sorts ascending
- Makes checking easier


FLAG PATTERN:
- Assume True (eligible)
- Set False if condition violated
- Break early on first violation


ADJACENT DIFFERENCE:
- L[i+1] - L[i]
- Compare consecutive elements
- All must be ≤ 2


RANGE:
- range(len(L)-1)
- Indices: 0 to len(L)-2
- Ensures L[i+1] exists


==================================================
LBP191 - TEST SET ASSIGNMENT
==================================================


📚 PROBLEM STATEMENT
──────────────────


In an online exam, the test paper set is 
categorized by the letters A-Z. The students 
enrolled in the exam have been assigned a numeric 
value called application ID. To assign the test 
set to the student, firstly the sum of all digits 
in the application ID is calculated. If the sum is 
within the numeric range 1-26 the corresponding 
alphabetic set code is assigned to the student, 
else the sum of the digits are calculated again 
and so on until the sum falls within the 1-26 
range.


INPUT: application id as int
OUTPUT: set number (A-Z or 1-26)


EXAMPLE:
Input: 9875


Step 1: Sum of digits = 9+8+7+5 = 29
        Is 29 in range [1-26]? NO

Step 2: Sum of digits = 2+9 = 11
        Is 11 in range [1-26]? YES

Mapping: 11 → K (11th letter)
        A=1, B=2, ..., K=11


Output: K (or 11)


ANOTHER EXAMPLE:
Input: 1234


Step 1: 1+2+3+4 = 10
        Is 10 in [1-26]? YES

Mapping: 10 → J
Output: J (or 10)






==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


def sum(n):
    # Function to sum all digits of n
    s = 0
    # Initialize sum to 0

    while n != 0:
        # Loop while n has digits
        s = s + (n % 10)
        # Add last digit to sum

        n = n // 10
        # Remove last digit

    return s
    # Return sum of all digits


n = int(input())
# Read application ID


while True:
    # Infinite loop (will break when in range)

    if n >= 1 and n <= 26:
        # Check if n is in range [1-26]

        print(chr(64 + n))
        # Convert to letter
        # chr(64+n): 1→chr(65)=A, 2→chr(66)=B, ..., 26→chr(90)=Z

        break
        # Exit loop

    else:
        # n is out of range [1-26]

        n = sum(n)
        # Calculate sum of digits
        # Replace n with this sum
        # Repeat until in range


EXPLANATION:
────────────


sum(n) FUNCTION:
──────────────


def sum(n):
  s = 0
  while n != 0:
    s = s + (n % 10)
    n = n // 10
  return s


Purpose: Extract and sum all digits


Example: sum(29)
  Iteration 1: s = 0 + (29%10) = 0 + 9 = 9
              n = 29//10 = 2
  Iteration 2: s = 9 + (2%10) = 9 + 2 = 11
              n = 2//10 = 0
  Return: 11


MAIN LOOP:
─────────


while True:
  if n >= 1 and n <= 26:
    print(chr(64 + n))
    break
  else:
    n = sum(n)


Purpose: Keep summing until in [1-26]


Example with n = 9875:
  Iteration 1: 9875 in [1-26]? NO
              n = sum(9875) = 29
  Iteration 2: 29 in [1-26]? NO
              n = sum(29) = 11
  Iteration 3: 11 in [1-26]? YES
              print(chr(64+11)) = chr(75) = 'K'
              break


ASCII CONVERSION:
────────────────


chr(64 + n):
  n=1: chr(65) = 'A'
  n=2: chr(66) = 'B'
  n=3: chr(67) = 'C'
  ...
  n=26: chr(90) = 'Z'


ASCII values:
  A=65, B=66, C=67, ..., Z=90
  So: chr(64 + n) where n is 1-26


==================================================
🔢 DETAILED EXECUTION
═════════════════════


EXAMPLE 1:
──────────
Input: 9875


n = 9875


While loop iteration 1:
  Is 9875 in [1-26]? NO
  n = sum(9875)
    s = 0
    Loop 1: s = 0 + 5 = 5, n = 987
    Loop 2: s = 5 + 7 = 12, n = 98
    Loop 3: s = 12 + 8 = 20, n = 9
    Loop 4: s = 20 + 9 = 29, n = 0
    Return 29
  n = 29


While loop iteration 2:
  Is 29 in [1-26]? NO
  n = sum(29)
    s = 0
    Loop 1: s = 0 + 9 = 9, n = 2
    Loop 2: s = 9 + 2 = 11, n = 0
    Return 11
  n = 111:
  Is 1 in 1-26? YES
  print(chr(64+1)) = print(chr(65)) = print('A')
  break


Output: A ✓


==================================================
LBP192 - DIGITS RAISED TO THE THIRD POWER
==================================================


📚 PROBLEM STATEMENT
──────────────────


Cristina appeared for a corporate Hackathon. She 
cleated first round of this and would like to 
take next challenge which is coding round. The 
problem statement comes to her is


"Write a program to find numbers which are in 
between integer 2 and integer N and such that the 
sum of its digits raised to the third power is 
equal to the number with the input given.


INPUT: integer N
OUTPUT: an integer value


EXAMPLE:
Input: 400


Check all numbers from 2 to 400:
  153: 1³ + 5³ + 3³ = 1 + 125 + 27 = 153 ✓
  370: 3³ + 7³ + 0³ = 27 + 343 + 0 = 370 ✓
  371: 3³ + 7³ + 1³ = 27 + 343 + 1 = 371 ✓


Output: 153 370 371


📚 DEFINITION
──────────────


ARMSTRONG NUMBER (NARCISSISTIC NUMBER):
- Sum of each digit raised to power of digit count
- For 3-digit numbers: d₁³ + d₂³ + d₃³ = number


DIGITS RAISED TO THIRD POWER:
- Extract each digit
- Raise to power 3 (cube)
- Sum all cubed digits


EXAMPLE:
153 = 1³ + 5³ + 3³ = 1 + 125 + 27 = 153 ✓
370 = 3³ + 7³ + 0³ = 27 + 343 + 0 = 370 ✓
407 = 4³ + 0³ + 7³ = 64 + 0 + 343 = 407 ✓


THESE ARE ARMSTRONG NUMBERS!




==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read number N
2. For each number i from 2 to N:
   - Calculate sum of digits cubed (d₁³ + d₂³ + ...)
   - If sum equals i: print i
3. Print all such numbers
==================================================
📊 ARMSTRONG NUMBERS (3-DIGIT)
═════════════════════════════════


Number | Calculation           | Sum  | Is ARM?
──────────────────────────────────────────────
153    | 1³+5³+3³ = 1+125+27   | 153  | ✓
370    | 3³+7³+0³ = 27+343+0   | 370  | ✓
371    | 3³+7³+1³ = 27+343+1   | 371  | ✓
407    | 4³+0³+7³ = 64+0+343   | 407  | ✓
100    | 1³+0³+0³ = 1+0+0      | 1    | ✗
999    | 9³+9³+9³ = 729*3      | 2187 | ✗


==================================================
ALGORITHM:
─────────
def sum(n):
  - Extract each digit
  - Cube each digit (d³)
  - Return total sum


Main loop:
  - For i from 2 to N
  - If sum(i) == i: print i


CORRECTED CODE:
──────────────


def sum(n):
    s = 0

    while n != 0:
        d = n % 10
        s = s + (d ** 3)  # d cubed
        n = n // 10

    return s


n = int(input())


for i in range(2, n+1):
    if i == sum(i):
        print(i, end=' ')


BREAKDOWN:
─────────


sum(n) function:
  - Extracts each digit using n % 10
  - Cubes the digit: d ** 3
  - Adds to sum
  - Removes digit: n // 10
  - Returns total sum of cubed digits


Example: sum(153)
  Iteration 1: d = 153 % 10 = 3
              s = 0 + (3**3) = 0 + 27 = 27
              n = 153 // 10 = 15

  Iteration 2: d = 15 % 10 = 5
              s = 27 + (5**3) = 27 + 125 = 152
              n = 15 // 10 = 1

  Iteration 3: d = 1 % 10 = 1
              s = 152 + (1**3) = 152 + 1 = 153
              n = 1 // 10 = 0

  Return: 153


Main loop:
  for i in range(2, n+1):
    - i goes from 2 to N
    - Check if i == sum(i)
    - If equal: print i


==================================================
LBP193 - GROCERY SHOP (ROUNDING TO NEAREST 10)
==================================================


📚 PROBLEM STATEMENT
──────────────────


There was a grocery shop. Shopkeeper would like 
to keep transactions as simple as he can. Hence, 
he used to take money as whole number. To optimize 
transactions, he decided if someone buys 
groceries from his shop, he will round money to 
the nearest whole number having zeros as last 
digit.


Write a program to help shopkeeper to make 
transactions much simple.
==================================================
📊 ROUNDING TABLE
═══════════════════


Input | Last Digit | Output | Distance
──────────────────────────────────────
1     | 1          | 10     | 9
5     | 5          | 10     | 5
10    | 0          | 10     | 0
12    | 2          | 20     | 8
15    | 5          | 20     | 5
20    | 0          | 20     | 0
23    | 3          | 30     | 7
25    | 5          | 30     | 5
99    | 9          | 100    | 1
100   | 0          | 100    | 0
123   | 3          | 130    | 7
127   | 7          | 130    | 3


INPUT: a number
OUTPUT: nearest int value which ending with 0


EXAMPLE:
Input: 123


Nearest number ending with 0:
  120 (round down) or 130 (round up)
  Distance from 123 to 120 = 3
  Distance from 123 to 130 = 7
  120 is closer


Output: 120


ANOTHER EXAMPLE:
Input: 127


Nearest to 120 or 130:
  127 - 120 = 7
  130 - 127 = 3
  130 is closer


Output: 130


📚 DEFINITION
──────────────


ROUNDING:
- Find nearest number ending with 0
- Numbers with 0 as last digit: 10, 20, 30...


ENDING WITH 0:
- Last digit is 0
- n % 10 == 0


NEAREST:
- Smallest distance from original number
- Can round up or down


ROUNDING RULE:
- If last digit 0-4: round down
- If last digit 5-9: round up




💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


n = int(input())
# Read number
# Example: n = 123


while True:
    # Infinite loop until condition met

    if n % 10 == 0:
        # Check if last digit is 0
        # n % 10 returns last digit
        # If last digit is 0: condition is true

        print(n)
        # Print the number (ends with 0)

        break
        # Exit loop

    else:
        # Last digit is not 0
        # Need to find next number ending with 0

        n = n + 1
        # Increment n by 1
        # Continue loop to check again


EXPLANATION:
────────────


Line 1: n = int(input())
  → Read number
  → Example: 123


Line 3-12: while True loop
  → Continues until break is executed


Line 5: if n % 10 == 0:
  → Check if n is divisible by 10
  → If last digit is 0: condition is TRUE
  → Example: 120 % 10 = 0 ✓
  → Example: 123 % 10 = 3 ✗


Line 6-8: if block (condition true)
  → print(n) - print the number
  → break - exit loop


Line 10-12: else block (condition false)
  → n = n + 1 - increment by 1
  → Loop continues, checks again


FLOW:
n=123: 123%10=3 (not 0) → n=124
n=124: 124%10=4 (not 0) → n=125
n=125: 125%10=5 (not 0) → n=126
n=126: 126%10=6 (not 0) → n=127
n=127: 127%10=7 (not 0) → n=128
n=128: 128%10=8 (not 0) → n=129
n=129: 129%10=9 (not 0) → n=130
n=130: 130%10=0 (YES!) → print(130), break


Output: 130 ✓


==================================================
LBP194 - PASSWORD CHANGE (CASE SWAP)
==================================================


📚 PROBLEM STATEMENT
──────────────────


Prakash a technical person wants to update his 
password for every 15 days, to create a new 
password, he is converting all lower case letters 
to upper case and upper case letters to lower 
case, help prakash to update password.


INPUT: a string from the user (old password)
OUTPUT: updated password
==================================================
📊 CHARACTER CONVERSION TABLE
═════════════════════════════════


Original | After swapcase()
──────────────────────────────
A        | a
a        | A
Z        | z
z        | Z
1        | 1
!        | !
@        | @
Space    | Space


Whole password:
MyPassword123  →  mYpASSWORD123
hello          →  HELLO
WORLD          →  world
Test@2024      →  tEST@2024


==================================================
EXAMPLE:
Input: PrAkAsH123


Conversion:
  P (upper) → p (lower)
  r (lower) → R (upper)
  A (upper) → a (lower)
  k (lower) → K (upper)
  A (upper) → a (lower)
  s (lower) → S (upper)
  H (upper) → h (lower)
  1 (digit) → 1 (unchanged)
  2 (digit) → 2 (unchanged)
  3 (digit) → 3 (unchanged)


Output: pRaKaShH123


📚 DEFINITION
──────────────


LOWERCASE:
- a, b, c, ..., z


UPPERCASE:
- A, B, C, ..., Z


CASE SWAP:
- Lowercase → Uppercase
- Uppercase → Lowercase
- Digits & special chars: unchanged


swapcase():
- Python built-in method
- Swaps case of all letters
- Returns modified string


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read password string
2. For each character:
   - If lowercase: convert to uppercase
   - If uppercase: convert to lowercase
   - If digit/special: keep unchanged
3. Print modified password


SIMPLE APPROACH:
────────────────
Use swapcase() method
It does all the work automatically


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


print(input().swapcase())


EXPLANATION:
────────────


input():
  - Reads string from user
  - Example: "PrAkAsH"


.swapcase():
  - Built-in Python method
  - Swaps case of all characters
  - Uppercase → lowercase
  - Lowercase → uppercase
  - Other chars unchanged
  - Returns new string


Example:
  "PrAkAsH".swapcase() = "pRaKaSh"


print():
  - Prints the result


💡 KEY POINTS
══════════════


swapcase():
- Python built-in string method
- Changes case of all letters
- Leaves digits, spaces, special chars unchanged
- Returns new string (original unchanged)


USAGE:
"string".swapcase()


PROPERTIES:
- Uppercase → Lowercase
- Lowercase → Uppercase
- Digits: unchanged
- Special characters: unchanged
- Spaces: unchanged


ONE-LINER:
print(input().swapcase())
- Read input
- Apply swapcase()
- Print result
All in one line!


==================================================
🔄 ALTERNATIVE SOLUTIONS
═════════════════════════


# Solution 1: Using swapcase() (given)
print(input().swapcase())


# Solution 2: Using manual iteration
s = input()
result = ""
for char in s:
    if char.isupper():
        result += char.lower()
    elif char.islower():
        result += char.upper()
    else:
        result += char
print(result)


# Solution 3: Using list comprehension
s = input()
result = ''.join(c.lower() if c.isupper() else 
                 c.upper() if c.islower() else c 
                 for c in s)
print(result)


# Solution 4: Store in variable then print
s = input()
print(s.swapcase())


==================================================
LBP195 - VIDEO SHARE (RATING SYSTEM)
==================================================


📚 PROBLEM STATEMENT
──────────────────


Video share is an online video sharing platform. 
The company has decided to rate its users 
channels based on the sum total of the number of 
views received online and the subscribers. This 
sum total is referred to as user points. The 
rating will be given according to the below charts.


User points    Rating
30-50          Average
51-60          Good
61-80          Excellent
81-100         Outstanding


INPUT: points value
OUTPUT: rating


CONSTRAINT: points >= 30 and points <= 100


EXAMPLE:
Input: 45


Check range:
  Is 45 in 30-50? YES
  Rating: Average


Output: Average


ANOTHER EXAMPLE:
Input: 75


Check range:
  Is 75 in 30-50? NO
  Is 75 in 51-60? NO
  Is 75 in 61-80? YES
  Rating: Excellent


Output: Excellent


📚 DEFINITION
──────────────


USER POINTS:
- Sum of views + subscribers
- Range: 30-100


RATING LEVELS:
  30-50:   Average
  51-60:   Good
  61-80:   Excellent
  81-100:  Outstanding


CONDITIONAL LOGIC:
- Check which range points fall into
- Return corresponding rating


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read user points
2. Check which range it falls into:
   - 30-50: print "Average"
   - 51-60: print "Good"
   - 61-80: print "Excellent"
   - 81-100: print "Outstanding"
3. Print corresponding rating


APPROACH:
────────
Use if-elif-else ladder
Check conditions in order
Print rating when condition matches


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


n = int(input())
# Read user points
# Example: n = 45


if n >= 30 and n <= 50:
    # Check if points in range 30-50
    print("Average")
    # Print rating for this range


elif n >= 51 and n <= 60:
    # Check if points in range 51-60
    print("Good")
    # Print rating for this range


elif n >= 61 and n <= 80:
    # Check if points in range 61-80
    print("Excellent")
    # Print rating for this range


else:
    # Points must be in range 81-100
    # (given constraint: n <= 100)
    print("Outstanding")
    # Print rating for this range


🔄 ALTERNATIVE SOLUTIONS
═════════════════════════


# Solution 1: Given (if-elif-else)
n = int(input())
if n >= 30 and n <= 50:
    print("Average")
elif n >= 51 and n <= 60:
    print("Good")
elif n >= 61 and n <= 80:
    print("Excellent")
else:
    print("Outstanding")


# Solution 2: Using dictionary
n = int(input())
ratings = {
    (30, 50): "Average",
    (51, 60): "Good",
    (61, 80): "Excellent",
    (81, 100): "Outstanding"
}
for (low, high), rating in ratings.items():
    if low <= n <= high:
        print(rating)
        break


# Solution 3: Using nested if
n = int(input())
if n <= 50:
    print("Average")
elif n <= 60:
    print("Good")
elif n <= 80:
    print("Excellent")
else:
    print("Outstanding")


# Solution 4: Using list of tuples
n = int(input())
ratings = [
    (50, "Average"),
    (60, "Good"),
    (80, "Excellent"),
    (100, "Outstanding")
]
for limit, rating in ratings:
    if n <= limit:
        print(rating)
        break


==================================================
==================================================
LBP196 - MODULAR EXPONENTIATION
==================================================


📚 PROBLEM STATEMENT
──────────────────


Given three numbers b, e, and m. Fill in a 
function that takes these three positive integer 
values and outputs b^e mod m.


INPUT: b, e and m values
OUTPUT: b^e mod m


EXAMPLE:
Input: 2 3 5


Calculate: 2^3 mod 5
  2^3 = 8
  8 mod 5 = 3


Output: 3


ANOTHER EXAMPLE:
Input: 5 3 7


Calculate: 5^3 mod 7
  5^3 = 125
  125 mod 7 = 6


Output: 6


📚 DEFINITION
──────────────


EXPONENTIATION:
- b^e means b raised to power e
- 2^3 = 2 × 2 × 2 = 8


MODULO:
- Remainder after division
- 8 mod 5 = 3 (8 divided by 5 gives remainder 3)


MODULAR EXPONENTIATION:
- (b^e) mod m
- Calculate b^e, then take modulo m


FORMULA:
(b^e) mod m


EXAMPLE:
(2^3) mod 5 = 8 mod 5 = 3
(5^3) mod 7 = 125 mod 7 = 6


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read three numbers: b, e, m
2. Calculate b raised to power e
3. Take modulo m of the result
4. Print result


FORMULA:
result = (b ** e) % m


APPROACH:
────────
Simple method:
  b_power_e = b ** e
  result = b_power_e % m


One-liner:
  result = (b ** e) % m


Or using pow() with 3 arguments:
  result = pow(b, e, m)


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


b, e, m = (int(i) for i in input().split())
# Read three integers from single line
# Example: input "2 3 5"
# b = 2, e = 3, m = 5


print(b**e%m)
# Calculate b^e mod m
# b**e = 2^3 = 8
# 8 % m = 8 % 5 = 3
# Output: 3


EXPLANATION:
────────────


Line 1: b, e, m = (int(i) for i in input().split())
  → input() reads entire line
  → .split() splits by spaces
  → Generator converts each to int
  → Unpacks into b, e, m
  → Example: "2 3 5" → b=2, e=3, m=5


Line 4: print(b**e%m)
  → b**e calculates b raised to power e
  → ** is exponentiation operator
  → 2**3 = 2×2×2 = 8

  → %m takes modulo m
  → 8 % 5 = 3 (remainder when 8÷5)

  → print() outputs result
  → Output: 3


OPERATOR PRECEDENCE:
───────────────   ───
In Python:
  ** (exponentiation) has higher precedence than %
  So: b**e%m = (b**e) % m


Calculation order:
  1. 2**3 = 8
  2. 8 % 5 = 3


==================================================
🔢 DETAILED EXECUTION
═════════════════════


EXAMPLE 1: Input 2 3 5
────────────────────


input() reads: "2 3 5"
.split() gives: ["2", "3", "5"]
After conversion: b=2, e=3, m=5


Calculation:
  b**e = 2**3 = 2×2×2 = 8
  b**e%m = 8%5 = 3 (8÷5 = 1 remainder 3)


print(3)


Output: 3 ✓


──────────────────────────────────────────────


EXAMPLE 2: Input 5 3 7
────────────────────


b=5, e=3, m=7


Calculation:
  5**3 = 5×5×5 = 125
  125%7 = 6 (125÷7 = 17 remainder 6)


Output: 6 ✓


──────────────────────────────────────────────


EXAMPLE 3: Input 10 2 3
────────────────────


b=10, e=2, m=3


Calculation:
  10**2 = 100
  100%3 = 1 (100÷3 = 33 remainder 1)


Output: 1 ✓


==================================================
🔄 ALTERNATIVE SOLUTIONS
════════════   ════════════


# Solution 1: Given (one-liner)
b, e, m = (int(i) for i in input().split())
print(b**e%m)


# Solution 2: Step by step
b, e, m = (int(i) for i in input().split())
result = b**e
result = result % m
print(result)


# Solution 3: Using pow() function
b, e, m = (int(i) for i in input().split())
print(pow(b, e, m))


# Solution 4: With variable assignment
b, e, m = (int(i) for i in input().split())
power_result = b ** e
modulo_result = power_result % m
print(modulo_result)


# Solution 5: Direct calculation
b, e, m = map(int, input().split())
print((b**e) % m)


==================================================
📝 MATH NOTATION
═════════════════


Mathematical notation: b^e mod m
Python notation: b**e % m
Alternative Python: pow(b, e, m)


Example:
  Math: 2^3 mod 5
  Python: 2**3 % 5 or pow(2, 3, 5)
  Result: 3


==================================================
==================================================
LBP197 - BACKSPACE STRING COMPARE
==================================================


📚 PYTHON join() METHOD
═══════════════════════


DEFINITION:
───────────


join() combines list elements into one string


Syntax:- separator.join(iterable)


Examples:
  ''.join(['a','b','c']) = "abc"
  ', '.join(['a','b','c']) = "a, b, c"
  '-'.join(['hello','world']) = "hello-world"


==================================================
join() is a Python string method that:
- Takes an iterable (list, tuple, etc.)
- Combines all elements into a single string
- Uses the string as separator between elements
- Returns the joined string


SYNTAX:
───────
separator.join(iterable)


Parameters:
  - separator: string to use between elements
  - iterable: list/tuple of strings to join


EXAMPLES:
─────────


Example 1: Basic join
  fruits = ['apple', 'banana', 'orange']
  result = ', '.join(fruits)
  # Result: "apple, banana, orange"


Example 2: Join with no separator
  letters = ['a', 'b', 'c', 'd']
  result = ''.join(letters)
  # Result: "abcd"


Example 3: Join with dash separator
  words = ['hello', 'world', 'python']
  result = '-'.join(words)
  # Result: "hello-world-python"


Example 4: Join list of numbers (converted to strings)
  numbers = ['1', '2', '3']
  result = ' '.join(numbers)
  # Result: "1 2 3"


COMPARISON WITH OTHER METHODS:
──────────────────────────────
  split() - opposite of join(), splits string into list
  append() - adds element to list

  split() vs join():
    ''.join(['a','b','c']) = "abc"
    "abc".split('') = ERROR (empty separator not allowed)
    "a,b,c".split(',') = ['a', 'b', 'c']
    ','.join(['a','b','c']) = "a,b,c"


==================================================
LBP197 - BACKSPACE STRING COMPARE
==================================================


📚 PROBLEM STATEMENT
──────────────────


Two strings are said to the same if they are of 
the same length and have the same character at 
each index. Backspacing in a string removes the 
previous character in the string.


Given two strings containing lowercase english 
letters and the character '#' which represents a 
backspace key. determine if the two final 
strings are equal or not. Return 1 if they are 
equal else 0.


INPUT: two strings s1 and s2
OUTPUT: 1 or 0


EXAMPLE:
Input: 
  s1 = "ab#c"
  s2 = "ad#c"


Processing s1:
  a → add 'a'
  b → add 'b'
  # → backspace, remove previous 'b'
  c → add 'c'
  Final: "ac"


Processing s2:
  a → add 'a'
  d → add 'd'
  # → backspace, remove previous 'd'
  c → add 'c'
  Final: "ac"


Are they equal? "ac" == "ac" → YES
Output: 1




📚 DEFINITION
──────────────


BACKSPACE (#):
- Removes previous character
- Like pressing backspace key
- '#' represents backspace operation


FINAL STRING:
- String after all backspaces processed
- Only regular characters remain


EQUAL STRINGS:
- Same characters in same order
- Same length


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read two strings s1 and s2
2. Process s1:
   - For each character:
     - If '#': remove previous char (backspace)
     - Else: add character to list
3. Process s2 similarly
4. Compare final strings
5. Return 1 if equal, 0 if different


APPROACH:
────────
Use two lists l1 and l2
For each character in string:
  - If character is '#' AND previous exists:
    - Don't add it (skip backspace char)
  - Else if character is NOT '#':
    - Add to list
Join lists and compare


==================================================
💻 CODE WITH COMMENTS (SCREENSHOT CODE)
═════════════════════════════════════════


s1 = input()
# Read first string
# Example: s1 = "ab#c"


s2 = input()
# Read second string
# Example: s2 = "ad#c"


l1 = []
# List to store processed characters of s1


l2 = []
# List to store processed characters of s2


for i in range(len(s1)-1):
    # Loop through s1, except last character
    # range(len(s1)-1) gives indices 0 to len-2
    # Example: "ab#c" has length 4
    #          range(3) = 0, 1, 2

    if s1[i] != '#' and s1[i+1] != '#':
        # Check if current char is NOT '#'
        # AND next character is NOT '#'
        # This means we should add current char
        # (it won't be followed by backspace)

        l1.append(s1[i])
        # Add character to l1


for i in range(len(s2)-1):
    # Same logic for s2

    if s2[i] != '#' and s2[i+1] != '#':
        # Check both conditions

        l2.append(s2[i])
        # Add character to l2


print(1 if ''.join(l1) == ''.join(l2) else 0)
# Compare final strings
# ''.join(l1) converts list to string
# Example: ['a', 'c'] → "ac"
# If strings equal: print 1
# Else: print 0




BETTER APPROACH:
────────────────


s1 = input()
s2 = input()


def process(s):
    result = []
    for char in s:
        if char == '#':
            if result:  # if list not empty
                result.pop()  # remove last element
        else:
            result.append(char)
    return result


l1 = process(s1)
l2 = process(s2)


print(1 if ''.join(l1) == ''.join(l2) else 0)
==================================================
💡 KEY POINTS
══════════════


join() METHOD:
- ''.join(list) joins with empty separator
- ' '.join(list) joins with space separator
- ','.join(list) joins with comma separator


BACKSPACE LOGIC:
- '#' means remove previous character
- Use list.pop() to remove last element
- If no previous char, '#' does nothing


ALGORITHM:
- Process each character
- If '#': remove previous (pop)
- Else: add character (append)
- Compare final strings


COMPARISON:
- Convert lists to strings using join()
- Compare strings with ==
- Return 1 if equal, 0 if different


==================================================
📊 BACKSPACE PROCESSING TABLE
═══════════════════════════════


Input    | Processing            | Final
──────────────────────────────────────────
"ab#c"   | a,b,#(pop),c → ac     | "ac"
"a##c"   | a,#(pop),#(pop),c→ c  | "c"
"a#b#c"  | a,#,b,#,c → c         | "c"
"abc"    | a,b,c → abc           | "abc"
"a#b#c#" | a,#,b,#,c,# → ""      | ""
"####"   | all backspace → ""    | ""


==================================================
==================================================
LBP198 - TOKEN NUMBER
==================================================


📚 PROBLEM STATEMENT
──────────────────


Write an algorithm to generate the token number 
from the application ID by doing these 
modifications:


R1. If the digit is even add 1 to it.
R2. If the digit is odd sub 1 from it.


INPUT: a number from the user
OUTPUT: token number


EXAMPLE:
Input: 45789


Processing each digit:
  4 (even) → 4+1 = 5
  5 (odd) → 5-1 = 4
  7 (odd) → 7-1 = 6
  8 (even) → 8+1 = 9
  9 (odd) → 9-1 = 8


Token number: 54698


Output: 54698 ✓


ANOTHER EXAMPLE:
Input: 98754


Processing:
  9 (odd) → 9-1 = 8
  8 (even) → 8+1 = 9
  7 (odd) → 7-1 = 6
  5 (odd) → 5-1 = 4
  4 (even) → 4+1 = 5


Token number: 89645


Output: 89645


📚 DEFINITION
──────────────


EVEN DIGIT:
- 0, 2, 4, 6, 8
- divisible by 2
- digit % 2 == 0


ODD DIGIT:
- 1, 3, 5, 7, 9
- not divisible by 2
- digit % 2 != 0


MODIFICATION RULES:
- Even: add 1
- Odd: subtract 1


TOKEN NUMBER:
- New number after applying rules to each digit


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read number as string (to access each digit)
2. For each digit:
   - Convert to integer
   - If even (digit % 2 == 0): add 1
   - If odd (digit % 2 != 0): subtract 1
   - Add modified digit to result
3. Print token number


APPROACH:
────────
Convert number to string to iterate digits
For each character:
  - Convert to int
  - Check if even or odd
  - Apply rule
  - Append to result string


==================================================
💻 BEST CODE (CLEAN & SHORT)
═════════════════════════════


n = input()
# Read number as string
# Example: n = "45789"


result = ""
# String to store token number


for digit in n:
    # Loop through each character (digit)

    d = int(digit)
    # Convert character to integer

    if d % 2 == 0:
        # If even (divisible by 2)
        result += str(d + 1)
        # Add 1 and convert to string, append

    else:
        # If odd (not divisible by 2)
        result += str(d - 1)
        # Subtract 1 and convert to string, append


print(result)
# Print final token number




EXAMPLE : Input 98754
────────────────────


n = "98754"
result = ""


digit='9': 9 is odd → 9-1=8 → result="8"
digit='8': 8 is even → 8+1=9 → result="89"
digit='7': 7 is odd → 7-1=6 → result="896"
digit='5': 5 is odd → 5-1=4 → result="8964"
digit='4': 4 is even → 4+1=5 → result="89645"


Output: 89645 ✓




💡 KEY POINTS
══════════════


EVEN CHECK:
- digit % 2 == 0
- Result is 0 if even
- Examples: 0,2,4,6,8 all give remainder 0


ODD CHECK:
- digit % 2 != 0 (or just else)
- Result is 1 if odd
- Examples: 1,3,5,7,9 all give remainder 1


CONVERSION:
- int(char) converts character to digit
- str(num) converts number back to string


STRING CONCATENATION:
- result += str(...) appends to string
- Builds token number character by character


==================================================
📊 DIGIT MODIFICATION TABLE
═════════════════════════════


Digit | Even/Odd | Operation | Result
──────────────────────────────────────
0     | Even     | 0+1       | 1
1     | Odd      | 1-1       | 0
2     | Even     | 2+1       | 3
3     | Odd      | 3-1       | 2
4     | Even     | 4+1       | 5
5     | Odd      | 5-1       | 4
6     | Even     | 6+1       | 7
7     | Odd      | 7-1       | 6
8     | Even     | 8+1       | 9
9     | Odd      | 9-1       | 8


==================================================
🔄 ALTERNATIVE SOLUTIONS
═════════════════════════


# Solution 1: Using list comprehension
n = input()
token = ''.join(str(int(d)+1 if int(d)%2==0 else int(d)-1) for d in n)
print(token)


# Solution 2: Using function
def modify_digit(d):
    if d % 2 == 0:
        return d + 1
    else:
        return d - 1


n = input()
result = ''.join(str(modify_digit(int(d))) for d in n)
print(result)


# Solution 3: Using map
n = input()
def token_rule(d):
    d = int(d)
    return str(d+1 if d%2==0 else d-1)
print(''.join(map(token_rule, n)))


==================================================
==================================================
LBP199 - SCORE OF THE PLAYER (BRAIN FUN GAME)
==================================================


📚 PROBLEM STATEMENT
──────────────────


A game developing company has developed a math 
game for kids called "Brain Fun". The game is for 
smartphone users and the player is given list of 
N positive numbers and a random number K. The 
player need to divide all the numbers in the list 
with random number k and then need to add all the 
quotients received in each division. The sum of 
all the quotients is the score of the player.


Write an algorithm to generate the score of the 
player.


INPUT: array size, elements and random number k
OUTPUT: an int value (score)


EXAMPLE:
Input: 
  n = 5
  array = [10, 20, 30, 40, 50]
  k = 5


Processing:
  10 / 5 = 2 (quotient)
  20 / 5 = 4 (quotient)
  30 / 5 = 6 (quotient)
  40 / 5 = 8 (quotient)
  50 / 5 = 10 (quotient)


Score = 2 + 4 + 6 + 8 + 10 = 30


Output: 30


ANOTHER EXAMPLE:
Input:
  n = 4
  array = [12, 24, 36, 48]
  k = 3


Processing:
  12 / 3 = 4
  24 / 3 = 8
  36 / 3 = 12
  48 / 3 = 16


Score = 4 + 8 + 12 + 16 = 40


Output: 40


📚 DEFINITION
──────────────


QUOTIENT:
- Result of integer division (without remainder)
- 10 / 5 = 2
- 15 / 3 = 5
- Integer division: a // b


DIVISION WITH RANDOM NUMBER K:
- Divide each array element by k
- Keep only the quotient (whole number part)
- Ignore remainder


SCORE:
- Sum of all quotients
- Total of all division results


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read array size n
2. Read n array elements
3. Read random number k
4. For each element in array:
   - Divide element by k (integer division)
   - Get quotient
   - Add to score
5. Print total score


FORMULA:
score = Σ(a[i] // k) for all i


APPROACH:
────────
Initialize score = 0
For each element in array:
  quotient = element // k (integer division)
  score += quotient
Print score


==================================================
💻 BEST CODE (CLEAN & SHORT)
═════════════════════════════


n = int(input())
# Read array size
# Example: n = 5


a = [int(i) for i in input().split()]
# Read array elements
# Example: a = [10, 20, 30, 40, 50]


k = int(input())
# Read random number k
# Example: k = 5


score = 0
# Initialize score to 0


for num in a:
    # Loop through each element in array

    score += num // k
    # Divide by k (integer division)
    # Add quotient to score
    # num // k = 10 // 5 = 2


print(score)
# Print final score


EXPLANATION:
────────────


Line 1-3: Input
  n = 5
  a = [10, 20, 30, 40, 50]
  k = 5


Line 5: score = 0
  → Initialize score counter


Line 7-9: Loop
  for num in a:
    → Iterate through each element
    → num = 10, 20, 30, 40, 50

    score += num // k
    → Integer division (//)
    → 10 // 5 = 2
    → Add quotient to score

    Iterations:
      10 // 5 = 2 → score = 2
      20 // 5 = 4 → score = 6
      30 // 5 = 6 → score = 12
      40 // 5 = 8 → score = 20
      50 // 5 = 10 → score = 30


Line 11: print(score)
  → Output: 30


==================================================
🔢 DETAILED EXECUTION
═════════════════════


EXAMPLE 1: Input 5, [10,20,30,40,50], k=5
────────────────────────────────────────


n = 5
a = [10, 20, 30, 40, 50]
k = 5
score = 0


Loop iteration 1: num = 10
  score += 10 // 5 = 2
  score = 2


Loop iteration 2: num = 20
  score += 20 // 5 = 4
  score = 6


Loop iteration 3: num = 30
  score += 30 // 5 = 6
  score = 12


Loop iteration 4: num = 40
  score += 40 // 5 = 8
  score = 20


Loop iteration 5: num = 50
  score += 50 // 5 = 10
  score = 30


print(30)


Output: 30 ✓


──────────────────────────────────────────────


EXAMPLE 2: Input 4, [12,24,36,48], k=3
──────────────────────────────────


n = 4
a = [12, 24, 36, 48]
k = 3
score = 0


Loop iteration 1: 12 // 3 = 4 → score = 4
Loop iteration 2: 24 // 3 = 8 → score = 12
Loop iteration 3: 36 // 3 = 12 → score = 24
Loop iteration 4: 48 // 3 = 16 → score = 40


Output: 40 ✓




══════════════


INTEGER DIVISION (//):
- Divides and returns only quotient
- Ignores remainder
- 10 // 3 = 3 (not 3.33...)
- 20 // 5 = 4 (exact division)


QUOTIENT:
- Result of division (without decimal)
- 10 / 5 = 2 quotient, 0 remainder
- 15 / 4 = 3 quotient, 3 remainder


ACCUMULATOR PATTERN:
- score = 0 (initialize)
- score += num // k (accumulate)
- Works for sum, product, etc.


INPUT FORMAT:
- First line: array size n
- Second line: n space-separated elements
- Third line: random number k


==================================================
📊 CALCULATION TABLE
═════════════════════


Array Element | k | Quotient | Running Score
──────────────────────────────────────────────
10            | 5 | 2        | 2
20            | 5 | 4        | 6
30            | 5 | 6        | 12
40            | 5 | 8        | 20
50            | 5 | 10       | 30


==================================================
🔄 ALTERNATIVE SOLUTIONS
═════════════════════════


# Solution 1: Using sum() with list comprehension
n = int(input())
a = [int(i) for i in input().split()]
k = int(input())
print(sum(num // k for num in a))


# Solution 2: Using map()
n = int(input())
a = list(map(int, input().split()))
k = int(input())
score = sum(x // k for x in a)
print(score)


# Solution 3: With function
def calculate_score(arr, k):
    return sum(num // k for num in arr)


n = int(input())
a = [int(i) for i in input().split()]
k = int(input())
print(calculate_score(a, k))


==================================================
==================================================
LBP200 - PERFECT MATCH (SUM OF REMAINDERS)
==================================================


📚 PROBLEM STATEMENT
──────────────────


Perfect match is an online math program. In one of 
the assignments the system displays a list of N 
numbers and a value K, and students need to 
calculate the sum of remainders after dividing 
all the numbers from the list of N numbers by K. 
The system need to develop a program to calculate 
the correct answer for the assignment.


Write an algorithm to calculate the correct 
answer for the assignment.


INPUT: array size, elements and divisor K
OUTPUT: sum of remainders


EXAMPLE:
Input: 
  n = 5
  array = [10, 20, 30, 40, 50]
  k = 5


Processing (remainder = number % k):
  10 % 5 = 0 (remainder)
  20 % 5 = 0 (remainder)
  30 % 5 = 0 (remainder)
  40 % 5 = 0 (remainder)
  50 % 5 = 0 (remainder)


Sum of remainders = 0 + 0 + 0 + 0 + 0 = 0


Output: 0


ANOTHER EXAMPLE:
Input:
  n = 4
  array = [10, 15, 20, 25]
  k = 3


Processing:
  10 % 3 = 1
  15 % 3 = 0
  20 % 3 = 2
  25 % 3 = 1


Sum of remainders = 1 + 0 + 2 + 1 = 4


Output: 4


ANOTHER EXAMPLE:
Input:
  n = 3
  array = [7, 8, 9]
  k = 2


Processing:
  7 % 2 = 1 (7 = 3*2 + 1)
  8 % 2 = 0 (8 = 4*2 + 0)
  9 % 2 = 1 (9 = 4*2 + 1)


Sum of remainders = 1 + 0 + 1 = 2


Output: 2


📚 DEFINITION
──────────────


REMAINDER:
- What's left after division
- a % b gives remainder when a is divided by b
- 10 % 3 = 1 (10 = 3*3 + 1)
- 20 % 7 = 6 (20 = 2*7 + 6)


MODULO OPERATOR (%):
- Returns remainder of division
- Always positive (less than divisor)
- Example: 15 % 4 = 3


SUM OF REMAINDERS:
- Add all remainders together
- Total of all (number % k)


==================================================
💻 SYNTAX & LOGIC
──────────────────


LOGIC:
1. Read array size n
2. Read n array elements
3. Read divisor K
4. For each element in array:
   - Calculate remainder: element % k
   - Add to sum
5. Print total sum of remainders


FORMULA:
sum = Σ(a[i] % k) for all i


APPROACH:
────────
Initialize sum = 0
For each element in array:
  remainder = element % k
  sum += remainder
Print sum


==================================================
💻 BEST CODE (CLEAN & SHORT)
═════════════════════════════


n = int(input())
# Read array size
# Example: n = 4


a = [int(i) for i in input().split()]
# Read array elements
# Example: a = [10, 15, 20, 25]


k = int(input())
# Read divisor K
# Example: k = 3


total = 0
# Initialize sum to 0


for num in a:
    # Loop through each element

    total += num % k
    # Calculate remainder and add to total
    # num % k = remainder when num divided by k


print(total)
# Print sum of all remainders


EXPLANATION:
────────────


Line 1-3: Input
  n = 4
  a = [10, 15, 20, 25]
  k = 3


Line 5: total = 0
  → Initialize sum counter


Line 7-10: Loop
  for num in a:
    → num = 10, 15, 20, 25

    total += num % k
    → Calculate remainder
    → 10 % 3 = 1
    → 15 % 3 = 0
    → 20 % 3 = 2
    → 25 % 3 = 1

    Accumulate:
      total = 0 + 1 = 1
      total = 1 + 0 = 1
      total = 1 + 2 = 3
      total = 3 + 1 = 4


Line 12: print(total)
  → Output: 4


==================================================
🔢 DETAILED EXECUTION
═════════════════════


EXAMPLE 1: Input 4, [10,15,20,25], k=3
────────────────────────────────────


n = 4
a = [10, 15, 20, 25]
k = 3
total = 0


Loop iteration 1: num = 10
  remainder = 10 % 3 = 1
  total += 1 → total = 1


Loop iteration 2: num = 15
  remainder = 15 % 3 = 0
  total += 0 → total = 1


Loop iteration 3: num = 20
  remainder = 20 % 3 = 2
  total += 2 → total = 3


Loop iteration 4: num = 25
  remainder = 25 % 3 = 1
  total += 1 → total = 4


print(4)


Output: 4 ✓


──────────────────────────────────────────────


EXAMPLE 2: Input 5, [10,20,30,40,50], k=5
──────────────────────────────────────────


n = 5
a = [10, 20, 30, 40, 50]
k = 5
total = 0


All divisible by 5:
  10 % 5 = 0 → total = 0
  20 % 5 = 0 → total = 0
  30 % 5 = 0 → total = 0
  40 % 5 = 0 → total = 0
  50 % 5 = 0 → total = 0


Output: 0 ✓




💡 KEY POINTS
══════════════


MODULO OPERATOR (%):
- Returns remainder after division
- a % b gives remainder when a ÷ b
- Result is always < b
- 10 % 3 = 1, 20 % 7 = 6


REMAINDER PROPERTIES:
- 0 % k = 0 (0 divided by k has remainder 0)
- k % k = 0 (k divided by k has remainder 0)
- (k-1) % k = k-1 (largest remainder)


ACCUMULATOR PATTERN:
- total = 0 (initialize)
- total += num % k (accumulate)
- Works for any sum operation


DIFFERENCE FROM LBP199:
- LBP199: Sum of quotients (// operator)
- LBP200: Sum of remainders (% operator)
- Similar approach, different operation


==================================================
📊 REMAINDER CALCULATION TABLE
═══════════════════════════════


Array Element | k | Remainder | Running Total
──────────────────────────────────────────────
10            | 3 | 1         | 1
15            | 3 | 0         | 1
20            | 3 | 2         | 3
25            | 3 | 1         | 4


==================================================
🔄 ALTERNATIVE SOLUTIONS
═════════════════════════


# Solution 1: Using sum() with list comprehension
n = int(input())
a = [int(i) for i in input().split()]
k = int(input())
print(sum(num % k for num in a))


# Solution 2: Using map()
n = int(input())
a = list(map(int, input().split()))
k = int(input())
print(sum(x % k for x in a))


# Solution 3: With function
def sum_of_remainders(arr, k):
    return sum(num % k for num in arr)


n = int(input())
a = [int(i) for i in input().split()]
k = int(input())
print(sum_of_remainders(a, k))


==================================================
📊 COMPARISON: LBP199 vs LBP200
═════════════════════════════════


Property      | LBP199          | LBP200
──────────────────────────────────────────────
Name          | Score (Quotient)| Sum Remainder
Operation     | a[i] // k       | a[i] % k
Returns       | Quotient        | Remainder
Result Type   | Whole number    | Whole number
Example Input | [10,20,30], k=5 | [10,20,30], k=5
Example Result| 2+4+6 = 12      | 0+0+0 = 0


==================================================










================================================================
PLB251 - MULTIPLES OF 10 (MOVE TO END)
================================================================


PROBLEM:
Given an array, move all multiples of 10 to the end of the array.


NOTE:
- Order of non-multiples should remain same ✔
- Order of multiples of 10 should remain same ✔




================================
INPUT
================================


n -> size of array  
array elements  




================================
OUTPUT
================================


Print updated array




================================
PYTHON INPUT + STRING PROCESS
================================


input() always takes data as STRING


Example:
Input: 10 11 20 15 30 45 50


input() → "10 11 20 15 30 45 50"  
split() → ['10','11','20','15','30','45','50']  
int(i) → [10,11,20,15,30,45,50]  


Final:
L = [10,11,20,15,30,45,50]




================================
LOGIC
================================


1. Take array L
2. Print elements NOT divisible by 10
3. Then print elements divisible by 10
4. Maintain order




================================
METHOD 1 (TWO LOOPS - SIMPLE)
================================


# Take size
n = int(input())


# Take elements
L = [int(i) for i in input().split()]


# First print non-multiples
for i in L:
    if i % 10 != 0:
        print(i, end=' ')


# Then print multiples of 10
for i in L:
    if i % 10 == 0:
        print(i, end=' ')




================================
IMPORTANT POINT
================================


i % 10 == 0 → multiple of 10  
i % 10 != 0 → not multiple  




================================
EXAMPLE
================================


INPUT:
7
10 11 20 15 30 45 50


Step 1 (non-multiples):
11 15 45


Step 2 (multiples):
10 20 30 50


OUTPUT:
11 15 45 10 20 30 50




================================
TIME COMPLEXITY
================================


→ O(n) ✔ (two passes but still linear)




================================
METHOD 2 (USING LIST)
================================


non = []
mul = []


for i in L:
    if i % 10 != 0:
        non.append(i)
    else:
        mul.append(i)


print(*(non + mul))




================================
ADVANTAGE
================================


- Clean separation ✔  
- Order preserved ✔  




================================
METHOD 3 (LIST COMPREHENSION)
================================


non = [i for i in L if i % 10 != 0]
mul = [i for i in L if i % 10 == 0]


print(*(non + mul))




================================
METHOD 4 (PYTHONIC)
================================


print(*[i for i in L if i % 10 != 0],
      *[i for i in L if i % 10 == 0])




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


FOR each element
    IF not multiple of 10
        PRINT


FOR each element
    IF multiple of 10
        PRINT


END




================================
INTERVIEW LINE
================================


"This is a stable partition problem where elements are rearranged 
based on a condition while preserving their relative order."




================================================================
PLB252
================================================================


Employee's Rating Point


In a company, an employee's rating point (ERP) is calculated as the sum of the rating points given by the employee's manager and HR. 
The employee rating grade (ERG) is calculated according to the ERP ranges given below.


ERP      ERG
30-50    D
51-60    C
61-80    B
81-100   A


Write an algorithm to find the ERG character for a given employee's ERP.


input ------> an integer value  
con --------> con  
output -----> employee rating grade




================================
INPUT
================================


n -> ERP value (integer)




================================
OUTPUT
================================


Print employee rating grade (A/B/C/D)




================================
LOGIC
================================


1. Take ERP value n
2. Check range:
   30-50  → D
   51-60  → C
   61-80  → B
   81-100 → A
3. Print corresponding grade




================================
PYTHON CODE (MAIN)
================================


# Take input
n = int(input())


# Check ranges
if n >= 30 and n <= 50:
    print("D")


elif n >= 51 and n <= 60:
    print("C")


elif n >= 61 and n <= 80:
    print("B")


elif n >= 81 and n <= 100:
    print("A")




================================
IMPORTANT POINT
================================


Use range checking:


n >= lower AND n <= upper


Each range must be mutually exclusive




================================
EXAMPLE
================================


INPUT:
45


OUTPUT:
D




--------------------------------


INPUT:
75


OUTPUT:
B




================================
TIME COMPLEXITY
================================


→ O(1) ✔




================================
METHOD 2 (SIMPLIFIED)
================================


if 30 <= n <= 50:
    print("D")


elif 51 <= n <= 60:
    print("C")


elif 61 <= n <= 80:
    print("B")


elif 81 <= n <= 100:
    print("A")




================================
EDGE CASE
================================


if n < 30 or n > 100:
    print("Invalid input")




================================
PSEUDO CODE
================================


START
INPUT n


IF 30-50 → D  
ELSE IF 51-60 → C  
ELSE IF 61-80 → B  
ELSE IF 81-100 → A  


END




================================
INTERVIEW LINE
================================


"Range-based classification can be implemented using conditional statements with constant time complexity O(1)."
================================================================
PLB253
================================================================


encrypted digits


A company trasfers an encrypted code to one of its clients. 
The code needed to be decrypted so that it can be used for accessing all the required information. 
The code can be decrypted by interchanging each consecutive digit and once if the digit got interchanged then it cannot be used again. 
If at a certain point there is no digits to be interchanged with, then that single digit must be left as it is.


Write an algorithm to decrypt the code so that it can be used to access the required information.


input ------> a number from the user  
con --------> no  
output -----> an integer value  




================================
UNDERSTANDING
================================


Swap every pair of digits:


Example:
1234 → 2 1 4 3  
12345 → 2 1 4 3 5  (last stays same)




================================
PYTHON INPUT + STRING PROCESS
================================


# input() takes string


Example:
input() → "1 2 3 4"


split() → ['1','2','3','4']  
int(i) → [1,2,3,4]  


Final:
L = [1,2,3,4]




================================
LOGIC
================================


1. Take size n
2. Take list L
3. Traverse in steps of 2
4. Swap L[i] and L[i+1]
5. If last element remains → print as it is




================================
METHOD 1 (YOUR LOGIC WITH COMMENTS)
================================


# Take size of array
n = int(input())


# Take elements and convert to list
L = [int(i) for i in input().split()]


# If number of elements is even
if n % 2 == 0:

    i = 0  # start index

    # Loop through all elements
    while i < n:

        # Swap and print current pair
        print(L[i+1], L[i], end=' ')

        # Move to next pair
        i += 2


# If number of elements is odd
else:

    i = 0

    # Loop till second last element
    while i < n-1:

        # Swap adjacent elements
        print(L[i+1], L[i], end=' ')

        # Move to next pair
        i += 2

    # Print last element as it is
    print(L[n-1])




================================
METHOD 2 (SIMPLER WHILE LOOP)
================================


# Take input
n = int(input())
L = [int(i) for i in input().split()]


i = 0


# Loop pair-wise
while i < n-1:

    # Swap and print
    print(L[i+1], L[i], end=' ')

    # Move to next pair
    i += 2


# If odd length → print last element
if n % 2 != 0:
    print(L[-1])




================================
METHOD 3 (BEST - INPLACE SWAP)
================================


# Take input
n = int(input())
L = [int(i) for i in input().split()]


# Traverse in steps of 2
for i in range(0, n-1, 2):

    # Swap elements directly
    L[i], L[i+1] = L[i+1], L[i]


# Print final array
print(*L)




================================
IMPORTANT POINT
================================


i += 2
→ move to next pair


L[i], L[i+1]
→ adjacent elements


Odd case:
last element remains unchanged




================================
EXAMPLE
================================


INPUT:
5
1 2 3 4 5


Pairs:
(1,2) → 2 1  
(3,4) → 4 3  
5 → same  


OUTPUT:
2 1 4 3 5




================================
TIME COMPLEXITY
================================


→ O(n) ✔




================================
PSEUDO CODE
================================


START
INPUT n
INPUT array L


FOR i = 0 to n-1 step 2
    SWAP L[i] and L[i+1]


IF odd
    last element same


PRINT array


END




================================
INTERVIEW LINE
================================


"Adjacent elements can be swapped efficiently by traversing the array with a step size of 2."


================================================================
PLB255
================================================================


player's score


In a game, organizers has given a number to the player. 
The player has to find out the difference between the number and the reverse of the number. 
The difference between two numbers is the player's score. 
The number given to the player and the player's score can be a negative or positive number.


Write an algorithm to find the player's score.


input ------> an integer  
con --------> no  
output -----> player's score  




================================
UNDERSTANDING
================================


Score = number - reverse(number)


Example:
Input: 123  
Reverse: 321  


Score = 123 - 321 = -198  




================================
PYTHON INPUT + STRING PROCESS
================================


input() → "123"


Reverse string:
n[::-1] → "321"


Convert to int:
int("321") → 321




================================
LOGIC
================================


1. Take input n
2. Reverse the number
3. Convert both to integer
4. Subtract:
   n - reverse(n)
5. Print result




================================
METHOD 1 (STRING REVERSAL - BEST)
================================


# Take input as string
n = input()


# Reverse string using slicing
rev = n[::-1]   # reverse


# Convert to integer and subtract
print(int(n) - int(rev))




================================
IMPORTANT COMMENT
================================


n[::-1]
→ reverses string


Example:
"123"[::-1] → "321"




================================
EXAMPLE
================================


INPUT:
123


REVERSE:
321


OUTPUT:
-198




================================
METHOD 2 (WITHOUT STRING)
================================


# Take input
n = int(input())


temp = n
rev = 0


# Reverse using math
while temp > 0:

    digit = temp % 10      # last digit
    rev = rev * 10 + digit  # build reverse
    temp = temp // 10       # remove last digit


# Print result
print(n - rev)




================================
ADVANTAGE
================================


- Works without string ✔  
- Useful for interviews ✔  




================================
METHOD 3 (ONE LINE)
================================


n = input()


print(int(n) - int(n[::-1]))




================================
IMPORTANT POINT
================================


Reverse logic:
123 → 321  


digit extraction:
n % 10 → last digit  
n // 10 → remove digit  




================================
TIME COMPLEXITY
================================


→ O(d) ✔ (d = number of digits)




================================
PSEUDO CODE
================================


START
INPUT n


REVERSE n


result = n - reverse


PRINT result


END




================================
INTERVIEW LINE
================================


"Number reversal can be done using string slicing or mathematical approach. 
Final score is computed as difference between original and reversed number."


================================================================
PLB256 - GlobalAdd
================================================================


PROBLEM:


The media company "GlobalAdd" has received a batch of advertisements from different product brands.


The batch of advertisements is a numeric value where each digit represents the number of advertisements 
the media company has received from different product brands.


Since the company banners permit only even numbers of advertisements to be displayed, 
the media company needs to know the total number of advertisements it will be able to display 
from the given batch.


Write an algorithm to calculate the total number of advertisements that will be displayed from the batch.


input ------> an integer  
con --------> no  
output -----> count of advertisements  




================================
UNDERSTANDING
================================


Each digit = advertisements from a brand


Only EVEN digits are allowed


So we need to:
👉 count how many digits are EVEN




--------------------------------
Example:
--------------------------------


Input:
123456


Digits:
1 2 3 4 5 6


Even digits:
2, 4, 6


Count = 3 ✔




================================
LOGIC
================================


1. Take input number n
2. Extract last digit using n % 10
3. Check if digit is even (d % 2 == 0)
4. If yes → count++
5. Remove last digit (n //= 10)
6. Repeat until n becomes 0
7. Print count




================================
PYTHON CODE (WITH COMMENTS)
================================


# Take input
n = int(input())


c = 0   # counter for even digits


# Loop until number becomes 0
while n != 0:


    d = n % 10      # get last digit


    # check if digit is even
    if d % 2 == 0:
        c = c + 1


    n = n // 10     # remove last digit


# Print result
print(c)




================================
STEP BY STEP TRACE
================================


Input: 24631


Iteration 1:
d = 1 → odd → skip


Iteration 2:
d = 3 → odd → skip


Iteration 3:
d = 6 → even → count = 1


Iteration 4:
d = 4 → even → count = 2


Iteration 5:
d = 2 → even → count = 3


Final Output:
3 ✔




================================
IMPORTANT POINT
================================


n % 10 → last digit  
n // 10 → remove last digit  


d % 2 == 0 → even check  




================================
METHOD 2 (STRING METHOD - EASY)
================================


n = input()


c = 0


for i in n:
    if int(i) % 2 == 0:
        c += 1


print(c)




================================
METHOD 3 (ONE LINE - PYTHONIC)
================================


n = input()


print(sum(1 for i in n if int(i) % 2 == 0))




================================
TIME COMPLEXITY
================================


→ O(d) ✔ (d = number of digits)




================================
PSEUDO CODE
================================


START
INPUT n


SET count = 0


WHILE n > 0
    d = n % 10


    IF d is even
        count++


    n = n // 10


PRINT count
END




================================
INTERVIEW LINE
================================


"Digit extraction using modulus and division helps process numbers without converting to string. 
Even digits are counted using simple modulo condition."


================================================================
PLB257 - FunGames
================================================================


PROBLEM:


The games development company "FunGames" has developed a balloon shooter game.


The balloons are arranged in a linear sequence and each balloon has a number associated with it.  
The numbers on the balloons are Fibonacci series.


In the game the player shoots 'k' balloons.  
The player's score is the sum of numbers on k balloons.


Write an algorithm to generate the player's score.


input ------> an integer value k  
con --------> no  
output -----> sum value  




================================
UNDERSTANDING
================================


Fibonacci Series:
0 1 1 2 3 5 8 ...


Each number = sum of previous two numbers


We need:
👉 sum of first k Fibonacci numbers




--------------------------------
Example:
--------------------------------


k = 1 → 0  
k = 3 → 0 + 1 + 1 = 2 ✔  




================================
LOGIC
================================


1. Initialize first two Fibonacci numbers
2. Generate next numbers
3. Keep adding them
4. Repeat k times
5. Print sum




================================
PYTHON CODE (WITH COMMENTS)
================================


# Take input
k = int(input())


# First two Fibonacci numbers
a1 = -1   # trick to generate 0 first
a2 = 1


sum = 0   # to store sum


# Generate k Fibonacci numbers
for i in range(1, k+1):


    a3 = a1 + a2      # next Fibonacci number


    sum = sum + a3    # add to sum


    # update values
    a1, a2 = a2, a3


# Print result
print(sum)




================================
IMPORTANT COMMENT
================================


a1 = -1, a2 = 1
→ This trick generates sequence:
0, 1, 1, 2, 3, 5 ...




================================
STEP BY STEP TRACE
================================


k = 3


Iteration 1:
a3 = 0 → sum = 0


Iteration 2:
a3 = 1 → sum = 1


Iteration 3:
a3 = 1 → sum = 2


Final Output:
2 ✔




================================
METHOD 2 (STANDARD FIB)
================================


k = int(input())


a = 0
b = 1
sum = 0


for i in range(k):

    sum += a        # add current value

    a, b = b, a + b  # move forward


print(sum)




================================
METHOD 3 (RECURSIVE - NOT RECOMMENDED)
================================


def fib(n):
    if n <= 1:
        return n
    return fib(n-1) + fib(n-2)


k = int(input())


sum = 0
for i in range(k):
    sum += fib(i)


print(sum)




⚠ Slow → O(2^n)




================================
TIME COMPLEXITY
================================


→ O(k) ✔ (best method)




================================
PSEUDO CODE
================================


START
INPUT k


SET a = 0, b = 1
SET sum = 0


FOR i = 0 to k-1
    sum = sum + a
    next = a + b
    a = b
    b = next


PRINT sum
END




================================
INTERVIEW LINE
================================


"Fibonacci sequence is generated iteratively using two variables. 
Sum of first k terms can be computed in O(k) time without storing the entire sequence."






















































================================================================
ASCII CONCEPT (PYTHON - FULL GUIDE)
================================================================


DEFINITION:
ASCII = American Standard Code for Information Interchange


→ Each character has a numeric value
→ Used internally by computer to store characters





================================
IMPORTANT RANGES
================================


Digits      → 48 - 57  
Uppercase   → 65 - 90  
Lowercase   → 97 - 122  
================================
IMPORTANT ASCII VALUES
================================


'0' → 48  
'9' → 57  


'A' → 65  
'Z' → 90  


'a' → 97  
'z' → 122  




================================
CONVERSION FORMULA (VERY IMPORTANT)
================================


Uppercase → Lowercase:
chr(ord(ch) + 32)


Lowercase → Uppercase:
chr(ord(ch) - 32)




--------------------------------
WHY 32?
--------------------------------


ord('a') = 97  
ord('A') = 65  


Difference = 97 - 65 = 32 ✔




================================
CODE EXAMPLES
================================


# Lower → Upper
ch = 'a'
print(chr(ord(ch) - 32))   # A




# Upper → Lower
ch = 'A'
print(chr(ord(ch) + 32))   # a




# Full string conversion
s = "AbC"


result = ""


for ch in s:
    if 'a' <= ch <= 'z':
        result += chr(ord(ch) - 32)
    elif 'A' <= ch <= 'Z':
        result += chr(ord(ch) + 32)
    else:
        result += ch


print(result)




================================
INTERVIEW LINE
================================


"ASCII difference between uppercase and lowercase letters is 32. 
This allows quick conversion using ord() and chr()."






================================
PYTHON FUNCTIONS
================================


ord(ch)
→ character → ASCII value


chr(num)
→ ASCII value → character




================================
ABBREVIATION (IMPORTANT)
================================


ord = ordinal


→ ordinal means "order / position number"


So:
ord(ch)
→ gives the position (numeric code) of character


Example:
ord('A') = 65  




================================
CODE 1: CHARACTER → ASCII
================================


ch = input("Enter character: ")
print("ASCII value:", ord(ch))




================================
CODE 2: ASCII → CHARACTER
================================


num = int(input("Enter ASCII value: "))
print("Character:", chr(num))




================================
CODE 3: CHECK DIGIT (ASCII METHOD)
================================


ch = input()


if ord(ch) >= 48 and ord(ch) <= 57:
    print("Digit")
else:
    print("Not Digit")




================================
CODE 4: CHECK DIGIT (SHORTCUT)
================================


ch = input()


if ch.isdigit():
    print("Digit")
else:
    print("Not Digit")




================================
CODE 5: CHECK LOWERCASE
================================


ch = input()


if 'a' <= ch <= 'z':
    print("Lowercase")
else:
    print("Not Lowercase")




================================
CODE 6: CHECK UPPERCASE
================================


ch = input()


if 'A' <= ch <= 'Z':
    print("Uppercase")
else:
    print("Not Uppercase")




================================
CODE 7: CONVERT LOWER → UPPER
================================


ch = input()


# subtract 32 from ASCII
print(chr(ord(ch) - 32))




================================
CODE 8: CONVERT UPPER → LOWER
================================


ch = input()


# add 32 to ASCII
print(chr(ord(ch) + 32))




================================
CODE 9: NEXT CHARACTER
================================


ch = input()


print(chr(ord(ch) + 1))




================================
CODE 10: COUNT DIGITS IN STRING
================================


s = input()


count = 0


for ch in s:
    if '0' <= ch <= '9':
        count += 1


print(count)




================================
CODE 11: REMOVE DIGITS
================================


s = input()


result = ""


for ch in s:
    if not ch.isdigit():
        result += ch


print(result)




================================
LIST → ORDINAL CONVERSION
================================


PROBLEM:
Convert all characters in a list into ASCII values




--------------------------------
METHOD 1 (FOR LOOP)
--------------------------------


L = ['a', 'b', 'c']


result = []


for ch in L:
    result.append(ord(ch))


print(result)




--------------------------------
METHOD 2 (LIST COMPREHENSION - BEST)
--------------------------------


L = ['a', 'b', 'c']


result = [ord(ch) for ch in L]


print(result)




--------------------------------
METHOD 3 (STRING INPUT)
--------------------------------


s = input()


result = [ord(ch) for ch in s]


print(result)




--------------------------------
METHOD 4 (SAFE MIXED LIST)
--------------------------------


L = ['a', '1', 'b', '#']


result = []


for ch in L:
    if isinstance(ch, str) and len(ch) == 1:
        result.append(ord(ch))


print(result)




================================
REVERSE (ORDINAL → CHARACTER)
================================


L = [97, 98, 99]


result = [chr(i) for i in L]


print(result)




================================
IMPORTANT LOGIC
================================


ord('A') = 65  
ord('a') = 97  


Difference = 32  


Uppercase → Lowercase = +32  
Lowercase → Uppercase = -32  




================================
TIME COMPLEXITY
================================


→ O(n) ✔ (string/list traversal)




================================
INTERVIEW LINE
================================


"ord stands for ordinal and returns the numeric (ASCII/Unicode) position of a character. 
chr() performs the reverse operation. List elements can be converted using loops or list comprehension."




================================================================
PLB258 - The Past Book
================================================================


PROBLEM:


To create a profile on a social media account "ThePastBook",  
the user needs to enter a string value in the form of a username.


The username should consist of only characters tagged a-z.  
If the user enters an incorrect string containing digits,  
the system automatically identifies the number of digits in the string and removes them.


Write an algorithm to help the system identify the count of digits present in the username.


input ------> A string from the user  
con --------> no  
output -----> count of digits  




================================
UNDERSTANDING
================================


Input = string (username)


We need to:
👉 count how many digits are present


--------------------------------
Example:
--------------------------------


Input:
abc123xyz


Digits:
1, 2, 3


Output:
3 ✔




================================
LOGIC
================================


1. Take input string
2. Traverse each character
3. Check if character is digit
4. If yes → count++
5. Print count




================================
PYTHON CODE (WITH COMMENTS)
================================


# Take input
s = input()


c = 0   # counter for digits


# Traverse each character
for i in s:


    # check if character is digit
    if i.isdigit():
        c = c + 1


# Print result
print(c)




================================
IMPORTANT FUNCTION
================================


isdigit()


→ checks whether character is a digit (0–9)


Example:
'5'.isdigit() → True  
'a'.isdigit() → False  




================================
STEP BY STEP TRACE
================================


Input: a1b2c3


i = 'a' → not digit  
i = '1' → digit → count = 1  
i = 'b' → skip  
i = '2' → digit → count = 2  
i = 'c' → skip  
i = '3' → digit → count = 3  


Final Output:
3 ✔




================================
METHOD 2 (ONE LINE - PYTHONIC)
================================


s = input()


print(sum(1 for i in s if i.isdigit()))




================================
METHOD 3 (ASCII CHECK)
================================


s = input()


c = 0


for i in s:
    if '0' <= i <= '9':   # ASCII comparison
        c += 1


print(c)




================================
BONUS (REMOVE DIGITS ALSO)
================================


s = input()


new_str = ""


for i in s:
    if not i.isdigit():   # keep only characters
        new_str += i


print(new_str)




================================
TIME COMPLEXITY
================================


→ O(n) ✔ (n = length of string)




================================
PSEUDO CODE
================================


START
INPUT string s


SET count = 0


FOR each character in s
    IF character is digit
        count++


PRINT count
END




================================
INTERVIEW LINE
================================


"String traversal with built-in functions like isdigit() helps efficiently identify numeric characters."




================================================================
PLB259 - Morning Prayer
================================================================


PROBLEM:


Student of a school are assembled in a straight line for the morning prayer.  
To uplift the spirit of the students, an exercise is conducted.  


The initial letter of all the student's names is noted down (str).  
The task here is to substitute the initial letters in the list with consonants such that:


- If the initial letter of the student is a vowel → retain the same
- If the initial letter is a consonant → replace with next immediate consonant


Rules:
- Skip vowels while finding next consonant
- If letter is 'z' → wrap and use 'b'


input ------> a string from the user  
con --------> no  
output -----> updated string  




================================
UNDERSTANDING
================================


Vowels:
a, e, i, o, u


Consonants:
all other letters


Example:
welcome


w → next consonant = x  
e → vowel → same  
l → m  
c → d  
o → same  
m → n  
e → same  


Output:
xemdone ✔




================================
LOGIC
================================


1. Traverse each character
2. If vowel → print same
3. If consonant:
   → find next character using ASCII
   → skip vowels
4. Handle 'z' → go to 'b'
5. Print result




================================
PYTHON CODE (CORRECT + COMMENTS)
================================


s = input()


vowels = "aeiou"


for ch in s:


    # If vowel → print same
    if ch in vowels:
        print(ch, end='')


    else:
        # move to next character
        next_ch = ch


        while True:
            next_ch = chr(ord(next_ch) + 1)


            # handle wrap case
            if next_ch > 'z':
                next_ch = 'a'


            # if not vowel → break
            if next_ch not in vowels:
                break


        print(next_ch, end='')




================================
STEP BY STEP TRACE
================================


Input: welcome


w → x  
e → e  
l → m  
c → d  
o → o  
m → n  
e → e  


Output:
xemdone ✔




================================
IMPORTANT POINT
================================


chr(ord(ch)+1)
→ next character


skip vowels using:
if ch not in vowels




================================
METHOD 2 (FUNCTION STYLE)
================================


def next_consonant(ch):

    vowels = "aeiou"

    while True:
        ch = chr(ord(ch) + 1)

        if ch > 'z':
            ch = 'a'

        if ch not in vowels:
            return ch




s = input()


for ch in s:
    if ch in "aeiou":
        print(ch, end='')
    else:
        print(next_consonant(ch), end='')




================================
TIME COMPLEXITY
================================


→ O(n) ✔




================================
PSEUDO CODE
================================


START
INPUT string


FOR each character
    IF vowel
        print same
    ELSE
        find next consonant
        print


END




================================
INTERVIEW LINE
================================


"Character manipulation using ASCII helps to find next valid consonant while skipping vowels and handling wrap-around cases."




================================================================
PLB260 - Factorial Game
================================================================


PROBLEM:


Mikes likes to play with numbers.  
His friends are also good with numbers and often play mathematical games.  


They made a small game where they will find the last digit of a factorial of a number OTHER THAN 0.


Let say the given number is 5:


5! = 120  
Last digit = 0 ❌ (ignore 0)


So we take last NON-ZERO digit → 2 ✔


input ------> an integer value  
con --------> no  
output -----> last non-zero digit of factorial  




================================
UNDERSTANDING
================================


We need:
👉 last digit of factorial (excluding trailing zeros)


Example:


0! = 1 → 1  
1! = 1 → 1  
2! = 2 → 2  
3! = 6 → 6  
4! = 24 → 4  
5! = 120 → 2  
6! = 720 → 2  
7! = 5040 → 4  




================================
PROBLEM WITH NORMAL METHOD
================================


math.factorial(n)
→ gives big number ❌
→ slow for large n ❌




================================
METHOD 1 (BASIC - GIVEN APPROACH)
================================


import math


n = int(input())


f = math.factorial(n)


# remove trailing zeros
while f % 10 == 0:
    f = f // 10


# print last digit
print(f % 10)




================================
METHOD 2 (OPTIMIZED - BEST)
================================


n = int(input())


res = 1


for i in range(1, n+1):

    res = res * i


    # remove trailing zeros
    while res % 10 == 0:
        res = res // 10


    # keep number small (important)
    res = res % 100000


print(res % 10)




================================
WHY THIS WORKS
================================


Trailing zeros come from:
2 × 5 = 10


So we remove zeros continuously  
and keep number small using modulo




================================
STEP BY STEP TRACE
================================


n = 5


1 → res = 1  
2 → res = 2  
3 → res = 6  
4 → res = 24  
5 → res = 120 → remove 0 → 12  


Answer:
2 ✔




================================
IMPORTANT POINT
================================


f % 10 == 0
→ check trailing zero


f // 10
→ remove last digit




================================
TIME COMPLEXITY
================================


Basic → O(n!) ❌  
Optimized → O(n) ✔




================================
PSEUDO CODE
================================


START
INPUT n


res = 1


FOR i = 1 to n
    res = res * i


    WHILE res ends with 0
        remove zero


    keep res small


PRINT last digit
END




================================
INTERVIEW LINE
================================


"Trailing zeros in factorial are caused by factors of 10 (2×5). 
Removing zeros during multiplication helps efficiently find the last non-zero digit."
========================================================================
========================================================================
PLB261 - Speed Maths (Count number of 1's in Binary)
========================================================================
PROBLEM STATEMENT:
Jack was in 9th standard. He appeared for a speed maths competitive exam.
Jack is taking longer time to solve one of the problems.
Count the number of 1's in the binary representation of an integer.
Help him to solve the below problem and write a code for the same.
========================================================================
 METHOD 1 (bin() WITH COMMENTS)
========================================================================
n = int(input())   # Take input
# bin(n) → converts number to binary string
# Example: bin(5) → '0b101'
# '0b' is prefix → ignore
binary = bin(n)
# count('1') → counts how many '1' characters exist
count = binary.count('1')
print(count)


MAIN CODE (BIT MANIPULATION WITH COMMENTS 🔥)
================================================================================
n = int(input())   # Take input number (example: 5)
count = 0          # Initialize counter
while n > 0:
    # n & 1 → Bitwise AND with 1
    # Purpose: Check LAST BIT (2^0 position)
    # If last bit = 1 → result = 1 (odd)
    # If last bit = 0 → result = 0 (even)
    #
    # Example:
    # n = 5 → binary = 101
    # 101 & 001 = 001 → 1
    count += n & 1   # Add 1 if last bit is 1
    # n >> 1 → Right Shift
    # Purpose: Remove last bit and move to next
    # Equivalent to: n // 2
    #
    # Example:
    # 101 >> 1 = 10 → 1 → 0
    n = n >> 1       # Shift right (divide by 2)
print(count)         # Final count of 1's


========================================================================
SNAP B: DRY RUN (STEP-BY-STEP 🔍)
========================================================================
n = 5 → binary = 101
Step 1:
n & 1 = 101 & 001 = 1 → count = 1
n >> 1 = 101 >> 1 = 10 = 2
Step 2:
n & 1 = 010 & 001 = 0 → count = 1
n >> 1 = 010 >> 1 = 1
Step 3:
n & 1 = 001 & 001 = 1 → count = 2
n >> 1 = 001 >> 1 = 0 (stop)
Final Answer = 2 ✓


========================================================================
METHOD 2 WITH DETAILED COMMENTS
========================================================================
# Method 2: Using Bitwise Operations (BIT MANIPULATION)
n = int(input("Enter number: "))  # Take input from user
count = 0  # Initialize counter variable to 0
while n > 0:  # Loop while n is greater than 0
    # n & 1 checks the LAST BIT (rightmost bit)
    # Binary AND operation:
    # If last bit is 1: n & 1 = 1 (we add 1 to count)
    # If last bit is 0: n & 1 = 0 (we add 0 to count)
    count += n & 1
    # n >> 1 means RIGHT SHIFT by 1 position
    # This removes the last bit and moves to next bit
    # Same as dividing by 2: n = n // 2
    # Example: 101 >> 1 = 10 (5 becomes 2)
    n = n >> 1
print(f"Count of 1's: {count}")
========================================================================
METHOD 3 WITH DETAILED COMMENTS
========================================================================
# Method 3: Kernighan's Algorithm (OPTIMIZED 🚀)
n = int(input("Enter number: "))  # Take input from user
count = 0  # Initialize counter variable to 0
while n > 0:  # Loop while n is greater than 0
    # n & (n - 1) removes the rightmost '1' bit in ONE operation
    # This is a CLEVER TRICK:
    # - When you subtract 1 from binary: rightmost 1 becomes 0
    # - When you AND them: the rightmost 1 disappears
    #
    # Example: n = 5 (101)
    # n = 5     → 101
    # n-1 = 4   → 100
    # 101 & 100 → 100 (removes rightmost 1)
    #
    # Why is this faster?
    # It skips all 0 bits and only counts when removing a 1
    n = n & (n - 1)
    count += 1  # Increment count for each 1 removed
print(f"Count of 1's: {count}")


DRY RUN (n=5, Binary: 101):
Step 1: 5 & 4 = 101 & 100 = 100 = 4, count=1
Step 2: 4 & 3 = 100 & 011 = 000 = 0, count=2
Final: count = 2 ✓
(Only 2 iterations for 2 ones!)
========================================================================
                 COUNT 1's IN BINARY (FULL UNDERSTANDING FLOW)
========================================================================


🎯 PROBLEM:
Count number of 1's in binary representation of a number.


Example:
5  → 101  → 2
13 → 1101 → 3


========================================================================
🧠 SNAP 1: BINARY BASICS (ROOT CONCEPT)
========================================================================


Binary = powers of 2


Position:   2^2   2^1   2^0
Binary:      1     0     1


Calculation:
= 1×2^2 + 0×2^1 + 1×2^0
= 4 + 0 + 1 = 5


👉 Important:
Rightmost bit = 2^0 → THIS is what we check using (n & 1)


================================================================================
🧠 SNAP 2: bin() FUNCTION
================================================================================


bin(n) → converts decimal to binary string


Example:
bin(5) → '0b101'


👉 '0b' = prefix → ignore
👉 only count '1'




🧠 SNAP 3: BITWISE AND (&)
==================================================================
Purpose → check LAST BIT


Rules:
1 & 1 = 1
1 & 0 = 0
0 & 1 = 0
0 & 0 = 0


Example:
5 = 101
1 = 001


 101
&001
----
 001 → 1


👉 So:
n & 1 = last bit check


👉 Meaning:
1 → odd
0 → even


========================================================================
🧠 SNAP 4: RIGHT SHIFT (>>)
========================================================================
RIGHT SHIFT (>>)
------------------------------------------------------------
PURPOSE:
# Removes last bit (rightmost bit)
# Same as divide by 2 (integer)


------------------------------------------------------------
STEP-BY-STEP FLOW:
101 (binary = 5)
   ↓ >> 1   (right shift → last bit remove)
10  (binary)
   ↓ convert (binary → decimal)
2   (decimal)


------------------------------------------------------------
DETAILED EXPLANATION:


# Step 1: Remove last bit
101 → 10


# Step 2: Convert binary to decimal


Position:   2^1   2^0
Binary:      1     0


Calculation:
= 1×2^1 + 0×2^0
= 2 + 0
= 2
------------------------------------------------------------
MORE EXAMPLES:
110 (binary = 6)
   ↓ >> 1
11 (binary)
   ↓ convert
3 (decimal)


100 (binary = 4)
   ↓ >> 1
10 (binary)
   ↓ convert
2 (decimal)


------------------------------------------------------------
ONE LINE SUMMARY:


>> 1 → remove last bit → convert to decimal → result = half value


------------------------------------------------------------
========================================================================
🧠 SNAP 5: FLOW CONNECTION (IMPORTANT 🔥)
========================================================================


👉 This is the MAIN LOGIC FLOW:


Step 1: n & 1 → check last bit (2^0)
Step 2: n >> 1 → remove last bit
Step 3: repeat


👉 So we are scanning binary from RIGHT → LEFT


========================================================================
🧠 SNAP 6: FULL CONNECTION (IMPORTANT 🔥)
========================================================================
Binary = powers of 2
Rightmost bit = 2^0


n & 1 → checks 2^0 bit
n >> 1 → moves to next bit
Loop → scans all bits


================================================================================
🧠 SNAP 7: METHOD 1 (EASY)
========================================================================
n = int(input())
# convert to binary string
# count '1'
count = bin(n).count('1')
print(count)
👉 Simple but uses extra space
========================================================================
🧠 SNAP 8: METHOD 2 (BIT LOGIC 🔥)
========================================================================


n = int(input())
count = 0
while n > 0:
    # Step 1: check last bit
    count += n & 1
    # Step 2: move to next bit
    n = n >> 1
print(count)


DRY RUN:


n = 5 → 101


Step 1:
5 & 1 = 1 → count = 1
5 >> 1 = 2


Step 2:
2 & 1 = 0 → count = 1
2 >> 1 = 1


Step 3:
1 & 1 = 1 → count = 2
1 >> 1 = 0


Final Answer = 2


========================================================================
🧠 SNAP 9: METHOD 3 (OPTIMIZED 🚀)
========================================================================
n = int(input())
count = 0
while n > 0:
    # removes last '1'
    n = n & (n - 1)
    count += 1
print(count)


👉 Faster because skips 0's


Example:
101 → 100 → 000
========================================================================
🧠 SNAP 10: FINAL SUMMARY
========================================================================


bin() → easiest
& → last bit check
>> → move to next bit
n&(n-1) → fastest trick


Goal:👉 Count number of 1's in binary
=========================================================
PLB262 - Puzzle
------------------------------------------------------------
PROBLEM STATEMENT:
Dennis was solving a puzzle.
The puzzle is to verify a number whose cube ends with the number itself.
------------------------------------------------------------
LOGIC:
1. Take integer input n
2. Find cube → n^3
3. Get last digit → n^3 % 10
4. Compare with n
5. If equal → true else false
------------------------------------------------------------
ONE-LINE CODE WITH COMMENTS:
n=int(input()) # take input number
# n**3 → cube of number
# %10 → gives last digit of cube
# compare last digit with original number
print('true' if n**3%10==n else 'false')
------------------------------------------------------------
MULTI-LINE CODE WITH COMMENTS:
n=int(input()) # take input number
cube=n**3 # calculate cube (n*n*n)
last_digit=cube%10 # extract last digit of cube
if last_digit==n: # check if last digit equals original number
    print('true')
else:
    print('false')
------------------------------------------------------------
PLB263 - mathematics class
------------------------------------------------------------
PROBLEM STATEMENT:
In a mathematics class, number system is being taught to students, before teaching them 10's and 100's place, 
they will be taught the number positions.The positions will be starting from sequence number 1 and
the direction will be from left to right.So if I want to find second position of a digit in the number 90876,
it will be 0.If the kth digit exceeds the number position return -1.Write a program to find the kth digit in a given number.
------------------------------------------------------------
LOGIC (VERY SIMPLE):
1.Take number as string
2.Take k (position)
3.If k is valid → print kth digit
4.If not → print -1
------------------------------------------------------------
================================================================================
                    PYTHON IMPLEMENTATION - IMAGE DESCRIPTION
================================================================================


s = input()                     # Get number as string
n = int(input())                # Get position as integer
print(s[n-1] if n<len(s) else '-1') # Print digit at position n (or -1 if exceeds)


================================================================================
                        LINE-BY-LINE BREAKDOWN
================================================================================
LINE 1: s=input()
Purpose: Get string input from user
What it does:
  - Takes input as STRING (not converted to int)
  - Stores in variable 's'

Example:
  Input: 90876
  s = "90876" (string, not integer)

------------------------------------------------------------
WHY STRING?
  - Easy to access individual characters using indexing
  - Direct digit extraction possible

BASIC SYNTAX:string_name[index]
EXAMPLE:
s = "90876"
s[0]  → '9'
s[1]  → '0'
s[2]  → '8'
s[3]  → '7'
s[4]  → '6'
------------------------------------------------------------
INDEX vs POSITION (STRING)
------------------------------------------------------------
POSITION:
Starts from 1 (human counting)


Example:
Number = 90876
Position: 1  2  3  4  5
Digits:   9  0  8  7  6


------------------------------------------------------------
INDEX:
Starts from 0 (Python / programming)


Index:    0  1  2  3  4
Digits:   9  0  8  7  6


------------------------------------------------------------
RELATION:


Position → Index
k        → k-1


------------------------------------------------------------
EXAMPLES:


k = 1 → s[0] → 9
k = 2 → s[1] → 0
k = 3 → s[2] → 8


------------------------------------------------------------
FINAL RULE:


👉 Position starts from 1  
👉 Index starts from 0  
👉 So use: s[k-1]


------------------------------------------------------------
================================================================================


LINE 2: n=int(input())
Purpose: Get position k as integer
What it does:
  - Takes input and converts to integer
  - Stores in variable 'n'

Example:
  Input: 2
  n = 2 (integer)


WHY INT?
  - We need to use it as index value
  - For mathematical comparison


================================================================================


LINE 3: print(s[n-1] if n<len(s) else '-1')
Purpose: Find and print the nth digit (or -1 if invalid)
What it does:
  - Uses TERNARY OPERATOR (conditional in one line)
  - Accesses digit at position n
  - Returns -1 if n exceeds length


BREAKDOWN:
  s[n-1]           → Access digit at index (n-1)
  if n<len(s)      → Check if position is valid
  else '-1'        → Return '-1' if invalid

LOGIC:
  - Position n = Index (n-1)
  - Valid if: n < len(s) AND n >= 1
  - Note: This checks n < len(s) but doesn't check n >= 1
           (Assumes user gives n >= 1)


================================================================================
                        TERNARY OPERATOR EXPLANATION
================================================================================


SYNTAX: <value_if_true> if <condition> else <value_if_false>


EXAMPLE: s[n-1] if n<len(s) else '-1'


If condition (n<len(s)) is TRUE:
  → Execute s[n-1]
  → Return the digit character


If condition (n<len(s)) is FALSE:
  → Execute else part
  → Return '-1' (string)


================================================================================
                        STEP-BY-STEP EXECUTION
================================================================================
EXAMPLE 1: s="90876", n=2
Step 1: s = "90876"
Step 2: n = 2
Step 3: Check condition: n < len(s)?
        2 < 5? YES (True)
Step 4: Execute s[n-1]
        s[2-1] = s[1] = '0'
Step 5: Print '0'
Output: 0
================================================================================
EXAMPLE 2: s="90876", n=6
Step 1: s = "90876"
Step 2: n = 6
Step 3: Check condition: n < len(s)?
        6 < 5? NO (False)
Step 4: Execute else part
        Return '-1'
Step 5: Print '-1'
Output: -1


================================================================================


EXAMPLE 3: s="12345", n=1


Step 1: s = "12345"
Step 2: n = 1
Step 3: Check condition: n < len(s)?
        1 < 5? YES (True)
Step 4: Execute s[n-1]
        s[1-1] = s[0] = '1'
Step 5: Print '1'
Output: 1


========================================================================
PLB264 - POWER FUNCTION
------------------------------------------------------------
PROBLEM STATEMENT:
In a mathematics class, the students are being taught power function.
So "a" raised to the power of "b" is shown as a^b and the calculation
goes as a*a*a... b times. Now there is slight twist to the problem,
the students have to find out the last digit of the resultant a^b.
------------------------------------------------------------
LOGIC:
1. Take input a (base) and b (power)
2. Calculate a^b
3. Get last digit using % 10
------------------------------------------------------------
EXAMPLES:
4 2  -> 4^2  = 16   -> last digit = 6
2 10 -> 2^10 = 1024 -> last digit = 4
------------------------------------------------------------
ONE-LINE CODE WITH COMMENTS:
a, b = (int(i) for i in input().split())   # take base and power
# (a**b) -> calculate power
# %10    -> extract last digit
print((a**b) % 10)
------------------------------------------------------------
STATEMENT:MULTIPLE VARIABLE ASSIGNMENT (UNPACKING)
a, b = (int(i) for i in input().split())
EXPLANATION:
This line takes two numbers as input and assigns them to variables a and b.
------------------------------------------------------------
STEP-BY-STEP:


STEP 1. input()
User enters:4 and 2
STEP 2. input().split()
Splits input into list:
['4', '2']


3. for i in input().split()
Loops through each value:
i = '4', then i = '2'


4. int(i)
Converts string to integer:
'4' → 4
'2' → 2


5. (int(i) for i in input().split())
Produces values:
4, 2


6. a, b = ...
Assigns values:
a = 4
b = 2
------------------------------------------------------------
FINAL FLOW:


Input: 4 2
↓
split → ['4','2']
↓
int → 4, 2
↓
a = 4
b = 2
------------------------------------------------------------
IMPORTANT RULE:
Number of variables = number of values
Correct:
a, b = 4, 2
Wrong:
a, b = 4, 2, 3  → Error
------------------------------------------------------------
ONE LINE MEANING:
Take two numbers from input, convert to integer, and assign to a and b.
------------------------------------------------------------
MULTI-LINE CODE WITH COMMENTS:
a, b = (int(i) for i in input().split())   # take input
power = a ** b        # calculate a^b
last_digit = power % 10   # get last digit
print(last_digit)     # print result
------------------------------------------------------------
FINAL FORMULA:
last digit = (a^b) % 10
------------------------------------------------------------
========================================================================
------------------------------------------------------------
KEY DIFFERENCE:FOR LOOP vs WHILE LOOP


FOR LOOP:
- Fixed number of iterations
- Cleaner and shorter
- Used for sequences (list, string, range)


WHILE LOOP:
- Condition-based
- Can run infinite if condition not handled
- Used when number of iterations unknown


------------------------------------------------------------
FOR LOOP:
------------------------------------------------------------
# Used when number of iterations is known
# Works with range, list, string etc.


Syntax:
for i in range(start, end, step):
    # code


Example:
for i in range(5):
    print(i)


------------------------------------------------------------
WHILE LOOP:


# Used when condition-based looping is needed
# Runs until condition becomes False


Syntax:
while condition:
    # code


Example:
i = 0
while i < 5:
    print(i)
    i += 1




EXAMPLE (PLB265):


FOR LOOP:
s = input()
for i in range(len(s)-1,-1,-1):
    print(int(s[i])**2, end='')


WHILE LOOP:
n = int(input())
while n != 0:
    d = n % 10
    print(d*d, end='')
    n = n // 10


------------------------------------------------------------
FINAL SUMMARY:


FOR → when count known  
WHILE → when condition based  


------------------------------------------------------------




PLB265 - mathematical tricks
------------------------------------------------------------
PROBLEM STATEMENT:
Aryan is studying in the 5th standard. He is very interested in mathematical tricks 
and always wanted to play with numbers. Aryan would like to replace existing numbers
with some other numbers. Today he decided to replace all digits of the number 
(which is greater than or equal to 2 digits) by its squares and print it in reverse order.
------------------------------------------------------------
LOGIC:
1.Take number n
2.Extract last digit using n%10
3.Find square of digit → d*d
4.Print it
5.Remove last digit → n//=10
6.Repeat until n becomes 0
------------------------------------------------------------
EXPLANATION WITH EXAMPLE:
n = 23
Step 1:
d = 3 → square = 9 → print 9
n = 2


Step 2:
d = 2 → square = 4 → print 4


Output:
94 (reverse order automatically)
------------------------------------------------------------
CODE WITH COMMENTS:
n=int(input()) #take input number


while n!=0:
    d=n%10 #get last digit
    print(d*d,end='') #print square of digit (no space, same line)
    n=n//10 #remove last digit


------------------------------------------------------------
FINAL ONE LINE:
👉 Take each digit → square it → print in reverse order
------------------------------------------------------------
PLB265 - mathematical tricks (FOR LOOP METHOD)
------------------------------------------------------------
LOGIC:
1.Take number as string
2.Run loop from right to left
3.Convert each digit to integer
4.Find square → d*d
5.Print result
------------------------------------------------------------
CODE WITH COMMENTS:
s=input() #take number as string


for i in range(len(s)-1,-1,-1): #reverse loop (last index to 0)
    d=int(s[i]) #get digit at index i
    print(d*d,end='') #print square of digit


------------------------------------------------------------
EXPLANATION WITH EXAMPLE:


Input:
23


s = "23"
len(s) = 2


Loop runs:
range(1, -1, -1) → i = 1, 0


------------------------------------------------------------
STEP 1:
i = 1
s[1] = '3'
d = 3
square = 3*3 = 9
print → 9


------------------------------------------------------------
STEP 2:
i = 0
s[0] = '2'
d = 2
square = 2*2 = 4
print → 4


------------------------------------------------------------
FINAL OUTPUT:
94


------------------------------------------------------------
WHAT IS HAPPENING:


Loop runs in reverse (right → left)
Each digit is taken one by one
Square of each digit is printed
So output comes in reverse order
------------------------------------------------------------
ONE LINE:Reverse loop → take digit → square → print






------------------------------------------------------------
PLB266 - coding standards
------------------------------------------------------------
PROBLEM STATEMENT:
Tom has joined a new company and he is assigned a program to code. 
But before starting to code, he needs to know the coding standards.
He needs to make sure that the variable name should meet the below standards:


=> contains only english letters
=> and/or digits
=> and/or underscore (_)
=> should not start with digits


The program should return True/False based on the above conditions.


------------------------------------------------------------
LOGIC:
1.Take input string s
2.Check:
   - starts with letter or underscore
   - remaining characters can be letter/digit/underscore
3.If valid → print true
4.Else → print false


------------------------------------------------------------
REGEX BASICS:
1) WHAT IS REGEX?
Regex (Regular Expression) is a pattern used to check or match strings.
Used for validation (variable names, emails, passwords)
------------------------------------------------------------
2) WHAT IS re.fullmatch()?
        re.fullmatch(pattern, string)
        Checks entire string matches pattern
Example:
        re.fullmatch("abc","abc") → True
        re.fullmatch("abc","abcd") → False
------------------------------------------------------------
REGEX PATTERN USED:


[a-zA-Z_][a-zA-Z0-9_]*


------------------------------------------------------------
PATTERN BREAKDOWN:


[a-zA-Z_]
→ First character must be:
   a-z OR A-Z OR _


[a-zA-Z0-9_]*
→ Remaining characters:
   a-z OR A-Z OR 0-9 OR _
→ * means 0 or more times


------------------------------------------------------------
IMPORTANT CONCEPTS:


[] → character set (NOT list)
→ means choose ONE character


- → range
a-z → a to z
A-Z → A to Z
0-9 → digits


* → repeat (0 or more times)


------------------------------------------------------------
PYTHON vs REGEX []:


Python:
[1,2,3] → list


Regex:
[a-z] → pattern (character set)


------------------------------------------------------------
FULL MEANING:


[a-zA-Z_][a-zA-Z0-9_]*


First character → letter or _
Remaining → letter/digit/_


------------------------------------------------------------
EXAMPLES:


var1   → valid
_temp  → valid
1var   → invalid
var@   → invalid


------------------------------------------------------------
CODE WITH COMMENTS:


import re
s=input() #take variable name


# fullmatch → checks full string
# pattern → variable rules


print('true' if re.fullmatch("[a-zA-Z_][a-zA-Z0-9_]*", s) else 'false')


------------------------------------------------------------
FINAL SUMMARY:


Regex = pattern checking tool
[] = set of allowed characters
- = range
* = repeat
------------------------------------------------------------
re.match() - EXPLANATION
------------------------------------------------------------
WHAT IS re.match()?
re.match(pattern,string) → checks pattern only at start of string
------------------------------------------------------------
DIFFERENCE:
re.match() → checks from beginning only
re.fullmatch() → checks entire string
------------------------------------------------------------
EXAMPLE 1:
import re
s="var123"
result=re.match("[a-zA-Z]+",s) #must start with letters
print("true" if result else "false")
OUTPUT:true
------------------------------------------------------------
EXPLANATION:
[a-zA-Z]+ → one or more letters
"var123" → starts with "var" → match
------------------------------------------------------------
EXAMPLE 2:
import re
s="123var"
result=re.match("[a-zA-Z]+",s)
print("true" if result else "false")
OUTPUT:false
------------------------------------------------------------
EXPLANATION:
"123var" → does not start with letter → no match
------------------------------------------------------------
IMPORTANT:
re.match("abc","abcdef") → true
re.fullmatch("abc","abcdef") → false
------------------------------------------------------------
FINAL ONE LINE:
re.match() → checks only beginning of string 
------------------------------------------------------------








REGEX: + vs *
------------------------------------------------------------
MEANING:
* → 0 or more times  
+ → 1 or more times  
WHAT DOES * (0 TIMES) MEAN?


------------------------------------------------------------
* → 0 or more times


👉 "0 times" means:
second part may NOT exist


------------------------------------------------------------
EXAMPLE:


Pattern:
[a-zA-Z_][a-zA-Z0-9_]*


------------------------------------------------------------
CASE 1:


Input: a


Breakdown:
[a-zA-Z_] → matches 'a'
[a-zA-Z0-9_]* → 0 times (nothing)


👉 So "a" is VALID ✔


------------------------------------------------------------
CASE 2:


Input: ab


[a-zA-Z_] → 'a'
[a-zA-Z0-9_]* → 'b'


✔ valid


------------------------------------------------------------
CASE 3:


Input: a1_


[a-zA-Z_] → 'a'
[a-zA-Z0-9_]* → '1_'


✔ valid


------------------------------------------------------------
IMPORTANT:


* allows EMPTY (0 characters)


So pattern works even if only 1 character exists


------------------------------------------------------------
COMPARE WITH +:


[a-zA-Z_][a-zA-Z0-9_]+


👉 + means at least 1 character required after first


Input: a
❌ invalid (no second character)


------------------------------------------------------------
FINAL UNDERSTANDING:


* → second part optional (can be empty)
+ → second part compulsory


------------------------------------------------------------


------------------------------------------------------------
PATTERN:
[a-zA-Z_][a-zA-Z0-9_]+
[a-zA-Z_] → first character (letter or _)  
[a-zA-Z0-9_]+ → remaining characters (at least 1 required)
------------------------------------------------------------
IMPORTANT POINT:
+ → minimum 2 characters required  
* → even 1 character is allowed  
------------------------------------------------------------
CODE:
import re
s=input()
print('true' if re.fullmatch("[a-zA-Z_][a-zA-Z0-9_]+",s) else 'false')
------------------------------------------------------------
EXAMPLES:
a   → false  
ab  → true  
a1  → true  
_x  → true  
1a  → false  
------------------------------------------------------------
FINAL ONE LINE:
+ → at least one extra character  
* → optional characters  
------------------------------------------------------------
==============================================
PLB267 - party quiz
------------------------------------------------------------
PROBLEM STATEMENT:
While sitting in party, Tom came up with an idea of a quiz and the quiz is,
Tom will spell out a number, and a person has to tell a number which is next to it.
But this number has to be perfect square.


------------------------------------------------------------
INPUT:
a number from the user


------------------------------------------------------------
OUTPUT:
the next perfect square after N


------------------------------------------------------------
LOGIC:
1.Take input n
2.Start from i = 1
3.Check i*i (perfect squares)
4.Find first square greater than n
5.Print that square


------------------------------------------------------------
EXAMPLE:
n = 7
Squares: 1, 4, 9, 16...
Next perfect square → 9


------------------------------------------------------------
SAMPLE INPUT:
7


------------------------------------------------------------
SAMPLE OUTPUT:
9


------------------------------------------------------------
CODE WITH COMMENTS:


n=int(input()) #take input
i=1


while True:
    if i*i>n: #first square greater than n
        print(i*i) #output
        break
    i=i+1 #increment


------------------------------------------------------------
DRY RUN (n = 7):


INITIAL VALUES:
n = 7
i = 1


------------------------------------------------------------
ITERATION 1:
i = 1
i*i = 1
1 > 7 ? ❌ No
i = 2


------------------------------------------------------------
ITERATION 2:
i = 2
i*i = 4
4 > 7 ? ❌ No
i = 3


------------------------------------------------------------
ITERATION 3:
i = 3
i*i = 9
9 > 7 ? ✅ Yes
print(9)
break


------------------------------------------------------------
FINAL OUTPUT:
9


------------------------------------------------------------
WHAT IS HAPPENING:
Loop checks square of each number
Stops when square becomes greater than n
Prints the first such square


------------------------------------------------------------
FINAL ONE LINE:
Find first i such that i*i > n


------------------------------------------------------------


========================================================================PLB268 - Be Positive
------------------------------------------------------------
PROBLEM STATEMENT:
Write a program to get two inputs from the user and find the 
absolute difference between the sum of two numbers and the product of two numbers.
------------------------------------------------------------
INPUT:
two numbers from the user
------------------------------------------------------------
OUTPUT:
absolute difference
ABSOLUTE VALUE (abs)
------------------------------------------------------------
MEANING:
Absolute value means distance from 0
👉 Always positive value
------------------------------------------------------------
EXAMPLES:
abs(5)  = 5  
abs(-5) = 5  
abs(0)  = 0  
------------------------------------------------------------
WHY?
Distance from 0 is always positive
Number line:
-5 ---- 0 ---- 5
Distance of -5 from 0 = 5  
Distance of 5 from 0 = 5  
------------------------------------------------------------
IN CODE:
abs(x)
👉 Converts negative → positive  
👉 Keeps positive as it is  
------------------------------------------------------------
EXAMPLE IN YOUR QUESTION:
(a+b) - (a*b) = -1  
abs(-1) = 1  
------------------------------------------------------------
FINAL ONE LINE:
Absolute = always positive (distance from 0)
------------------------------------------------------------
------------------------------------------------------------
LOGIC:
1.Take two inputs a and b
2.Find sum → (a + b)
3.Find product → (a * b)
4.Find difference → (a + b) - (a * b)
5.Take absolute value using abs()
------------------------------------------------------------
EXAMPLE:
a = 2, b = 3


Sum = 2 + 3 = 5  
Product = 2 * 3 = 6  


Difference = 5 - 6 = -1  
Absolute Difference = 1  


------------------------------------------------------------
SAMPLE INPUT:
2
3


------------------------------------------------------------
SAMPLE OUTPUT:
1


------------------------------------------------------------
CODE WITH COMMENTS:


a=int(input()) #take first number
b=int(input()) #take second number


# (a+b) → sum
# (a*b) → product
# abs() → converts negative to positive


print(abs((a+b)-(a*b)))


------------------------------------------------------------
FINAL ONE LINE:
👉 abs((a+b) - (a*b))
========================================================================PLB269 - Prime Number Busses
------------------------------------------------------------
PROBLEM STATEMENT:
James wants to travel by bus to reach his friend John's home. 
John gave a hint that all busses from James's location will reach his home 
if the bus number is prime number. 
Write a program to help James find the bus that reaches John's home.


INPUT:
a number from the user
OUTPUT:
yes or no
------------------------------------------------------------
LOGIC:
1.Take input n
2.Count how many numbers divide n
3.If exactly 2 divisors → prime
4.Print "yes" else "no"
------------------------------------------------------------
PRIME NUMBER - DEFINITION
A prime number is a number that has exactly 2 factors:
1 and the number itself
------------------------------------------------------------
EXAMPLES:PRIME
2 → factors: 1,2 → prime  
3 → factors: 1,3 → prime  
5 → factors: 1,5 → prime  
7 → factors: 1,7 → prime  
EXAMPLES:NOT PRIME
4 → factors: 1,2,4 → not prime  
6 → factors: 1,2,3,6 → not prime  
------------------------------------------------------------
IMPORTANT NOTE:1 is NOT a prime number  
(It has only 1 factor)
------------------------------------------------------------
FINAL ONE LINE:
Prime = exactly 2 factors (1 and itself)
EXAMPLE:
n = 5
Divisors → 1, 5 (only 2)
→ Prime → yes
n = 6
Divisors → 1,2,3,6 (more than 2)
→ Not prime → no
------------------------------------------------------------
SAMPLE INPUT:
5
SAMPLE OUTPUT:
yes
------------------------------------------------------------
CODE WITH COMMENTS:
n=int(input()) #take input number
f=0 #counter for factors
for i in range(1,n+1): #loop from 1 to n
    if n%i==0: #check divisor
        f=f+1 #increase count
# prime → exactly 2 factors
print('yes' if f==2 else 'no')
------------------------------------------------------------
FINAL ONE LINE:
👉 prime → exactly 2 divisors
------------------------------------------------------------






PLB270 - sentence making
------------------------------------------------------------
PROBLEM STATEMENT:
The teacher explains that a correct sentence must start with a capital letter 
and end with a full stop. If any condition fails, the sentence is incorrect. 
Write a program to validate the sentence and return true or false.


------------------------------------------------------------
INPUT:a string from the user
OUTPUT:true or false
------------------------------------------------------------
LOGIC:
1.First character must be capital letter (A-Z)
2.Last character must be '.'
3.Middle characters can be letters, digits, underscore or space


------------------------------------------------------------
REGEX PATTERN:[A-Z][a-zA-Z0-9_ ]*[.]
Where,
        [A-Z] → first character must be capital letter  
        [a-zA-Z0-9_ ]* → middle characters (0 or more allowed)  
        [.] → sentence must end with dot  
------------------------------------------------------------
EXAMPLES:
"Hello." → true  
"hello." → false  
"Hello" → false  
"H1_test." → true  


------------------------------------------------------------
CODE WITH COMMENTS:


import re
s=input() #take sentence


# fullmatch → checks entire string
# pattern → capital start + valid characters + ends with '.'


print('true' if re.fullmatch("[A-Z][a-zA-Z0-9_ ]*[.]",s) else 'false')


------------------------------------------------------------
FINAL ONE LINE:A valid sentence starts with capital letter and ends with '.'
=============================================================
PLB271 - Single Binary Value
------------------------------------------------------------
PROBLEM STATEMENT:
Geetha Singh is trying to create a system to convert binary number 
to its decimal equivalent. Help her to automate the process.


------------------------------------------------------------
INPUT:
a binary value
OUTPUT:
decimal value
------------------------------------------------------------
LOGIC:
1.Take binary input
2.Convert it into decimal
3.Print result
------------------------------------------------------------
EXAMPLE:SAMPLE INPUT:110,SAMPLE OUTPUT:6
Binary: 110


Position:   2^2   2^1   2^0
Digits:      1     1     0


Calculation:
= 1×2^2 + 1×2^1 + 0×2^0
= 4 + 2 + 0
= 6
------------------------------------------------------------
CODE WITH COMMENTS (GIVEN METHOD):


# input() → takes binary string (example: "110")
# "0b"+input() → converts it into binary format string ("0b110")
# eval() → evaluates binary and converts to decimal


print(eval("0b"+input()))


------------------------------------------------------------
EXPLANATION:


Input: 110  
"0b" + "110" → "0b110"  


eval("0b110") → 6  


------------------------------------------------------------
IMPORTANT:
0b → prefix used for binary numbers in Python
eval() → evaluates binary and converts to decimal
------------------------------------------------------------
FINAL ONE LINE:
👉 "0b"+input() → binary → eval() → decimal
------------------------------------------------------------
=============================================================
PLB272 - Item id
------------------------------------------------------------
PROBLEM STATEMENT:
A company wishes to bucketize their item id's for better search operations. 
The bucket for the item ID is chosen on the basis of the maximum value of 
the digit in the item ID. Write an algorithm to find the bucket to which the item ID will be assigned.
------------------------------------------------------------
INPUT:
ItemId


OUTPUT:
bucket ID (maximum digit in number)
------------------------------------------------------------
LOGIC:
1.Take input as string
2.Convert each digit to integer
3.Find maximum digit
4.Print it
------------------------------------------------------------
EXAMPLE:
Input: 12875
Digits: 1,2,8,7,5
Maximum digit → 8
------------------------------------------------------------
SAMPLE INPUT:
12875
SAMPLE OUTPUT:
8
------------------------------------------------------------
CODE WITH COMMENTS:
# input() → takes number as string
# for i in input() → iterate each digit
# int(i) → convert to integer
# max() → find maximum digit
print(max([int(i) for i in input()]))
------------------------------------------------------------
EXPLANATION:Input: 12875
→ ['1','2','8','7','5']
→ [1,2,8,7,5]
→ max = 8
FINAL ONE LINE:👉 bucket ID = maximum digit in number
------------------------------------------------------------
FIND MAX DIGIT WITHOUT max()
------------------------------------------------------------
LOGIC:
1.Take input as string
2.Initialize max_digit = 0
3.Loop through each digit
4.Convert digit to int
5.If digit > max_digit → update
6.Print max_digit
------------------------------------------------------------
CODE WITH COMMENTS:
s=input() #take number as string
max_digit=0 #assume minimum
for ch in s: #loop each digit
    d=int(ch) #convert to int

    if d>max_digit: #compare
        max_digit=d #update max


print(max_digit)
------------------------------------------------------------
EXAMPLE:
Input: 12875
Step:
1 → max=1
2 → max=2
8 → max=8
7 → no change
5 → no change
Output:
8
------------------------------------------------------------
FINAL ONE LINE:👉 compare each digit and keep updating max
=============================================================
PLB280 - Validate ATM PIN
------------------------------------------------------------
PROBLEM STATEMENT:
Implement a program that will test if a string is a valid PIN or not using regular expression.
A valid PIN has:
- Exactly 4 characters
- Only numeric characters (0-9)
- No whitespace
------------------------------------------------------------
INPUT:
a string from the user
------------------------------------------------------------
OUTPUT:
true or false
------------------------------------------------------------
LOGIC:
1.Length must be exactly 4
2.All characters must be digits (0-9)
3.No spaces allowed
------------------------------------------------------------
REGEX PATTERN:[0-9]{4}
------------------------------------------------------------
PATTERN BREAKDOWN:
[0-9] → digits from 0 to 9  
{4} → exactly 4 times  
👉 Means: exactly 4 digits
------------------------------------------------------------
EXAMPLES:
"1234" → true  
"0000" → true  
"12a4" → false (contains letter)  
"12345" → false (length > 4)  
"12 4" → false (space not allowed)


------------------------------------------------------------
CODE WITH COMMENTS:


import re
s=input() #take input


# fullmatch → entire string must match
# [0-9]{4} → exactly 4 digits


print('true' if re.fullmatch("[0-9]{4}",s) else 'false')
------------------------------------------------------------
IMPORTANT:
{4} → fixed length (exactly 4 characters)
------------------------------------------------------------
FINAL ONE LINE:👉 valid PIN = exactly 4 digits
------------------------------------------------------------
re.fullmatch() - EXACT SYNTAX


------------------------------------------------------------
SYNTAX:


re.fullmatch(pattern, string)


------------------------------------------------------------
YOUR CASE:


re.fullmatch("[0-9]{4}", s)


------------------------------------------------------------
BREAKDOWN:


1) re.fullmatch(...)
→ checks if the ENTIRE string matches the pattern


------------------------------------------------------------
2) "[0-9]{4}" → pattern


[0-9]
→ digits from 0 to 9


{4}
→ exactly 4 times


👉 So:
"[0-9]{4}" = exactly 4 digits


------------------------------------------------------------
3) s
→ input string (user input)


------------------------------------------------------------
RETURN VALUE:


If match → returns match object (True condition)
If not → returns None (False condition)


------------------------------------------------------------
EXAMPLE:


s = "1234"
re.fullmatch("[0-9]{4}", s) → match → True


s = "123"
re.fullmatch("[0-9]{4}", s) → None → False


------------------------------------------------------------
USED IN CODE:


print('true' if re.fullmatch("[0-9]{4}", s) else 'false')


------------------------------------------------------------
FINAL ONE LINE:
re.fullmatch(pattern, string) → checks full string matches pattern


FINAL SUMMARY:REGEX COMPLETE SUMMARY ([], *, +, {})
[] = selection (what to match )
-  → range
*  = optional(0 or more )
+  = at least one(1 or more )
{} = controlled repetition(exact/range control )
------------------------------------------------------------
1) [] → CHARACTER SET (WHAT TO MATCH)
Used to define allowed characters
Example:
[0-9] → any digit  
[a-z] → any lowercase letter  
[A-Z] → any uppercase letter  
👉 Means: choose ONE character
------------------------------------------------------------
2) - (DASH)
Used for range inside []
Example:
a-z → a to z  
0-9 → digits  
------------------------------------------------------------
3) * (STAR)
* → 0 or more times
Example:
[a-z]*
👉 "", a, abc → all valid  
👉 allows empty also
------------------------------------------------------------
4) + (PLUS)
+ → 1 or more times
Example:[a-z]+
👉 a, abc → valid  
👉 "" → not allowed
------------------------------------------------------------
5) {} (CURLY BRACES)
Used for exact or range repetition
Examples:
[0-9]{4}
→ exactly 4 digits  
[a-z]{2,5}
→ minimum 2, maximum 5 letters  
------------------------------------------------------------
6) COMBINED EXAMPLES:
[a-z]*      → 0 to infinite letters  
[a-z]+      → 1 to infinite letters  
[a-z]{3}    → exactly 3 letters  
[a-z]{2,4}  → 2 to 4 letters  
------------------------------------------------------------
7) REAL EXAMPLE (ATM PIN):
[0-9]{4}
→ digit (0-9)
→ repeated exactly 4 times
→ valid PIN
============================================================
PLB281 - The Actual Memory Size of Your USB Flash Drive
------------------------------------------------------------
PROBLEM STATEMENT:
Implement a program that takes the memory size as input and returns 
the actual memory size.Note:The actual storage loss on a USB device is 7% of the overall memory size.
------------------------------------------------------------
INPUT:
memory size in GB
OUTPUT:
actual memory size (rounded to 2 decimal places)
------------------------------------------------------------
LOGIC:
1.Take input n (memory size)
2.Calculate 7% loss → n*0.07
3.Subtract loss → n-(n*0.07)
4.Format to 2 decimal places
------------------------------------------------------------
PERCENTAGE CONCEPT:
7% = 7/100 = 0.07
loss = n*0.07
Actual = n-(n*0.07) = n*0.93
------------------------------------------------------------
EXAMPLE:
n=10
Loss=10*0.07=0.7
Actual=10-0.7=9.3
------------------------------------------------------------
SAMPLE INPUT:
1
SAMPLE OUTPUT:
0.93
------------------------------------------------------------
CODE WITH COMMENTS:
n=int(input()) #take memory size
# n*0.07 → 7% loss
# n-n*0.07 → actual memory
# %.2f → format to 2 decimal places
print("%.2f"%(n-n*0.07))
------------------------------------------------------------
STEP-BY-STEP:
STEP 1: n*0.07 → calculate loss
STEP 2: n-n*0.07 → actual value
STEP 3: "%.2f"%value → format output
STEP 4: print() → display result
------------------------------------------------------------
FORMAT EXPLANATION:
"%.2f"%value
First % → format pattern
Second % → applies format to value
%.2f → 2 decimal places (float)
Example:
9.3 → 9.30
5 → 5.00
3.456 → 3.46
------------------------------------------------------------
FINAL ONE LINE:
calculate → subtract → format → print
=============================================================
PLB282 - Happy Number
------------------------------------------------------------
PROBLEM STATEMENT:
A happy number is a number which becomes 1 when we repeatedly replace it by the sum of the squares of its digits.If the process enters a cycle including 4, then it is not a happy number.Write a program to check whether a number is happy or not.
------------------------------------------------------------
INPUT:a number from the user
OUTPUT:true or false
------------------------------------------------------------
LOGIC:
1.Take input n
2.Find sum of squares of digits
3.Replace n with result
4.If n becomes 1 → true
5.If n becomes 4 → false (cycle)
6.Repeat until condition met
------------------------------------------------------------
EXAMPLE 1:
n=32
3²+2²=9+4=13
1²+3²=1+9=10
1²+0²=1+0=1
→ true
------------------------------------------------------------
EXAMPLE 2:
n=16
1²+6²=1+36=37
3²+7²=9+49=58
5²+8²=25+64=89
...→ reaches 4
→ false
------------------------------------------------------------
CODE WITH COMMENTS (WHILE LOOP):
def sum_sq(n): #sum of squares
    s=0
    while n!=0:
        d=n%10 #last digit
        s=s+d*d #square and add
        n=n//10 #remove last digit
    return s
n=int(input()) #take input
while True:
    if n==1:
        print('true')
        break
    if n==4:
        print('false')
        break
    n=sum_sq(n)
------------------------------------------------------------


------------------------------------------------------------
CODE WITH LOGIC EXPLANATION:
def sum_sq(n): #sum of squares of digits
    # Example: n=32
    s=0 #initial sum
    while n!=0:
        d=n%10 #32%10=2
        s=s+d*d #0+4=4
        n=n//10 #32//10=3
        d=n%10 #3%10=3
        s=s+d*d #4+9=13
        n=n//10 #3//10=0
    return s #result=13
------------------------------------------------------------
FINAL ONE LINE:
👉 repeat sum of squares until 1 (happy) or 4 (not happy)
------------------------------------------------------------
============================================================
PLB283 - Calculate the Mean
------------------------------------------------------------
PROBLEM STATEMENT:
Implement a function that takes an array of numbers and returns 
the mean (average) of all those numbers.
------------------------------------------------------------
INPUT:
array size and elements
OUTPUT:
mean value (rounded to 2 decimal places)
------------------------------------------------------------
LOGIC:
1.Take input n (size)
2.Take list of elements
3.Find sum of elements
4.Calculate mean → sum/n
5.Format to 2 decimal places
------------------------------------------------------------
EXAMPLE:
n=5
L=1 2 3 4 5
Sum=1+2+3+4+5=15
Mean=15/5=3.0
------------------------------------------------------------
SAMPLE INPUT:
5
1 2 3 4 5
------------------------------------------------------------
SAMPLE OUTPUT:
3.00
------------------------------------------------------------
CODE WITH COMMENTS:
n=int(input()) #size
L=[int(i) for i in input().split()] #elements
sum=0 #init
for i in L: sum=sum+i #add
print("%.2f"%(sum/n)) #mean with format
------------------------------------------------------------
FINAL ONE LINE:
👉 mean = sum / n
============================================================
PLB284 - Factorize a Number
------------------------------------------------------------
PROBLEM STATEMENT:
Implement a program that takes a number as input and returns a list of all its factors.
------------------------------------------------------------
INPUT:
a number
OUTPUT:
list of factors
------------------------------------------------------------
LOGIC:
1.Take input n
2.Run loop from 1 to n
3.Check if n % i == 0
4.If yes → i is a factor
5.Print all such i
------------------------------------------------------------
EXAMPLE:
n=6
Factors:1 2 3 6
------------------------------------------------------------
SAMPLE INPUT:
6
------------------------------------------------------------
SAMPLE OUTPUT:
1 2 3 6
------------------------------------------------------------
CODE WITH COMMENTS:
n=int(input()) #take number
for i in range(1,n+1): #loop 1 to n
    if n%i==0: #check factor
        print(i,end=' ') #print factors
------------------------------------------------------------
FINAL ONE LINE:
👉 factor = number that divides n exactly
------------------------------------------------------------
============================================================
PLB286 - Composite Number
------------------------------------------------------------
PROBLEM STATEMENT:
Implement a program to check whether the given number is 
composite number or not.
------------------------------------------------------------
COMPOSITE NUMBER:
A composite number is a number that has more than 2 factors.
EXPLANATION:
If a number is divisible by numbers other than 1 and itself → composite
EXAMPLES:
4 → factors:1,2,4 → composite
6 → factors:1,2,3,6 → composite
8 → factors:1,2,4,8 → composite
NOT COMPOSITE:
2 → factors:1,2 → prime
3 → factors:1,3 → prime
IMPORTANT:
1 is neither prime nor composite
FINAL ONE LINE:
👉 composite = more than 2 factors
==========
INPUT:
a number from the user
OUTPUT:
true or false
LOGIC:
        1.Take input n
        2.Count number of factors
        3.If factors > 2 → composite
        4.Else → not composite


IMPORTANT:
prime → exactly 2 factors
composite → more than 2 factors


EXAMPLE:
n=6
Factors:1 2 3 6 → 4 factors → composite → true
SAMPLE INPUT:
6
SAMPLE OUTPUT:
true
-------------------------------------------
CODE WITH COMMENTS:
n=int(input()) #take number
f=0 #factor count
for i in range(1,n+1): #loop 1 to n
    if n%i==0: #check divisor
        f=f+1 #increase count
print('true' if f>2 else 'false') #check
--------------------------------------------
FINAL ONE LINE:
👉 factors > 2 → composite
===========================================


=============================================================
PLB292 - DECIMAL TO OCTAL (WITH NUMBER SYSTEMS INTRO)
=============================================================
🎯 PROBLEM: Implement a program to Convert decimal to octal (base 10 → base 8)


INPUT: Decimal number
OUTPUT: Octal number


EXAMPLE: 10 (decimal) = 12 (octal)


=============================================================
                    📚 NUMBER SYSTEMS INTRODUCTION
=============================================================


NUMBER SYSTEM = Different ways to represent numbers using different BASES


BASE = How many different digits are available


4 MAIN NUMBER SYSTEMS:


1. DECIMAL (Base 10)
2. BINARY (Base 2)
3. OCTAL (Base 8)
4. HEXADECIMAL (Base 16)


ALL represent the SAME value, just differently!


=============================================================
                    1️⃣ DECIMAL (BASE 10)
=============================================================


WHAT: Number system we use daily


BASE: 10


DIGITS: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9


HOW IT WORKS:
Each position = power of 10


Example: 345
Position:  10^2   10^1   10^0
Value:     100    10     1
Digit:     3      4      5


Calculation: (3×100) + (4×10) + (5×1) = 300 + 40 + 5 = 345


REAL USE: Money, daily counting, measurements


=============================================================
                    2️⃣ BINARY (BASE 2)
=============================================================


WHAT: Number system used by computers


BASE: 2


DIGITS: 0, 1 only


WHY BINARY?
Computers use electrical signals:
- 1 = ON
- 0 = OFF


HOW IT WORKS:
Each position = power of 2


Example: 101 (binary)
Position:  2^2   2^1   2^0
Value:     4     2     1
Digit:     1     0     1


Calculation: (1×4) + (0×2) + (1×1) = 4 + 0 + 1 = 5 (decimal)


So: 101 (binary) = 5 (decimal)


REAL USE: Computer memory, data storage, digital circuits


===========================================================
                    3️⃣ OCTAL (BASE 8)
===========================================================
WHAT: Base 8 number system


BASE: 8


DIGITS: 0, 1, 2, 3, 4, 5, 6, 7


WHY OCTAL?
- Shortcut for binary (3 bits = 1 octal digit)
- Used in Unix/Linux file permissions
- Easier to read than long binary


HOW IT WORKS:
Each position = power of 8


Example: 12 (octal)
Position:  8^1   8^0
Value:     8     1
Digit:     1     2


Calculation: (1×8) + (2×1) = 8 + 2 = 10 (decimal)


So: 12 (octal) = 10 (decimal)


REAL USE: Unix permissions (chmod 777), old computer systems


============================================================
                    4️⃣ HEXADECIMAL (BASE 16)
============================================================


WHAT: Base 16 number system


BASE: 16


DIGITS: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F


DIGIT MAPPING:
A=10, B=11, C=12, D=13, E=14, F=15


WHY HEXADECIMAL?
- Shortcut for binary (4 bits = 1 hex digit)
- Used for memory addresses
- Used for web colors (#FF5733)
- Compact representation


HOW IT WORKS:
Each position = power of 16


Example: 1F (hex)
Position:  16^1  16^0
Value:     16    1
Digit:     1     F(15)


Calculation: (1×16) + (15×1) = 16 + 15 = 31 (decimal)


So: 1F (hex) = 31 (decimal)


REAL USE: Web colors (#RGB), memory addresses, programming


==============================================================
                    📊 COMPARISON TABLE
==============================================================


System         | Base | Digits              | Example | = Decimal
----------------|------|---------------------|---------|----------
DECIMAL        | 10   | 0-9                 | 25      | 25
BINARY         | 2    | 0-1                 | 11001   | 25
OCTAL          | 8    | 0-7                 | 31      | 25
HEXADECIMAL    | 16   | 0-9, A-F            | 19      | 25


👉 SAME VALUE (25), just DIFFERENT REPRESENTATIONS!


==============================================================
                    🔄 CONVERSION EXAMPLES (EACH SYSTEM)
==============================================================


DECIMAL TO BINARY:
-----------------
Example: Convert 5 (decimal) to binary


Method: Divide by 2, store remainders


5 ÷ 2 = 2 remainder 1
2 ÷ 2 = 1 remainder 0
1 ÷ 2 = 0 remainder 1


Read reverse: 101 (binary)


Answer: 5 (decimal) = 101 (binary) ✓


Verify: (1×4) + (0×2) + (1×1) = 5 ✓


DECIMAL TO OCTAL:
-----------------
Example: Convert 10 (decimal) to octal


Method: Divide by 8, store remainders


10 ÷ 8 = 1 remainder 2
1 ÷ 8 = 0 remainder 1


Read reverse: 12 (octal)


Answer: 10 (decimal) = 12 (octal) ✓


Verify: (1×8) + (2×1) = 10 ✓


DECIMAL TO HEXADECIMAL:
-----------------------
Example: Convert 26 (decimal) to hex


Method: Divide by 16, store remainders


26 ÷ 16 = 1 remainder 10 (A)
1 ÷ 16 = 0 remainder 1


Read reverse: 1A (hex)


Answer: 26 (decimal) = 1A (hex) ✓


Verify: (1×16) + (10×1) = 26 ✓


=========================================================
                    🔗 RELATIONSHIPS
=========================================================


BINARY ↔ OCTAL:
Group binary by 3 bits = 1 octal digit


Binary: 101 110 001
Octal:   5   6   1
Answer: 561 (octal)


BINARY ↔ HEXADECIMAL:
Group binary by 4 bits = 1 hex digit


Binary: 1010 1111
Hex:     A    F
Answer: AF (hex)


WHY?
- 8 = 2^3 (octal uses 3 binary digits)
- 16 = 2^4 (hex uses 4 binary digits)


=========================================================
             🎯 NOW: DECIMAL TO OCTAL (MAIN PROBLEM)
=========================================================
PROBLEM: Convert decimal to octal


CONCEPT: Divide by 8 (because octal base = 8)


LOGIC:
1. Divide number by 8
2. Store remainder (0-7)
3. Divide quotient by 8
4. Repeat until quotient = 0
5. Read remainders from BOTTOM to TOP


==========================================================
                    📝 DECIMAL TO OCTAL EXAMPLE
==========================================================


Example 1: Convert 10 to octal


10 ÷ 8 = 1 remainder 2
1 ÷ 8 = 0 remainder 1


Read reverse: 12 (octal)


Verify: (1×8) + (2×1) = 10 ✓


---


Example 2: Convert 100 to octal


100 ÷ 8 = 12 remainder 4
12 ÷ 8 = 1 remainder 4
1 ÷ 8 = 0 remainder 1


Read reverse: 144 (octal)


Verify: (1×64) + (4×8) + (4×1) = 100 ✓


=======================================================
                    💻 PYTHON CODE (EASIEST)
========================================================


n = int(input())
print(oct(n)[2:])


EXPLANATION:
oct(10) → "0o12" (string with prefix)
[2:] → removes "0o" → "12"
Output: 12


INPUT: 10
OUTPUT: 12 ✓


======================================================
                    💻 PYTHON CODE (MANUAL)
======================================================


n = int(input())
octal = ""


while n > 0:
    remainder = n % 8      # Get octal digit
    octal = str(remainder) + octal  # Add to front
    n = n // 8             # Divide by 8


print(octal)


EXECUTION (n=10):


Step 1: n=10, remainder=10%8=2, octal="2", n=10//8=1
Step 2: n=1, remainder=1%8=1, octal="1"+"2"="12", n=1//8=0
Stop (n=0)


Output: 12 ✓


=====================================================
                    📋 QUICK REFERENCE TABLE
=====================================================


Decimal | Binary | Octal | Hex
--------|--------|-------|-----
0       | 0      | 0     | 0
5       | 101    | 5     | 5
10      | 1010   | 12    | A
15      | 1111   | 17    | F
16      | 10000  | 20    | 10
25      | 11001  | 31    | 19
31      | 11111  | 37    | 1F
64      | 1000000| 100   | 40
100     | 1100100| 144   | 64
255     | 11111111| 377  | FF


=================================================
                    ✅ COMPLETE SOLUTION
=================================================
PROBLEM: Decimal to Octal


CODE:
n = int(input())
print(oct(n)[2:])


SAMPLE:
Input: 10
Output: 12


===================================================
                    🎓 SUMMARY
===================================================


NUMBER SYSTEMS:
✓ Decimal (Base 10): 0-9
✓ Binary (Base 2): 0-1 (computers use)
✓ Octal (Base 8): 0-7 (shortcut for binary)
✓ Hex (Base 16): 0-9, A-F (colors, addresses)


CONVERSION LOGIC:
Divide by BASE → store remainder → read reverse = answer


DECIMAL TO OCTAL:
Divide by 8, read remainders bottom-to-top


PYTHON:
print(oct(n)[2:])


====================================================
PLB293 - Sum of Adjacent Elements
------------------------------------------------
PROBLEM STATEMENT:
Implement a program to find sum of adjacent elements in the array
INPUT:
an array size and elements
OUTPUT:
array with sum of adjacent elements
------------------------------------------------
LOGIC:
1.Take input n and array
2.Initialize s=0
3.Add each element to s
4.Print s at every step
------------------------------------------------
EXAMPLE:
Input:
n=5
1 2 3 4 5
Output:
1 3 6 10 15
------------------------------------------------
SYNTAX EXPLANATION:
L=[int(i) for i in input().split()]


input() → takes full line as string
split() → splits by space → ['1','2','3','4','5']
for i in ... → loop through each value
int(i) → convert string to integer
[] → store values in list


Final:
L=[1,2,3,4,5]
------------------------------------------------
CODE WITH COMMENTS:
n=int(input()) #size
L=[int(i) for i in input().split()] #list input
s=0
for i in L:
    s=s+i #add
    print(s,end=' ') #print running sum
------------------------------------------------
FINAL:
👉 prefix sum (running sum)
=====End=====


PLB294 - Vaccination Drive List Preparator
------------------------------------------------
PROBLEM STATEMENT:
Currently government is taking lot of measures to control the spread of Coronavirus. 
As we have vaccine now, many campaigns are done to vaccination.
Health dept is identifying the people in each area and recommended/vaccination of them. 
They are planning three stages


stage1: above 60 years
stage2: between 18 and 60
stage3: below 18 years


Implement a program to read date of birth of the person and decide he belong to which stage.


INPUT:date of birth
OUTPUT:1 or 2 or 3
------------------------------------------------
LOGIC:
1.Take DOB input (dd/mm/yyyy)
2.Extract year
3.Calculate age = current_year - birth_year
4.If age > 60 → stage 1
5.If age between 18 and 60 → stage 2
6.If age < 18 → stage 3
------------------------------------------------
EXAMPLE:
Input:
10/05/2000
Age = 2022 - 2000 = 22
Output:
2
------------------------------------------------
SYNTAX EXPLANATION:
l=input().split("/")


input() → takes DOB string
split("/") → splits by '/' → ['10','05','2000']


l[0]=day
l[1]=month
l[2]=year


------------------------------------------------
CODE WITH COMMENTS:
l=input().split("/") #take DOB
age=2022-int(l[2]) #calculate age from year
if age>60:
    print(1) #stage 1
elif age>=18 and age<=60:
    print(2) #stage 2
else:
    print(3) #stage 3
------------------------------------------------
FINAL:👉 age decide stage
=====End=====


PLB295 - Area of the Circle
------------------------------------------------
PROBLEM STATEMENT:
Implement a program to find the area of the circle
INPUT:
radius value
OUTPUT:
area of the circle (round to two decimals)
------------------------------------------------
FORMULA:
Area = π × r²
π ≈ 3.14159
------------------------------------------------
LOGIC:
1.Take radius n
2.Calculate π × n²
3.Format to 2 decimal places
------------------------------------------------
CODE WITH COMMENTS:
import math
n=int(input()) #radius


# step1: square
# step2: multiply with pi
# step3: format output


print("%.2f"%(math.pi*n**2))
------------------------------------------------
EXAMPLE:
Input:
r=3
Area = 3.14159 × 3²
= 3.14159 × 9
= 28.27431
Output:
28.27
------------------------------------------------
SYNTAX EXPLANATION:
print("%.2f"%(math.pi*n**2))


math.pi → value of π (3.14159...)


n**2 → square of n
Example: 3**2 = 9


math.pi*n**2 → area calculation
Example: 3.14159 × 9 = 28.27431


"%.2f" → format pattern
% → start format
.2 → 2 decimal places
f → float


second % → formatting operator
👉 applies format to value


------------------------------------------------
STEP-BY-STEP EXECUTION:
n=3


Step 1:
n**2 = 3**2 = 9


Step 2:
math.pi * n**2 = 3.14159 × 9 = 28.27431


Step 3:
"%.2f" % 28.27431 → "28.27"


Step 4:
print("28.27")


FINAL:👉 calculate → format → print
=========================End=========================
PLB296 - Divisible by 5 or 7
------------------------------------------------
PROBLEM STATEMENT:
Implement a program to print the list of integers which are divisible by 5 or 7.
INPUT:a number from the user
OUTPUT:seq of int values which are divisible by 5 or 7
------------------------------------------------
LOGIC:
1.Take input n
2.Run loop from 1 to n
3.Check i%5==0 or i%7==0
4.Print such numbers
------------------------------------------------
EXAMPLE:
Input:
n=15
Output:
5 7 10 14 15
------------------------------------------------
SYNTAX EXPLANATION:
i%5==0 → divisible by 5
i%7==0 → divisible by 7
% → modulus (remainder)
Example:
10%5=0 ✔
14%7=0 ✔
------------------------------------------------
CODE WITH COMMENTS:
n=int(input()) #take number
for i in range(1,n+1): #loop 1 to n
    if i%5==0 or i%7==0: #check condition
        print(i,end=' ') #print values
------------------------------------------------
FINAL:👉 divisible means remainder = 0
===============End===============


================================================================================
PLB296 - DIVISIBLE BY 5 OR 7 (WITH TWO VARIABLES)
================================================================================


🎯 PROBLEM: Print all numbers divisible by 5 OR 7 (from n1 to n2)


INPUT: Two numbers (range start and end)
OUTPUT: Sequence of integers divisible by 5 or 7 in that range


EXAMPLE:
Input: 10 35
Output: 14 15 20 21 25 28 30 35


==============================================================
📥 TWO VARIABLES INPUT SYNTAX
==============================================================


METHOD 1: Using tuple unpacking with int()
n1, n2 = (int(i) for i in input().split())


METHOD 2: Using map() (RECOMMENDED - CLEANER)
n1, n2 = map(int, input().split())


METHOD 3: Separate lines
n1 = int(input())
n2 = int(input())


==============================================================
🔍 HOW TWO VARIABLE INPUT WORKS
==============================================================


STEP-BY-STEP (METHOD 2 - map()):


User input: "10 35"


Step 1: input()
→ Returns string "10 35"


Step 2: input().split()
→ Splits by space
→ Returns list ['10', '35']


Step 3: map(int, ...)
→ Converts each string to integer
→ Produces 10, 35


Step 4: n1, n2 = ...
→ First value (10) goes to n1
→ Second value (35) goes to n2


RESULT:
n1 = 10
n2 = 35


==============================================================
DETAILED EXPLANATION
==============================================================


What is input().split()?
"10 35".split() → ['10', '35']


What is map(int, ...)?
map(int, ['10', '35']) → [10, 35] (converts strings to integers)


What is n1, n2 = ?
Assignment: Left side gets right side values one by one
n1 = 10 (first value)
n2 = 35 (second value)


==============================================================
💻 PYTHON CODE (TWO VARIABLES)
==============================================================


n1, n2 = map(int, input().split())


for i in range(n1, n2+1):
    if i % 5 == 0 or i % 7 == 0:
        print(i, end=' ')


EXPLANATION:
- input().split() → Split input by space
- map(int, ...) → Convert to integers
- n1, n2 = ... → Assign to variables
- range(n1, n2+1) → Loop from n1 to n2 (inclusive)


INPUT: 10 35
OUTPUT: 14 15 20 21 25 28 30 35


==============================================================
💻 CODE WITH COMMENTS (TWO VARIABLES)
==============================================================


# Take two numbers as input in one line
# Input format: n1 n2 (space separated)
# Example: 10 35
n1, n2 = map(int, input().split())


# Loop from n1 to n2 (inclusive)
for i in range(n1, n2+1):
    # Check if divisible by 5 or 7
    if i % 5 == 0 or i % 7 == 0:
        # Print the number with space
        print(i, end=' ')


EXAMPLE EXECUTION (n1=10, n2=35):


i=10: 10%5=0 → YES (divisible by 5) ✗ (not in range output)
i=11: 11%5=1, 11%7=4 → NO
i=12: 12%5=2, 12%7=5 → NO
i=13: 13%5=3, 13%7=6 → NO
i=14: 14%7=0 → YES (divisible by 7) ✓
i=15: 15%5=0 → YES (divisible by 5) ✓
i=20: 20%5=0 → YES (divisible by 5) ✓
i=21: 21%7=0 → YES (divisible by 7) ✓
i=25: 25%5=0 → YES (divisible by 5) ✓
i=28: 28%7=0 → YES (divisible by 7) ✓
i=30: 30%5=0 → YES (divisible by 5) ✓
i=35: 35%5=0 → YES (divisible by 5) ✓


OUTPUT: 14 15 20 21 25 28 30 35


==============================================================
📝 STEP-BY-STEP: HOW input().split() WORKS
==============================================================


EXAMPLE:
User enters: 10 35


Step 1: Read input as STRING
input() → "10 35"


Step 2: Split by space
split() → ['10', '35']


Step 3: Convert each to integer
map(int, ['10', '35']) → Generator yielding 10, then 35


Step 4: Unpack to variables
n1, n2 = (10, 35)
n1 = 10
n2 = 35


RESULT: Two variables assigned!


==============================================================
💻 COMPARISON: 3 METHODS
==============================================================


METHOD 1: map() [RECOMMENDED]
n1, n2 = map(int, input().split())


METHOD 2: Generator expression
n1, n2 = (int(i) for i in input().split())


METHOD 3: Separate inputs
n1 = int(input("Enter n1: "))
n2 = int(input("Enter n2: "))


METHOD 4: Manual split
data = input().split()
n1 = int(data[0])
n2 = int(data[1])


All do the same thing, METHOD 1 is cleanest!


==============================================================
🔢 EXAMPLES
==============================================================


EXAMPLE 1:
Input: 10 35
Output: 14 15 20 21 25 28 30 35


EXAMPLE 2:
Input: 1 20
Output: 5 7 10 14 15 20


EXAMPLE 3:
Input: 25 50
Output: 25 28 30 35 40 42 45 49 50


EXAMPLE 4:
Input: 1 10
Output: 5 7 10


==============================================================
💻 COMPLETE SOLUTION (TWO VARIABLES)
==============================================================


n1, n2 = map(int, input().split())


for i in range(n1, n2+1):
    if i % 5 == 0 or i % 7 == 0:
        print(i, end=' ')


INPUT: 10 35
OUTPUT: 14 15 20 21 25 28 30 35


==============================================================
💻 ONE-LINER (TWO VARIABLES)
==============================================================


n1, n2 = map(int, input().split())
print([i for i in range(n1, n2+1) if i % 5 == 0 or i % 7 == 0])


INPUT: 10 35
OUTPUT: [14, 15, 20, 21, 25, 28, 30, 35]


==============================================================
🎯 SYNTAX SUMMARY
==============================================================


SYNTAX: n1, n2 = map(int, input().split())


BREAKDOWN:
├─ input() → Read string from user
├─ .split() → Split by space → list of strings
├─ map(int, ...) → Convert to integers
├─ n1, n2 = → Assign to two variables
└─ Result: n1 and n2 have integer values


SIMPLER UNDERSTANDING:
👉 Left side (n1, n2) has 2 variables
👉 Right side produces 2 values
👉 Python assigns: n1=value1, n2=value2


==============================================================
✅ FINAL CODE
==============================================================


# Take two numbers as input
n1, n2 = map(int, input().split())


# Loop and print divisible by 5 or 7
for i in range(n1, n2+1):
    if i % 5 == 0 or i % 7 == 0:
        print(i, end=' ')


INPUT: 10 35
OUTPUT: 14 15 20 21 25 28 30 35


==============================================================
==============================================================
PLB298 - MIN AND MAX
==============================================================


🎯 PROBLEM: Find absolute difference between sum of max digits 
and sum of min digits in three integers


INPUT: Three numbers (n1, n2, n3)
OUTPUT: Integer value (absolute difference)


EXAMPLE:
Input: 123 456 789
Max digits: 3 + 6 + 9 = 18
Min digits: 1 + 4 + 7 = 12
Output: |18 - 12| = 6


==============================================================
💡 CONCEPT
==============================================================


MAX DIGIT: Largest digit in a number (123 → 3)
MIN DIGIT: Smallest digit in a number (123 → 1)
SUM OF MAX: Add all max digits from each number (3+6+9=18)
SUM OF MIN: Add all min digits from each number (1+4+7=12)
ABSOLUTE DIFFERENCE: |s1 - s2| = |18-12| = 6


==============================================================
📝 STEP-BY-STEP
==============================================================


Input: n1=123, n2=456, n3=789


Step 1: Find max digit from each
123 → max=3, 456 → max=6, 789 → max=9


Step 2: Sum of max digits
s1 = 3 + 6 + 9 = 18


Step 3: Find min digit from each
123 → min=1, 456 → min=4, 789 → min=7


Step 4: Sum of min digits
s2 = 1 + 4 + 7 = 12


Step 5: Absolute difference
|18 - 12| = 6 ✓


==============================================================
💻 PYTHON CODE
==============================================================


n1 = input()
n2 = input()
n3 = input()


s1 = max([int(i) for i in n1]) + max([int(i) for i in n2]) + max([int(i) for i in n3])
s2 = min([int(i) for i in n1]) + min([int(i) for i in n2]) + min([int(i) for i in n3])


print(abs(s1 - s2))


==============================================================
💻 CODE WITH COMMENTS
==============================================================


n1 = input("Enter n1: ")
n2 = input("Enter n2: ")
n3 = input("Enter n3: ")


# Sum of max digits from each number
# [int(i) for i in n1] converts chars to integers
# max() finds largest digit
s1 = max([int(i) for i in n1]) + max([int(i) for i in n2]) + max([int(i) for i in n3])


# Sum of min digits from each number
# min() finds smallest digit
s2 = min([int(i) for i in n1]) + min([int(i) for i in n2]) + min([int(i) for i in n3])


# abs() gives absolute difference (no negative)
print(abs(s1 - s2))


==============================================================
🔍 HOW LIST COMPREHENSION WORKS
==============================================================


Example: n1 = "123"


[int(i) for i in n1]
→ Loop: '1' → 1, '2' → 2, '3' → 3
→ Result: [1, 2, 3]
→ max([1, 2, 3]) = 3
→ min([1, 2, 3]) = 1


==============================================================
🔍 ABSOLUTE VALUE abs()
==============================================================


abs(5) = 5
abs(-5) = 5
abs(18 - 12) = 6
abs(12 - 18) = 6


👉 Always gives positive result


==============================================================
🔢 EXAMPLE
==============================================================


Input: 987 654 321
Max: 9 + 6 + 3 = 18
Min: 7 + 4 + 1 = 12
Output: |18 - 12| = 6


==============================================================
💻 TWO VARIABLE INPUT VERSION
==============================================================


n1, n2, n3 = input().split()


s1 = max([int(i) for i in n1]) + max([int(i) for i in n2]) + max([int(i) for i in n3])
s2 = min([int(i) for i in n1]) + min([int(i) for i in n2]) + min([int(i) for i in n3])


print(abs(s1 - s2))


INPUT: 123 456 789
OUTPUT: 6


==============================================================
📋 SYNTAX BREAKDOWN
==============================================================


[int(i) for i in n1] → Converts each char to integer
max([...]) → Finds maximum value
min([...]) → Finds minimum value
abs(x - y) → Absolute difference (always positive)


==============================================================
✅ FINAL SOLUTION
==============================================================


n1 = input()
n2 = input()
n3 = input()


s1 = max([int(i) for i in n1]) + max([int(i) for i in n2]) + max([int(i) for i in n3])
s2 = min([int(i) for i in n1]) + min([int(i) for i in n2]) + min([int(i) for i in n3])


print(abs(s1 - s2))


INPUT: 123 456 789
OUTPUT: 6


==============================================================
==============================================================
PLB299 - LUCKY STRING
==============================================================


🎯 PROBLEM: Check if string is lucky (sum of ASCII values is even)


INPUT: A string
OUTPUT: true or false


EXAMPLE:
Input: AB
ASCII: A=65, B=66
Sum = 65 + 66 = 131
131 % 2 = 1 (odd)
Output: false


==============================================================
💡 CONCEPT
==============================================================


LUCKY STRING: Sum of ASCII values of all characters is EVEN


ASCII VALUE: Numeric code for each character
A = 65, B = 66, a = 97, b = 98, space = 32


SUM ASCII: Add all character ASCII values
"AB" → 65 + 66 = 131


CHECK EVEN: If sum % 2 == 0 → EVEN → true
If sum % 2 == 1 → ODD → false


==============================================================
PYTHON IMPLEMENTATION:
==============================================================


s = input()
sum = 0
for i in s:
    sum = sum + ord(i)
print('true' if sum%2==0 else 'false')


==============================================================
📝 STEP-BY-STEP
==============================================================


Input: s = "AB"


Step 1: s = input()
→ s = "AB"


Step 2: Initialize sum = 0


Step 3: Loop through each character
i = 'A' → ord('A') = 65 → sum = 0 + 65 = 65
i = 'B' → ord('B') = 66 → sum = 65 + 66 = 131


Step 4: Check if sum is even
131 % 2 = 1 (ODD) → false ✓


Output: false


==============================================================
💻 CODE WITH COMMENTS
==============================================================


# Take string input
s = input()


# Initialize sum to 0
sum = 0


# Loop through each character in string
for i in s:
    # ord(i) returns ASCII value of character
    # Add ASCII value to sum
    sum = sum + ord(i)


# Check if sum is even
# If sum % 2 == 0 → even → print 'true'
# Otherwise → odd → print 'false'
print('true' if sum%2==0 else 'false')


==============================================================
🔍 HOW ord() WORKS
==============================================================


ord('A') = 65
ord('B') = 66
ord('a') = 97
ord('b') = 98
ord(' ') = 32
ord('0') = 48
ord('9') = 57


Each character has unique ASCII value


==============================================================
🔍 MODULUS OPERATOR (%)
==============================================================


% gives remainder after division


131 % 2 = 1 (131 ÷ 2 = 65 remainder 1) → ODD
130 % 2 = 0 (130 ÷ 2 = 65 remainder 0) → EVEN


if sum % 2 == 0 → sum is EVEN → lucky
if sum % 2 == 1 → sum is ODD → not lucky


==============================================================
🔢 EXAMPLE
==============================================================


Input: "CD"
C = 67, D = 68
Sum = 67 + 68 = 135
135 % 2 = 1 (ODD)
Output: false


==============================================================
💻 ALTERNATIVE CODE (USING sum())
==============================================================


s = input()
total = sum(ord(i) for i in s)
print('true' if total % 2 == 0 else 'false')


Explanation:
sum(ord(i) for i in s) → calculates sum of all ASCII values
Shorter version of the loop


==============================================================
💻 ONE-LINER
==============================================================


print('true' if sum(ord(i) for i in input()) % 2 == 0 else 'false')


==============================================================
📋 LINE-BY-LINE BREAKDOWN
==============================================================


s = input()
→ Take string from user


sum = 0
→ Initialize counter to 0


for i in s:
→ Loop through each character


sum = sum + ord(i)
→ Get ASCII value with ord()
→ Add to sum


print('true' if sum%2==0 else 'false')
→ If sum is even (remainder 0) → print 'true'
→ If sum is odd (remainder 1) → print 'false'


==============================================================
✅ FINAL SOLUTION
==============================================================


s = input()
sum = 0
for i in s:
    sum = sum + ord(i)
print('true' if sum%2==0 else 'false')


INPUT: AB
OUTPUT: false


==============================================================
==============================================================
LBP300 - LAST THREE DIGITS
==============================================================


🎯 PROBLEM: Find sum of last three digits in a given number


INPUT: An integer value (must be 3+ digit number)
OUTPUT: Integer value (sum of last 3 digits)


EXAMPLE:
Input: 12345
Last 3 digits: 3, 4, 5
Sum = 3 + 4 + 5 = 12
Output: 12


==============================================================
💡 CONCEPT
==============================================================


LAST THREE DIGITS: The rightmost 3 digits of a number
12345 → last three = 345


NEGATIVE INDEXING: Access digits from end using negative indices
n[-1] → last digit
n[-2] → second last digit
n[-3] → third last digit


STRING CONVERSION: Convert number to string to access digits
12345 → "12345"


==============================================================
PYTHON IMPLEMENTATION:
==============================================================


n = input()
print(int(n[-1]) + int(n[-2]) + int(n[-3]))


==============================================================
📝 STEP-BY-STEP
==============================================================


Input: n = "12345"


Step 1: n = input()
→ n = "12345" (string)


Step 2: Access last three digits using negative indexing
n[-1] = '5' (last digit)
n[-2] = '4' (second last)
n[-3] = '3' (third last)


Step 3: Convert to integers and add
int(n[-1]) = 5
int(n[-2]) = 4
int(n[-3]) = 3
Sum = 5 + 4 + 3 = 12


Step 4: Print result
Output: 12 ✓


==============================================================
🔍 NEGATIVE INDEXING EXPLAINED
==============================================================


String: "12345"
Index:   01234 (forward)
Index:  -5-4-3-2-1 (backward)


Forward indexing (left to right):
n[0] = '1'
n[1] = '2'
n[2] = '3'
n[3] = '4'
n[4] = '5'


Backward indexing (right to left):
n[-1] = '5' (last)
n[-2] = '4' (second last)
n[-3] = '3' (third last)
n[-4] = '2'
n[-5] = '1'


👉 Negative index = Count from END


==============================================================
💻 CODE WITH COMMENTS
==============================================================


# Take number as string input
# (String makes digit access easier)
n = input("Enter number: ")


# Access last 3 digits using negative indexing
# n[-1] = last digit
# n[-2] = second last digit
# n[-3] = third last digit
# Convert to int and add them


sum_of_digits = int(n[-1]) + int(n[-2]) + int(n[-3])


print(sum_of_digits)


==============================================================
🔢 EXAMPLE
==============================================================


Input: 98765
n[-1] = '5'
n[-2] = '6'
n[-3] = '7'
Sum = 5 + 6 + 7 = 18
Output: 18


==============================================================
💻 ALTERNATIVE: USING SLICING
==============================================================


n = input()
last_three = n[-3:]
sum_digits = sum([int(i) for i in last_three])
print(sum_digits)


Explanation:
n[-3:] → Get last 3 characters as string
"98765"[-3:] = "765"
[int(i) for i in "765"] = [7, 6, 5]
sum([7, 6, 5]) = 18


==============================================================
💻 ONE-LINER
==============================================================


print(sum([int(i) for i in input()[-3:]]))


Breakdown:
input()[-3:] → Get last 3 digits as string
[int(i) for i in ...] → Convert each to int
sum(...) → Add them all
print() → Output result


==============================================================
📋 KEY CONCEPTS
==============================================================


NEGATIVE INDEX:
n[-1] = last element
n[-2] = second last element
n[-3] = third last element


SLICING:
n[-3:] = Get last 3 characters
n[-3:] from "12345" = "345"


STRING TO INT:
int('5') = 5 (convert string digit to integer)


==============================================================
💻 WITH ERROR HANDLING
==============================================================


n = input("Enter number (3+ digits): ")


# Check if input has at least 3 digits
if len(n) < 3:
    print("Error: Number must have at least 3 digits")
else:
    result = int(n[-1]) + int(n[-2]) + int(n[-3])
    print(result)


==============================================================
✅ FINAL SOLUTION
==============================================================


n = input()
print(int(n[-1]) + int(n[-2]) + int(n[-3]))


INPUT: 12345
OUTPUT: 12


==============================================================
==============================================================
LBP301 - REVERSE AND REPLACE
==============================================================
🎯 PROBLEM: Reverse string and replace vowels with numbers (1→9)
INPUT: A string
OUTPUT: Updated string (reversed with vowels replaced)
EXAMPLE:
Input: "hello"
Reverse: "olleh"
Replace: o→1, e→2
Output: "1ll2h"
==============================================================
💡 CONCEPT
==============================================================
STEP 1: Reverse the string
"hello" → "olleh"
STEP 2: Replace vowels with numbers (1,2,3...)
Vowels: a, e, i, o, u
First vowel → 1
Second vowel → 2
...
Tenth vowel → restart to 1
STEP 3: Keep consonants as is
==============================================================
PYTHON IMPLEMENTATION:
==============================================================
s = input()
s = s[::-1]  # Reverse string
vowels = "aeiou"
c = 1
result = ""
for i in s:
    if i in vowels:
        result += str(c)
        c = c + 1
        if c == 10:
            c = 1
    else:
        result += i
print(result)
==============================================================
📝 STEP-BY-STEP
==============================================================
Input: "hello"
Step 1: Reverse
"hello"[::-1] = "olleh"
Step 2: Loop and replace
o → vowel → result="1", c=2
l → consonant → result="1l"
l → consonant → result="1ll"
e → vowel → result="1ll2", c=3
h → consonant → result="1ll2h"
Output: "1ll2h" ✓
==============================================================
🔢 EXAMPLE
==============================================================
Input: "aeiou"
Reverse: "uoiea"
Replace: u→1, o→2, i→3, e→4, a→5
Output: "12345"
==============================================================
📋 KEY FUNCTIONS
==============================================================
s[::-1] → Reverse string
i in "aeiou" → Check if vowel
c = c + 1 → Increment counter
if c == 10: c = 1 → Restart after 9
==============================================================
✅ FINAL CODE
==============================================================
s = input()
s = s[::-1]
vowels = "aeiou"
c = 1
result = ""
for i in s:
    if i in vowels:
        result += str(c)
        c = c + 1
        if c == 10:
            c = 1
    else:
        result += i
print(result)
INPUT: hello
OUTPUT: 1ll2h
==============================================================
==============================================================
LBP302 - PARTY ON CRUISE
==============================================================
🎯 PROBLEM: Find total guests on cruise at the end
A party is organized on cruise for limited time (T hours)
Guests entering E[i] and leaving L[i] each hour
Find total guests present at end
INPUT: Size of two arrays E and L, elements of both arrays
OUTPUT: Number of guests present at end of party
EXAMPLE:
E = [5, 3, 2]  (entering each hour)
L = [2, 1, 4]  (leaving each hour)
Hour 1: enter 5, leave 2 → 5-2 = 3 guests
Hour 2: enter 3, leave 1 → 3+3-1 = 5 guests
Hour 3: enter 2, leave 4 → 5+2-4 = 3 guests
Output: 3
==============================================================
💡 CONCEPT
==============================================================
ENTERING (E): Guests entering at each hour
LEAVING (L): Guests leaving at each hour
TOTAL: Sum of all entering - Sum of all leaving
Logic: sum(E) - sum(L) = guests remaining
==============================================================
PYTHON IMPLEMENTATION:
==============================================================
n = int(input())
E = [int(i) for i in input().split()]
L = [int(i) for i in input().split()]
print(sum(E) - sum(L))
==============================================================
📝 STEP-BY-STEP
==============================================================
Input:
n = 3
E = [5, 3, 2]
L = [2, 1, 4]
Step 1: Calculate sum of entering guests
sum(E) = 5 + 3 + 2 = 10
Step 2: Calculate sum of leaving guests
sum(L) = 2 + 1 + 4 = 7
Step 3: Find difference
10 - 7 = 3
Output: 3 ✓
==============================================================
💻 CODE WITH COMMENTS
==============================================================
# Take size of arrays
n = int(input())
# Take entering guests array
E = [int(i) for i in input().split()]
# Take leaving guests array
L = [int(i) for i in input().split()]
# Total guests = sum(entering) - sum(leaving)
print(sum(E) - sum(L))
==============================================================
🔍 HOW sum() WORKS
==============================================================
sum([5, 3, 2]) = 5 + 3 + 2 = 10
sum([2, 1, 4]) = 2 + 1 + 4 = 7
Calculates total of all elements
==============================================================
🔢 EXAMPLE
==============================================================
Input:
n = 4
E = [10, 5, 8, 3]
L = [4, 2, 6, 1]
Calculation:
sum(E) = 10+5+8+3 = 26
sum(L) = 4+2+6+1 = 13
Result = 26 - 13 = 13
Output: 13
==============================================================
💻 ALTERNATIVE (HOUR BY HOUR)
==============================================================
n = int(input())
E = [int(i) for i in input().split()]
L = [int(i) for i in input().split()]
guests = 0
for i in range(n):
    guests = guests + E[i] - L[i]
print(guests)
Logic: Track guests hour by hour
Hour 1: guests = 0 + (5-2) = 3
Hour 2: guests = 3 + (3-1) = 5
Hour 3: guests = 5 + (2-4) = 3
==============================================================
📋 KEY FUNCTIONS
==============================================================
sum(list) → Add all elements
[int(i) for i in input().split()] → Convert input to list of integers
int(input()) → Take integer input
==============================================================
✅ FINAL CODE
==============================================================
n = int(input())
E = [int(i) for i in input().split()]
L = [int(i) for i in input().split()]
print(sum(E) - sum(L))
INPUT:
3
5 3 2
2 1 4
OUTPUT: 3
==============================================================
==============================================================
LBP303 - AIRPORT SECURITY
==============================================================
🎯 PROBLEM: Sort items by risk level (0, 1, 2)
Confiscated items have risk values 0, 1, or 2
Sort items in ascending order of risk
INPUT: Array size and elements (risk values)
OUTPUT: Sorted items based on risk level
EXAMPLE:
Input: [2, 0, 1, 2, 0, 1]
Output: [0, 0, 1, 1, 2, 2]
Risk 0 (safe) first, then 1, then 2 (dangerous)
==============================================================
💡 CONCEPT
==============================================================
RISK LEVELS:
0 = Safe items
1 = Medium risk items
2 = High risk items (dangerous)
SORTING: Arrange items in ascending order
[2, 0, 1, 2, 0, 1] → [0, 0, 1, 1, 2, 2]
==============================================================
PYTHON IMPLEMENTATION:
==============================================================
n = int(input())
L = [int(i) for i in input().split()]
L.sort()
for i in L:
    print(i, end=' ')
==============================================================
📝 STEP-BY-STEP
==============================================================
Input:
n = 6
L = [2, 0, 1, 2, 0, 1]
Step 1: Create list from input
L = [2, 0, 1, 2, 0, 1]
Step 2: Sort in ascending order
L.sort() → [0, 0, 1, 1, 2, 2]
Step 3: Print sorted items
print: 0 0 1 1 2 2
Output: 0 0 1 1 2 2 ✓
==============================================================
💻 CODE WITH COMMENTS
==============================================================
# Take array size
n = int(input())
# Take array elements as list of integers
L = [int(i) for i in input().split()]
# Sort in ascending order (0, 1, 2)
L.sort()
# Print each item with space
for i in L:
    print(i, end=' ')
==============================================================
🔍 HOW sort() WORKS
==============================================================
L = [2, 0, 1, 2, 0, 1]
L.sort()
Arranges in ascending order: [0, 0, 1, 1, 2, 2]
Modifies original list
==============================================================
🔢 EXAMPLE
==============================================================
Input:
n = 5
L = [1, 2, 0, 1, 2]
After sort: [0, 1, 1, 2, 2]
Output: 0 1 1 2 2
==============================================================
💻 ALTERNATIVE (WITHOUT sort())
==============================================================
n = int(input())
L = [int(i) for i in input().split()]
# Count each risk level
zeros = L.count(0)
ones = L.count(1)
twos = L.count(2)
# Print in order
for i in range(zeros):
    print(0, end=' ')
for i in range(ones):
    print(1, end=' ')
for i in range(twos):
    print(2, end=' ')
Logic: Count items of each risk level, print in order
==============================================================
💻 ONE-LINER
==============================================================
L = [int(i) for i in input().split()]
print(' '.join(map(str, sorted(L))))
==============================================================
📋 KEY FUNCTIONS
==============================================================
L.sort() → Sort list in ascending order
L.count(x) → Count occurrences of x
sorted(L) → Return sorted list (doesn't modify original)
print(i, end=' ') → Print without newline
==============================================================
✅ FINAL CODE
==============================================================
n = int(input())
L = [int(i) for i in input().split()]
L.sort()
for i in L:
    print(i, end=' ')
INPUT:
6
2 0 1 2 0 1
OUTPUT: 0 0 1 1 2 2
==============================================================
==============================================================
PLB304 - CHOCOLATE FACTORY
==============================================================
🎯 PROBLEM: Move empty packets (0) to end of array
INPUT: Array size and elements
OUTPUT: Array with 0s at end, non-zeros in front
EXAMPLE:
Input: 1 0 2 0 3 0
Output: 1 2 3 0 0 0
==============================================================
💡 CONCEPT
==============================================================
0 = empty packets
non-zero = full packets
Logic: print non-zeros first, then zeros
==============================================================
📝 LOGIC
==============================================================
1. Take input n and array
2. Initialize count c=0
3. If element ≠ 0 → print
4. If element = 0 → count++
5. Print 0 c times
==============================================================
📝 STEP-BY-STEP
==============================================================
L = [1, 0, 2, 0, 3, 0]
i=1 → print 1, c=0
i=0 → c=1
i=2 → print 2, c=1
i=0 → c=2
i=3 → print 3, c=2
i=0 → c=3
Print 0 three times → 0 0 0
Output: 1 2 3 0 0 0 ✓
==============================================================
💻 CODE WITH COMMENTS
==============================================================
n = int(input())
L = [int(i) for i in input().split()]
c = 0
for i in L:
    if i != 0:
        print(i, end=' ')
    else:
        c = c + 1
for i in range(c):
    print(0, end=' ')
==============================================================
💻 ALTERNATIVE (LAMBDA)
==============================================================
n = int(input())
L = [int(i) for i in input().split()]
L.sort(key=lambda x: x == 0)
for i in L:
    print(i, end=' ')
==============================================================
==============================================================
LAMBDA FUNCTION - EXPLAINED
==============================================================
🎯 WHAT IS LAMBDA:
Anonymous function without name
One-line function
SYNTAX:
lambda arguments : expression
==============================================================
💡 BASIC EXAMPLE
==============================================================
lambda x: x * 2
Input 5 → Output 10
==============================================================
💡 LAMBDA VS NORMAL FUNCTION
==============================================================
NORMAL:
def add(x):
    return x + 1
LAMBDA:
lambda x: x + 1
Same thing, lambda is shorter
==============================================================
📋 USE CASE 1: SORT()
==============================================================
L = [1, 0, 2, 0, 3]
L.sort(key=lambda x: x == 0)
Output: [1, 2, 3, 0, 0]
How it works:
x=1 → 1==0 → False (0)
x=0 → 0==0 → True (1)
x=2 → 2==0 → False (0)
Sort: False < True
Result: Non-zeros first, zeros last ✓
==============================================================
📋 USE CASE 2: MAP()
==============================================================
nums = [1, 2, 3]
result = list(map(lambda x: x * 2, nums))
Output: [2, 4, 6]
Transform each element by multiplying by 2 ✓
==============================================================
📋 USE CASE 3: FILTER()
==============================================================
nums = [1, 2, 3, 4, 5, 6]
result = list(filter(lambda x: x % 2 == 0, nums))
Output: [2, 4, 6]
Keep only even numbers (remainder = 0) ✓
==============================================================
📋 MULTIPLE ARGUMENTS
==============================================================
func = lambda x, y: x + y
func(3, 4) → 7
Add two numbers ✓
==============================================================
✅ FINAL CODE (PLB304)
==============================================================
n = int(input())
L = [int(i) for i in input().split()]
c = 0
for i in L:
    if i != 0:
        print(i, end=' ')
    else:
        c = c + 1
for i in range(c):
    print(0, end=' ')
INPUT:
6
1 0 2 0 3 0
OUTPUT: 1 2 3 0 0 0
==============================================================
==============================================================
LBP305 - DIGITAL LOGIC
==============================================================
🎯 PROBLEM: Convert decimal to binary, toggle all bits, convert back
INPUT: Positive integer
OUTPUT: Positive decimal integer after toggling all bits
EXAMPLE:
Input: 5
Binary: 0101
Toggle: 1010
Output: 10
==============================================================
💡 CONCEPT
==============================================================
DECIMAL TO BINARY: Convert number to binary representation
5 → 0101 (4 bits)
TOGGLE BITS: Flip 0→1 and 1→0
0101 → 1010
BINARY TO DECIMAL: Convert back to decimal
1010 → 10
==============================================================
📝 STEP-BY-STEP
==============================================================
Input: n = 5
Step 1: Convert to binary (4 bits)
5 = 0101
d=5%2=1 → L[0]=1
d=5/2=2
d=2%2=0 → L[1]=0
d=2/2=1
d=1%2=1 → L[2]=1
d=1/2=0
d=0%2=0 → L[3]=0
Result: L=[1,0,1,0] (reversed: [0,1,0,1])
Step 2: Toggle all bits
for i in range(4):
if L[i]==0: L[i]=1
else: L[i]=0
L=[1,0,1,0] → [0,1,0,1]
Step 3: Convert binary to decimal
0*1 + 1*2 + 0*4 + 1*8 = 0+2+0+8 = 10
Output: 10 ✓
==============================================================
💻 CODE EXPLANATION
==============================================================
n = int(input())
L = [0,0,0,0]
i = 0
while n != 0:
    d = n % 2
    L[i] = d
    i = i + 1
    n = n // 2
BINARY CONVERSION: Store each bit in array
Toggle bits:
for i in range(4):
    if L[i] == 0:
        L[i] = 1
    else:
        L[i] = 0
FLIP: 0→1, 1→0
Convert back to decimal:
print(L[0]*1 + L[1]*2 + L[2]*4 + L[3]*8)
FORMULA: Sum of (bit * 2^position)
==============================================================
🔍 HOW BINARY CONVERSION WORKS
==============================================================
Number: 5
Step 1: 5 % 2 = 1, 5 // 2 = 2 → L[0] = 1
Step 2: 2 % 2 = 0, 2 // 2 = 1 → L[1] = 0
Step 3: 1 % 2 = 1, 1 // 2 = 0 → L[2] = 1
Step 4: 0 % 2 = 0, 0 // 2 = 0 → L[3] = 0
Result: [1,0,1,0] = 0101 (reversed order)
==============================================================
🔍 HOW BIT TOGGLING WORKS
==============================================================
Original: [1,0,1,0]
Toggle:
L[0]=1 → becomes 0
L[1]=0 → becomes 1
L[2]=1 → becomes 0
L[3]=0 → becomes 1
Result: [0,1,0,1]
==============================================================
🔍 HOW BINARY TO DECIMAL WORKS
==============================================================
Binary: [0,1,0,1]
Position: 0,1,2,3 (powers of 2)
Formula: L[0]*2^0 + L[1]*2^1 + L[2]*2^2 + L[3]*2^3
= 0*1 + 1*2 + 0*4 + 1*8
= 0 + 2 + 0 + 8
= 10 ✓
==============================================================
🔢 EXAMPLE
==============================================================
Input: 3
Binary: 0011
Toggle: 1100
L = [1,1,0,0]
Decimal: 1*1 + 1*2 + 0*4 + 0*8 = 1+2 = 3
Output: 3
==============================================================
🔢 ANOTHER EXAMPLE
==============================================================
Input: 12
Binary: 1100
Toggle: 0011
L = [0,0,1,1]
Decimal: 0*1 + 0*2 + 1*4 + 1*8 = 4+8 = 12
Output: 12
==============================================================
💻 COMPLETE CODE
==============================================================
n = int(input())
L = [0,0,0,0]
i = 0
while n != 0:
    d = n % 2
    L[i] = d
    i = i + 1
    n = n // 2
for i in range(4):
    if L[i] == 0:
        L[i] = 1
    else:
        L[i] = 0
print(L[0]*1 + L[1]*2 + L[2]*4 + L[3]*8)
INPUT: 5
OUTPUT: 10
==============================================================
📋 KEY CONCEPTS
==============================================================
n % 2 → Get last bit (0 or 1)
n // 2 → Remove last bit (divide by 2)
if L[i]==0: L[i]=1 → Toggle bit
L[0]*1 + L[1]*2 + L[2]*4 + L[3]*8 → Binary to decimal
==============================================================
==============================================================
DICTIONARY (PYTHON) - QUICK GUIDE
==============================================================
🎯 WHAT IS DICTIONARY:
Collection of key-value pairs
d = {key: value}
EXAMPLE:
d = {'1':2, '2':3}
Digit 1 appears 2 times
==============================================================
💡 WHY USE DICTIONARY:
Count frequencies easily
Fast lookup by key
Store related data
==============================================================
🔍 d[i] = d.get(i, 0) + 1 EXPLAINED
==============================================================
d.get(i, 0)
↓  ↓  ↓
key, default
i = The digit we're counting
0 = Default value if digit not found yet
EXAMPLE:
d = {}
i = 1
d[1] = d.get(1, 0) + 1
↓     ↓          ↓
key   Returns 0  Add 1
      (not found)
Result: d[1] = 0 + 1 = 1
NEXT ITERATION:
d[1] = d.get(1, 0) + 1
↓     ↓          ↓
key   Returns 1  Add 1
      (found!)
Result: d[1] = 1 + 1 = 2
==============================================================
📋 DICTIONARY METHODS
==============================================================
d.get(key, default)
→ Return value if key exists
→ Return default if key doesn't exist
d.values()
→ Get all count values
d.items()
→ Get all key-value pairs
==============================================================
==========================
LBP306 - Security Key
==========================
PROBLEM STATEMENT:
A company is transmitting data to another server.
The data is in the form of numbers.
To secure the data during transmission, they plan to obtain a security key that will be sent along with the data.
The security key is identified as the count of the repeating digits in the data.
Write a algorithm to find the security key for the data.
input ------> integer data to be transmitted
constraint --> no
output ------> security key or -1
==========================
LOGIC:
1.Take input digits
2.Store frequency using array
3.If frequency ≥2 → count it
4.If count>0 print count else -1
==========================
ARRAY UNDERSTANDING:
a = [0] * 10
[0] → list with one element (0)
10 → repeat 10 times
* → repetition operator
Result:
[0,0,0,0,0,0,0,0,0,0]
==========================
INDEX & VALUE CONCEPT:
Index = digit (0–9)
Value = frequency (count)


Example:
a=[0]*10


Input:112233


Step:
1 → a[1]=1 → a[1]=2
2 → a[2]=1 → a[2]=2
3 → a[3]=1 → a[3]=2


Final array:
Index:  0 1 2 3 4 5 6 7 8 9
Value: [0,2,2,2,0,0,0,0,0,0]


Meaning:
a[1]=2 → digit 1 appears 2 times
a[2]=2 → digit 2 appears 2 times
a[3]=2 → digit 3 appears 2 times
==========================
LOW LEVEL LOGIC:
a[10]={0} (C style)
for each digit:
    a[digit]++
if a[i] >=2 → count++
==========================
EXAMPLE:
Input:112233
Repeating digits:1,2,3 → count=3
Output:3
==========================
PYTHON CODE:
a=[0]*10
n=input()
for i in n:
    digit=int(i)
    a[digit]+=1
c=0
for i in a:
    if i>=2:
        c+=1
print(c if c!=0 else -1)
==========================
FINAL:
👉 index = digit
👉 value = frequency
=====End=====


==============================================================
PLB306 - SECURITY KEY
==============================================================
🎯 PROBLEM: Count digits that repeat ≥2 times
INPUT: Integer data (digits)
OUTPUT: Count of repeating digits (or -1)
EXAMPLE:
Input: 112233
Digit 1 → 2 times ✓
Digit 2 → 2 times ✓
Digit 3 → 2 times ✓
Output: 3
==============================================================
📝 LOGIC
==============================================================
1. Count frequency of each digit
2. Count how many digits repeat ≥2 times
3. If count >0 → print count
4. Else → print -1
==============================================================
📝 STEP-BY-STEP
==============================================================
Input: 112233
Step 1: Count frequency
d = {}
Loop: 1,1,2,2,3,3
d[1]=1 → d[1]=2
d[2]=1 → d[2]=2
d[3]=1 → d[3]=2
Result: d = {1:2, 2:2, 3:2}
Step 2: Count digits with frequency ≥2
d.values() = [2, 2, 2]
c = 0
2≥2 → c=1
2≥2 → c=2
2≥2 → c=3
Result: c = 3
Step 3: Output
Output: 3 ✓
==============================================================
💻 COMPLETE CODE
==============================================================
d = {}
L = [int(i) for i in input()]
for i in L:
    d[i] = d.get(i, 0) + 1
c = 0
for count in d.values():
    if count >= 2:
        c = c + 1
print(c if c != 0 else -1)
==============================================================
💻 CODE WITH COMMENTS
==============================================================
d = {}
Empty dictionary
L = [int(i) for i in input()]
Convert input to list of digits
for i in L:
    d[i] = d.get(i, 0) + 1
Count each digit:
i = current digit
d.get(i, 0) = get count (or 0 if new)
Add 1 = increment count
c = 0
Counter for repeating digits
for count in d.values():
    if count >= 2:
        c = c + 1
Loop through all counts
If digit repeats ≥2 times, increment c
print(c if c != 0 else -1)
If c > 0, print c
Otherwise print -1
==============================================================
🔢 EXAMPLE 1
==============================================================
Input: 112233
d = {1:2, 2:2, 3:2}
Repeating: 1, 2, 3 = 3
Output: 3
==============================================================
🔢 EXAMPLE 2
==============================================================
Input: 12345
d = {1:1, 2:1, 3:1, 4:1, 5:1}
Repeating: none = 0
Output: -1
==============================================================
🔢 EXAMPLE 3
==============================================================
Input: 111222
d = {1:3, 2:3}
Repeating: 1, 2 = 2
Output: 2
==============================================================
📋 KEY CONCEPTS
==============================================================
d = {} → Empty dictionary
i → Current digit (key)
0 → Default value (if key not found)
d.values() → Get all counts
if count >= 2 → Check if repeats
c if c != 0 else -1 → Ternary operator
==============================================================
✅ FINAL CODE
==============================================================
d = {}
L = [int(i) for i in input()]
for i in L:
    d[i] = d.get(i, 0) + 1
c = 0
for count in d.values():
    if count >= 2:
        c = c + 1
print(c if c != 0 else -1)
INPUT: 112233
OUTPUT: 3
==============================================================
==================================================
LBP307 - DATA ENCODE
==================================================
🎯 PROBLEM STATEMENT:
A company wishes to encode its data. The data is in the form
of a number. They wish to encode the data with respect to a
specific digit. They wish to count the number of times the
specific digit reoccurs in the given data so that they can
encode the data accordingly. Write an algorithm to find the
count of the specific digit in the given data.
INPUT ------> data and digit
CONSTRAINT --> no
OUTPUT ------> count of specific digit
==================================================
📝 LOGIC FLOW
==================================================
1. Take input (data and digit)
   Example: "112233 2"


2. Split input
   "112233 2" → ["112233", "2"]


3. Count digit occurrences in data
   "112233".count("2") = 2


4. Print result
   Output: 2


==================================================
📝 GENERATOR EXPLAINED
==================================================
Generator: Returns values one by one (not all at once)
Syntax: (expression for variable in iterable)
==================================================
📝 GENERATOR SYNTAX BREAKDOWN
==================================================
(expression for variable in iterable)
↓ ↓        ↓                ↓
| |        |                └─ source (list)
| |        └─ takes values one by one
| └─ what to return
└─ creates generator


YOUR CASE:
(i for i in input().split())
↓ ↓       ↓                 ↓
| |       |                 └─ ["112233","2"]
| |       └─ variable i gets each value
| └─ return i (same value)
└─ generator expression


👉 Both "i" are SAME variable
Example:
(i for i in ["112233", "2"])
Returns:
First → "112233"
Second → "2"


Meaning:
👉 returns = gives one value at a time (first i in ==> (i for i in ["112233", "2"]) )
👉 not all values together
==================================================
📝 YIELD EXPLAINED
==================================================
yield: Keyword used in generator functions
Pauses function and returns value
Resumes from where it paused on next call
Used in: def (function definition)


Syntax:
def generator_name():
    yield value1
    yield value2
    yield value3


Example:
def count_gen():
    yield 1
    yield 2
    yield 3


First call → returns 1, pauses
Second call → returns 2, pauses
Third call → returns 3, stops


Meaning:
👉 yield = pause and give one value
👉 can resume later
==================================================
📝 GENERATOR EXPRESSION vs GENERATOR FUNCTION
==================================================
GENERATOR EXPRESSION:
(i for i in ["112233", "2"])
Short syntax
Used directly


GENERATOR FUNCTION:
def my_gen():
    for i in ["112233", "2"]:
        yield i
Long syntax
Uses yield keyword


Both do same thing:
Return values one by one
==================================================
📝 YIELD in GENERATOR FUNCTION
==================================================
def count_gen():
    yield "112233"
    yield "2"


Usage:
for val in count_gen():
    print(val)


Output:
112233
2


How it works:
Call 1 → yield "112233" (pause)
Call 2 → yield "2" (stop)
==================================================
📝 YIELD vs RETURN
==================================================
RETURN:
def func():
    return 5
→ Returns 5, function ends


YIELD:
def gen():
    yield 5
→ Returns 5, function pauses
→ Can resume later


Example:
RETURN:
func() → 5 (done)


YIELD:
next(gen()) → 5 (pause)
next(gen()) → continues
==================================================
📝 GENERATOR IN CODE
==================================================
s, key = (i for i in input().split())


Step 1: input().split()
"112233 2" → ["112233", "2"]


Step 2: Generator returns/yields
(i for i in ["112233", "2"])
First return: "112233"
Second return: "2"


Step 3: Assign to variables
s = "112233"
key = "2"


Note:
Generator expression doesn't use yield keyword
Generator function uses yield keyword
Both return values one by one
==================================================
📝 YIELD EXAMPLE 1
==================================================
def my_gen():
    yield 10
    yield 20
    yield 30


Usage:
for val in my_gen():
    print(val)


Output:
10
20
30


How it works:
First call → yield 10 (pause)
Second call → yield 20 (pause)
Third call → yield 30 (stop)
==================================================
📝 YIELD EXAMPLE 2
==================================================
def fruits_gen():
    yield "apple"
    yield "banana"
    yield "orange"


Usage:
for fruit in fruits_gen():
    print(fruit)


Output:
apple
banana
orange


How it works:
First call → yield "apple" (pause)
Second call → yield "banana" (pause)
Third call → yield "orange" (stop)
==================================================
📝 YIELD EXAMPLE 3
==================================================
def range_gen(n):
    i = 0
    while i < n:
        yield i
        i = i + 1


Usage:
for num in range_gen(5):
    print(num)


Output:
0
1
2
3
4


How it works:
First call → yield 0 (pause)
Second call → yield 1 (pause)
...continues until i >= 5
==================================================
📝 COUNT FUNCTION
==================================================
s.count(key)


Counts occurrences of digit in data


Example:
"112233".count("2") = 2
Count how many '2' in "112233"
==================================================
📝 STEP FLOW
==================================================
Input: 112233 2
→ split() → ["112233", "2"]
→ generator/yield → returns values one by one
→ assign → s = "112233", key = "2"
→ count() → "112233".count("2") = 2
→ print → Output: 2
==================================================
💻 PYTHON CODE (WITH GENERATOR EXPRESSION)
==================================================
s, key = (i for i in input().split())
print(s.count(key))
==================================================
💻 PYTHON CODE (WITH GENERATOR FUNCTION)
==================================================
def my_gen():
    for i in input().split():
        yield i


s, key = my_gen()
print(s.count(key))
==================================================
💻 PYTHON CODE (WITHOUT GENERATOR)
==================================================
s, key = input().split()
print(s.count(key))
==================================================
📋 KEY CONCEPTS
==================================================
Generator: Returns values one by one
yield: Pause and return value in function
(i for i in iterable): Generator expression
split(): Break string by space
count(): Count occurrences
s.count(key): Count digit in data
==================================================
🔢 EXAMPLE 1 (STEP BY STEP)
==================================================
Input: 112233 2


Step 1: Split
input().split() → ["112233", "2"]


Step 2: Generator returns
(i for i in ["112233", "2"])
First return: "112233"
Second return: "2"


Step 3: Assign
s = "112233"
key = "2"


Step 4: Count
"112233".count("2")
Position 1: '1' ≠ '2'
Position 2: '1' ≠ '2'
Position 3: '2' = '2' ✓ (count = 1)
Position 4: '2' = '2' ✓ (count = 2)
Position 5: '3' ≠ '2'
Position 6: '3' ≠ '2'
Total: 2


Step 5: Output
Output: 2


==================================================
✅ FINAL EXPLANATION
==================================================
Step 3: Use count() to count DIGIT occurrences in DATA


s.count(key)
↓     ↓
data  digit


"112233".count("2") = 2
Search for '2' in '112233' = Found 2 times
==================================================
✅ FINAL
👉 split → assign → count → print
👉 Generator/yield returns values one by one
==================================================
==========================
LBP308 - One Time Password
==========================
PROBLEM STATEMENT:
An e-commerce site wishes to enhance its ordering process. 
They plan to implement a new scheme of OTP generation for order confirmations. 
The OTP can be any number of digits. For OTP generation, the user will be asked
for two random numbers where first number is always smaller than second number. 
The OTP is calculated as the sum of the maximum and minimum prime values in the range
of the user-entered numbers. Write a program to generate OTP.
input --------> two integer values
constraint ----> first number < second number
output --------> sum of max and min prime numbers
==========================
CONCEPT:
PRIME NUMBER → number with only 2 factors (1 and itself)
MIN PRIME → smallest prime in range
MAX PRIME → largest prime in range
OTP → min prime + max prime
==========================
LOGIC:
1.Take input n1,n2
2.Find first prime ≥ n1 (min prime)
3.Find first prime ≤ n2 (max prime)
4.Add both → print result
# ==================================================
# KEY CONCEPTS
# ==================================================
# 1. isprime(n):
#    - Counts all factors of n
#    - Returns True if exactly 2 factors (1 and n)
#    - Returns False otherwise
#
# 2. while True loop with break:
#    - Keeps looping until a condition is met
#    - break statement exits the loop
#
# 3. Moving right (n1 = n1 + 1):
#    - Increases number to find minimum prime
#    - Moves from left to right
#
# 4. Moving left (n2 = n2 - 1):
#    - Decreases number to find maximum prime
#    - Moves from right to left
#
# 5. Final result:
#    - Sum of minimum prime and maximum prime
#    - From the given range [n1, n2]
# ==================================================
# ==================================================
# EXAMPLE 1: Input "1 10"
# ==================================================
# STEP 2: n1=1, n2=10
# 
# STEP 3: Find first prime from left
# f stands for factor
# n1=1 → isprime(1) → f=1 → False → n1=2
# n1=2 → isprime(2) → f=2 → True → s1=2 → break
#
# STEP 4: Find first prime from right
# n2=10 → isprime(10) → f=4 → False → n2=9
# n2=9 → isprime(9) → f=3 → False → n2=8
# n2=8 → isprime(8) → f=4 → False → n2=7
# n2=7 → isprime(7) → f=2 → True → s2=7 → break
#
# STEP 5: Calculate and print
# s1 + s2 = 2 + 7 = 9
# Output: 9


==========================
EXAMPLE:
Input:1 10
Primes:2,3,5,7
Min prime=2
Max prime=7
OTP=2+7=9
Output:9
==========================
ISPRIME FUNCTION:
def isprime(n):           #check prime
    f=0
    for i in range(1,n+1):
        if n%i==0:
            f=f+1
    return f==2           #prime if exactly 2 factors
==========================
==========================
PYTHON CODE WITH COMMENTS:
==========================
# STEP 1: isprime function
# Purpose: Check if a number is prime
# Logic: Count factors, return True if exactly 2 factors
def isprime(n):
    # Initialize factor counter to 0
    f = 0
    # Loop from 1 to n (check all possible divisors)
    for i in range(1, n + 1):
        # Check if i divides n evenly (remainder is 0)
        if n % i == 0:
            # i is a factor of n, increment counter
            f = f + 1
    # Return True only if exactly 2 factors found
    # (Prime numbers have exactly 2 factors: 1 and itself)
    return f == 2
# ==================================================
# STEP 2: Take input
# Purpose: Read two numbers from user
# n1 = left side number
# n2 = right side number
n1, n2 = (int(i) for i in input().split())
# ==================================================
# STEP 3: Find first prime moving RIGHT from n1
# Purpose: Find minimum prime starting from n1
# Logic: Keep checking n1, if not prime increase n1
while True:
    # Check if current n1 is prime
    if isprime(n1):
        # Found first prime from left
        s1 = n1
        # Exit loop when prime is found
        break
    # Move to next number (increase n1)
    n1 = n1 + 1
# ==================================================
# STEP 4: Find first prime moving LEFT from n2
# Purpose: Find maximum prime starting from n2
# Logic: Keep checking n2, if not prime decrease n2
while True:
    # Check if current n2 is prime
    if isprime(n2):
        # Found first prime from right
        s2 = n2
        # Exit loop when prime is found
        break
    # Move to previous number (decrease n2)
    n2 = n2 - 1
# ==================================================
# STEP 5: Add and print
# Purpose: Calculate sum of both primes and display result
# s1 = minimum prime from left
# s2 = maximum prime from right
print(s1 + s2)


==========================
EXAMPLE FLOW:
Input:1 10
n1 moves → 1→2 (prime found)
n2 moves → 10→9→8→7 (prime found)
Output → 2+7 = 9
==========================
FINAL:
👉 left → min prime  
👉 right → max prime  
👉 add both  
=====End=====
==========================
STEP FLOW:
Input:1 10
→ check from 1 upward → first prime=2
→ check from 10 backward → first prime=7
→ sum=2+7=9
==========================
FINAL:
👉 find min prime + max prime → add
=====End=====
==================================================
LBP309 - NEAREST PALINDROME
==================================================
🎯 PROBLEM STATEMENT:
Write a program to find nearest greater palindrome


INPUT ------> an integer value
CONSTRAINT --> n > 0
OUTPUT ------> print nearest palindrome value
==================================================
💡 CONCEPT
==================================================
PALINDROME: Number reads same forwards and backwards
Examples:
121 → "121" reversed = "121" → PALINDROME ✓
1331 → "1331" reversed = "1331" → PALINDROME ✓
123 → "123" reversed = "321" → NOT PALINDROME ✗
1234 → "1234" reversed = "4321" → NOT PALINDROME ✗


NEAREST GREATER PALINDROME: 
Find palindrome > n (greater than input)
Closest to input number
==================================================
📝 PALINDROME CHECK LOGIC
==================================================
str(n) == str(n)[::-1]
↓       ↓           ↓
string reversed string


str(n): Convert number to string
str(n)[::-1]: Reverse the string
str(n) == str(n)[::-1]: Check if same
==================================================
🔍 PALINDROME CHECK EXAMPLES
==================================================
EXAMPLE 1: n = 121
str(121) = "121"
str(121)[::-1] = "121" (reversed)
"121" == "121" → True → PALINDROME ✓


EXAMPLE 2: n = 123
str(123) = "123"
str(123)[::-1] = "321" (reversed)
"123" == "321" → False → NOT PALINDROME ✗


EXAMPLE 3: n = 1331
str(1331) = "1331"
str(1331)[::-1] = "1331" (reversed)
"1331" == "1331" → True → PALINDROME ✓




==================================================
💻 PYTHON CODE
==================================================
n = int(input())


while True:
    if str(n) == str(n)[::-1]:
        print(n)
        break
    n = n + 1
==================================================
📝 LOGIC FLOW
==================================================
1. Take input (integer n)
2. Increment n by 1
3. Check if n is palindrome
4. If palindrome → print n, stop
5. If not → go to step 2
==================================================
📝 STEP-BY-STEP EXPLANATION
==================================================
Step 1: Take input
n = int(input())
Example: n = 120


Step 2: Start loop
while True:
Repeat until palindrome found


Step 3: Check palindrome condition
if str(n) == str(n)[::-1]:
Check if n is palindrome


Step 4: If palindrome found
print(n)
Print the palindrome value
break
Stop loop


Step 5: If not palindrome
n = n + 1
Increase n and check again


==================================================
🔢 EXAMPLE 1 (STEP BY STEP)
==================================================
Input: 120


Iteration 1:
n = 120
str(120) = "120"
str(120)[::-1] = "021"
"120" == "021" → False
n = 120 + 1 = 121


Iteration 2:
n = 121
str(121) = "121"
str(121)[::-1] = "121"
"121" == "121" → True ✓
print(121)
break


Output: 121


==================================================
LBP310 - FIZZBUZZ
==================================================
🎯 PROBLEM STATEMENT:
Given a number n, for each integer i in the range from 1 to n 
inclusive, print one value per line as follows:


=> if i is a multiple of both 3 and 5 print FizzBuzz
=> if i is a multiple of 3 (but not 5), print Fizz
=> if i is a multiple of 5 (but not 3), print Buzz
=> if i is not a multiple of 3 or 5 print the value of i.


Implement a program to read number n print the output as 
described above.


INPUT ------> a number n
CONSTRAINT --> no
OUTPUT ------> print n string as per the above rules
==================================================
💡 CONCEPT
==================================================
MULTIPLE: Number divisible by another with no remainder
i % 3 == 0 → i is multiple of 3
i % 5 == 0 → i is multiple of 5


DIVISIBILITY: Check using modulo operator (%)
i % n == 0 → i is divisible by n
i % n != 0 → i is not divisible by n
==================================================
📝 LOGIC FLOW
==================================================
1. Take input n
2. Loop from 1 to n
3. For each i:
   - If i % 3 == 0 AND i % 5 == 0 → print "FizzBuzz"
   - Else if i % 3 == 0 AND i % 5 != 0 → print "Fizz"
   - Else if i % 5 == 0 AND i % 3 != 0 → print "Buzz"
   - Else → print i
==================================================
💻 PYTHON CODE
==================================================
n = int(input())


for i in range(1, n+1):
    if i % 3 == 0 and i % 5 == 0:
        print('FizzBuzz')
    elif i % 3 == 0 and i % 5 != 0:
        print('Fizz')
    elif i % 5 == 0 and i % 3 != 0:
        print('Buzz')
    else:
        print(i)
==================================================
📝 STEP-BY-STEP EXPLANATION
==================================================
Step 1: Take input
n = int(input())
Example: n = 15


Step 2: Loop from 1 to n
for i in range(1, n+1):
Iterate: 1, 2, 3, ..., 15


Step 3: Check conditions in order
if i % 3 == 0 and i % 5 == 0:
Check if multiple of both 3 and 5
If True → print 'FizzBuzz'


elif i % 3 == 0 and i % 5 != 0:
Check if multiple of 3 only
If True → print 'Fizz'


elif i % 5 == 0 and i % 3 != 0:
Check if multiple of 5 only
If True → print 'Buzz'


else:
Not multiple of 3 or 5
Print the number i
==================================================
🔢 EXAMPLE 1 (INPUT: 15)
==================================================
i=1: 1%3!=0, 1%5!=0 → print 1
i=2: 2%3!=0, 2%5!=0 → print 2
i=3: 3%3==0, 3%5!=0 → print Fizz
i=4: 4%3!=0, 4%5!=0 → print 4
i=5: 5%3!=0, 5%5==0 → print Buzz
i=6: 6%3==0, 6%5!=0 → print Fizz
i=7: 7%3!=0, 7%5!=0 → print 7
i=8: 8%3!=0, 8%5!=0 → print 8
i=9: 9%3==0, 9%5!=0 → print Fizz
i=10: 10%3!=0, 10%5==0 → print Buzz
i=11: 11%3!=0, 11%5!=0 → print 11
i=12: 12%3==0, 12%5!=0 → print Fizz
i=13: 13%3!=0, 13%5!=0 → print 13
i=14: 14%3!=0, 14%5!=0 → print 14
i=15: 15%3==0, 15%5==0 → print FizzBuzz








======Session 28:-MATRIX  PROGRAMS========================




MATRIX BASICS – ROWS, COLUMNS, AND NESTED LOOPS




1. What is a Matrix?
A matrix is a table-like structure that contains numbers arranged in rows and columns.




Example Matrix (3x3):




1 2 3
4 5 6
7 8 9




Rows = 3
Columns = 3




So the order of the matrix is:
3 x 3








2. Matrix Representation in Programming




A matrix is usually represented as a 2D array or a nested list.




Example:




[[1,2,3],
 [4,5,6],
 [7,8,9]]




This structure is also called an “array of arrays”.








3. Matrix Indexing




To access elements in a matrix we use:




a[row][column]




Example matrix:




1 2 3
4 5 6
7 8 9




Indexes:




(0,0) (0,1) (0,2)
(1,0) (1,1) (1,2)
(2,0) (2,1) (2,2)




Examples:




a[0][0] = 1
a[1][2] = 6
a[2][1] = 8








4. Using Nested Loops for Matrix Traversal




To go through all elements in a matrix we use two loops.




Outer loop → rows
Inner loop → columns








C Example:




int a[3][3];




for(i=0;i<3;i++)
{
    for(j=0;j<3;j++)
    {
        printf("%d ", a[i][j]);
    }
}








5. Example: Matrix of size 3x2




int a[3][2];




Rows = 3
Columns = 2




Indexes:




(0,0) (0,1)
(1,0) (1,1)
(2,0) (2,1)








6. 1D vs 2D Arrays




1D Array




int a[5];




Loop:




for(i=0;i<5;i++)








2D Array




int a[5][5];




Loop:




for(i=0;i<5;i++)
{
    for(j=0;j<5;j++)
}








7. Important Concept




Two important parameters in a matrix:




rows = n
columns = m




Matrix size = n x m




Examples:




3x3 → 3 rows, 3 columns
2x4 → 2 rows, 4 columns
1x1 → 1 row, 1 column








8. Python Example




Matrix using nested list:




matrix = [
    [1,2,3],
    [4,5,6],
    [7,8,9]
]




Print the matrix:




for row in matrix:
    for value in row:
        print(value, end=" ")
    print()




Output:




1 2 3
4 5 6
7 8 9








Access specific element:




print(matrix[1][2])




Output:
6








Create matrix using loops:




rows = 3
cols = 3




matrix = []




for i in range(rows):
    row = []
    for j in range(cols):
        value = int(input("Enter value: "))
        row.append(value)
    matrix.append(row)




print("Matrix:")




for r in matrix:
    print(r)








=========================================================
PYTHON STRING FUNCTIONS – QUICK REVISION NOTES
Strings in Python are sequences of characters.
Python provides many built-in functions to work with strings.
________________




1. split()
________________




split() divides a string into parts and returns a list.
Syntax
string.split(separator)
If separator is not given, space is used by default.
Example
"1 2 3".split()
Output
['1', '2', '3']
Example
"hi hello how are you".split()
Output
['hi', 'hello', 'how', 'are', 'you']
Example with separator
"a,b,c".split(",")
Output
['a', 'b', 'c']
Common Interview Example
L = [int(i) for i in input().split()]
Input
10 20 30
Output
[10, 20, 30]
split() always returns a LIST.
________________




2. join()
________________




join() joins elements of a list into a single string.
Syntax
separator.join(list)
Example
L = ['a', 'b', 'c']
print("-".join(L))
Output
a-b-c
Example
L = ['hello', 'world']
print(" ".join(L))
Output
hello world
________________




3. replace()
________________




replace() replaces one substring with another.
Syntax
string.replace(old,new)
Example
s = "hello world"
print(s.replace("world","python"))
Output
hello python
________________




4. strip()
________________




strip() removes spaces from beginning and end of string.
Example
s = " hello "
print(s.strip())
Output
hello
lstrip()
Removes spaces from left side.
Example
s = " hello"
print(s.lstrip())
Output
hello
rstrip()
Removes spaces from right side.
Example
s = "hello "
print(s.rstrip())
Output
hello
________________




5. find()
________________




find() returns index of first occurrence of substring.
Syntax
string.find(substring)
Example
s = "hello"
print(s.find("e"))
Output
1
If substring not found → returns -1
________________




6. count()
________________




count() counts number of occurrences of substring.
Example
s = "banana"
print(s.count("a"))
Output
3
________________




7. startswith()
________________




Checks if string starts with given substring.
Example
s = "python programming"
print(s.startswith("python"))
Output
True
________________




8. endswith()
________________




Checks if string ends with given substring.
Example
s = "python programming"
print(s.endswith("ming"))
Output
True
________________




9. upper() and lower()
________________




upper() → converts string to uppercase
Example
s = "hello"
print(s.upper())
Output
HELLO
lower() → converts string to lowercase
Example
s = "HELLO"
print(s.lower())
Output
hello
________________




10. swapcase()
________________




Converts uppercase to lowercase and lowercase to uppercase.
Example
s = "Manish"
print(s.swapcase())
Output
mANISH
________________




11. Difference Between find() and re.search()
________________




Both are used to search text inside a string, but they work differently.
1. find() method
________________




* It is a built-in string method.
* Searches for a substring inside a string.
* Returns the index position of the first match.
* If not found → returns -1.
* Does NOT support regular expressions.
Example
s = "hello world"
print(s.find("world"))
Output
6
Example when not found
s = "hello"
print(s.find("python"))
Output
-1
2. re.search()
________________




* It belongs to the "re" module (Regular Expression module).
* Used for advanced pattern searching.
* Supports regex patterns.
* Returns a match object if found.
* Returns None if not found.
Example
import re
s = "hello world"
print(re.search("world", s))
Output
<re.Match object>
Example with pattern
import re
s = "abc123"
print(re.search(r"\d+", s))
Output
123
Explanation
\d+ → finds one or more digits.
________________




Comparison Table
Feature find() re.search()
Module String method re module
Return Value Index number Match object
Not Found -1 None
Regex Support No Yes
Use Case Simple search Pattern search
Example Comparison
Using find()
s = "hello123"
print(s.find("123"))
Output
5
Using re.search()
import re
s = "hello123"
m = re.search(r"\d+", s)
print(m.group())
Output
123
________________




IMPORTANT POINTS
1. Strings are immutable (cannot be changed directly).
2. Most string functions return a new string.
3. split() returns list.
4. join() converts list to string.
5. strip() removes unwanted spaces.
6. find() is simple substring search.
7. re.search() is powerful pattern search using regex.
==================================
find() vs re.search() (Interview Short Comparison)
find()
* String method
* No module required
* Searches simple substring
* Returns index of match
* If not found → -1
Example
s = "hello123"
print(s.find("123"))
Output
5
re.search()
* Function from re module
* Used for regex pattern search
* Returns Match object
* If not found → None
Example 1
import re
s = "hello world"
print(re.search("world", s))
Output
<re.Match object>
Example 2
import re
s = "hello123"
m = re.search(r"\d+", s)
print(m.group())
Output
123
Key Difference
find() → simple substring search
re.search() → pattern search using regex
=======================




























==================================================================
—------------------------------------------------------------------------------------------------------------------
Intro:-How does input() work in Python for Matrix?




example




input
1 2 3
4 5 6
7 8 9




This pattern comes from the code, not from the problem statement.




Look at this line in the code:




a.append([int(i) for i in input().split()])








Explanation




input()        → takes one line of input
split()        → separates values based on space
int(i)         → converts each value to integer
list           → creates a list of numbers








Example




User enters:
1 2 3




input().split() → ['1','2','3']




After int conversion:
[1,2,3]




This becomes one row of the matrix.








Then the loop runs 3 times:




for i in range(3)




So it reads 3 rows:




1 2 3
4 5 6
7 8 9








And stores matrix as:




[
[1,2,3],
[4,5,6],
[7,8,9]
]








============================================================




Matrix Input Using append() – Complete Explanation








Code
----




# create empty list to store matrix
a=[]




# loop to read matrix rows
for i in range(3):




    # take space separated numbers from user
    # split() separates numbers
    # int(i) converts each value to integer
    a.append([int(i) for i in input().split()])








Step 1 – Create Empty List
--------------------------




a=[]




This creates an empty list.
This list will store the matrix.




Example




a = []








Step 2 – Loop Runs 3 Times
--------------------------




for i in range(3)




This loop runs 3 times because matrix is 3x3.




Iteration sequence




1st iteration
2nd iteration
3rd iteration




Each iteration reads one row.








Step 3 – input() Reads One Line
-------------------------------




input() always reads one full line from keyboard.




Example




User types




1 2 3




input() reads this complete line.








Step 4 – split() Separates Values
---------------------------------




input().split()




Example




Input line




1 2 3




After split()




['1','2','3']




It separates numbers using space.








Step 5 – Convert String to Integer
----------------------------------




[int(i) for i in input().split()]




This converts each string into integer.




Example




['1','2','3']
↓




[1,2,3]








Step 6 – append() Adds Row to Matrix
------------------------------------




append() adds this row into list a.




Example




First row added




a = [[1,2,3]]








Step 7 – Next Row Automatically
-------------------------------




After typing numbers user presses Enter.




Enter moves cursor to next line.




input() reads the next line in the next loop iteration.








Step-by-Step Execution
----------------------




Iteration 1




User input
1 2 3




Row stored
[1,2,3]




Matrix
a = [[1,2,3]]








Iteration 2




User input
4 5 6




Row stored
[4,5,6]




Matrix
a = [[1,2,3],[4,5,6]]








Iteration 3




User input
7 8 9




Row stored
[7,8,9]




Matrix
a = [[1,2,3],[4,5,6],[7,8,9]]








Final Matrix Stored
-------------------




a =
[
[1,2,3],
[4,5,6],
[7,8,9]
]








Key Points
----------




input()  → reads one line
split()  → separates values by space
int()    → converts string to integer
append() → adds row to matrix
for loop → repeats input for multiple rows




—------------------------------------------------------------------------------------------------------------------
PLB201:-READ AND WRITE MATRIX ELEMENTS




Write a program to read a matrix and display it on the console.




Input  : a 3 x 3 matrix
Constraints : No constraints
Output : Display the same 3 x 3 matrix








PYTHON IMPLEMENTATION (WITH COMMENTS)




# PLB201 - Read and Write Matrix Elements




# read number of rows
n = int(input())




# read number of columns
m = int(input())




# create an empty list to store the matrix
a = []




# read matrix row by row
for i in range(n):




    # input example: 1 2 3
    # split() converts it into ['1','2','3']
    # map(int, ...) converts each value to integer
    row = list(map(int, input().split()))




    # Why do we store data in 'row' first and then append to 'a'?
    #
    # 'row' represents ONE complete row of the matrix.
    # A matrix is basically a list of rows.
    #
    # Example matrix:
    #
    # 1 2 3
    # 4 5 6
    # 7 8 9
    #
    # row1 = [1,2,3]
    # row2 = [4,5,6]
    # row3 = [7,8,9]
    #
    # Then the matrix becomes:
    #
    # a = [
    #      [1,2,3],
    #      [4,5,6],
    #      [7,8,9]
    #     ]
    #
    # So we first create one row and then append that row into matrix 'a'.




    a.append(row)








# print matrix using nested loops
for i in range(n):          # loop for rows
    for j in range(m):      # loop for columns




        # print element at row i and column j
        print(a[i][j], end=' ')




    # move to next line after each row
    print()








EXAMPLE INPUT




3
3
1 2 3
4 5 6
7 8 9








EXAMPLE OUTPUT




1 2 3
4 5 6
7 8 9








INTERNAL MATRIX REPRESENTATION




After input the matrix is stored as:




a = [
 [1,2,3],
 [4,5,6],
 [7,8,9]
]








INDEXING CONCEPT




Matrix elements are accessed using:




a[i][j]




i = row index
j = column index




Examples:




a[0][0] = 1
a[0][1] = 2
a[1][2] = 6
a[2][1] = 8








LOOP LOGIC




Outer loop -> rows
Inner loop -> columns




for i in range(n):
    for j in range(m):
        print(a[i][j])








SUMMARY




1. Read rows and columns
2. Create empty list for matrix
3. Store each row in a temporary list 'row'
4. Append that row into matrix 'a'
5. Use nested loops to print the matrix
==================================================================
==================================================================
LBP202
sum of all matrix elements
Write a program to find sum of all elements in the matrix.
input --------> a 3x3 matrix
constraints --> no
output -------> sum of all elements
python implementation:#read number of rows
n=int(input())
#read number of columns
m=int(input())
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(n):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])
#initialize sum variable
s=0
#loop through rows
for i in range(n):
#loop through columns
for j in range(m):
    #add each matrix element to sum
    s=s+a[i][j]
#print final sum of matrix elements
print(s)
n=int(input()) #read number of rows
m=int(input())#read number of columns
a=[]#create empty list to store matrix




for i in range(n):#loop to read matrix rows
    a.append([int(i) for i in input().split()])
    # take space separated numbers from user
    # split() separates numbers
    # int(i) converts each value to integer
    s=0#initialize sum variable
for i in range(n):#loop through rows
   for j in range(m):#loop through columns
       s=s+a[i][j]#add each matrix element to sum




print(s)#print final sum of matrix elements




example
input
3
3
1 2 3
4 5 6
7 8 9
output
45




=======================================================
LBP203
sum of all even elements
Write a program to find sum of all even elements in the matrix.
input --------> a 3x3 matrix
constraints --> no
output -------> sum of all even elements
python implementation:
#read number of rows
n=int(input())
#read number of columns
m=int(input())
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(n):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])




#initialize sum variable
s=0
#loop through rows
for i in range(n):
#loop through columns
for j in range(m):




            #check if element is even
                   if a[i][j] % 2 == 0:




                #add even element to sum
                        s=s+a[i][j]




#print final sum of all even elements
print(s)
#read number of rows
n=int(input())
#read number of columns
m=int(input())
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(n):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
   a.append([int(i) for i in input().split()])




#initialize sum variable
s=0
#loop through rows
for i in range(n):
   #loop through columns
   for j in range(m):




       #check if element is even
       if a[i][j] % 2 == 0:




        #add even element to sum
            s=s+a[i][j]




#print final sum of all even elements
print(s)




example
input
3
3
1 2 3
4 5 6
7 8 9
output
20
===============================================================
LBP204
sum of all odd elements
Write a program to find sum of all odd elements in the matrix.
input --------> a 3x3 matrix
constraints --> no
output -------> sum of all odd elements
python implementation:
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])




#initialize sum variable
s=0
#loop through rows
for i in range(3):
#loop through columns
for j in range(3):




            #check if element is odd
                    if a[i][j] % 2 != 0:




        #add odd element to sum
                        s=s+a[i][j]




#print final sum of all odd elements
print(s)
example
input
1 2 3
4 5 6
7 8 9
output
25
==============================================================
LBP205
sum of all prime elements
Write a program to find sum of all prime elements in the matrix.
input --------> a 3x3 matrix
constraints --> no
output -------> sum of all prime elements
python implementation:
#function to check whether a number is prime
def isprime(n):
#prime numbers are greater than 1
if n <= 1:
    return False




#check divisibility from 2 to n-1
for i in range(2,n):




    #if divisible then not prime
    if n % i == 0:
        return False




#otherwise prime
return True




#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])




#initialize sum variable
s=0
#loop through rows
for i in range(3):
#loop through columns
for j in range(3):
            #check if element is prime
                   if isprime(a[i][j]):
#add prime element to sum
s=s+a[i][j]




#print final sum of all prime elements
print(s)
example
input
1 2 3
4 5 6
7 8 9
output
17
================================================================
LBP206
row wise sum in matrix
Write a program to find row wise sum in the matrix.
input --------> a 3x3 matrix
constraints --> no
output -------> sum of each row
python implementation:
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])




#loop through rows
for i in range(3):
#initialize sum variable for each row
s=0




#loop through columns
for j in range(3):
 #add each element of the row
                    s=s+a[i][j]




#print sum of current row
print(s)




example
input
1 2 3
4 5 6
7 8 9
output
6
15
24
======================================================
LBP207
column wise sum in matrix
Write a program to find column wise sum in the matrix.
input --------> a 3x3 matrix
constraints --> no
output -------> sum of each column
python implementation:
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])




#loop through columns
for i in range(3):
#initialize sum variable for each column
s=0




#loop through rows
for j in range(3):




            #add elements column wise
                    s=s+a[j][i]




#print sum of current column
print(s)




example
input
1 2 3
4 5 6
7 8 9
output
12
15
18
==================================================================
LBP208
sum of diagonal elements in matrix
Write a program to find sum of diagonal elements in matrix.
input --------> a 3x3 matrix
constraints --> no
output -------> sum of diagonal elements
python implementation:
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])




#initialize sum variable
s=0
#loop through rows
for i in range(3):
#loop through columns
for j in range(3):




                    #check for diagonal element (row index = column index)
                    if i==j:




        #add diagonal element to sum
        s=s+a[i][j]




#print final sum of diagonal elements
print(s)
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
   a.append([int(i) for i in input().split()])




#initialize sum variable
s=0
#loop through rows
for i in range(3):
#loop through columns
   for j in range(3):#check for diagonal element (row index = column index)
       if i==j:
               s = s + a[i][j]#add diagonal element to sum
#print final sum of diagonal elements
print(s)




example
input
1 2 3
4 5 6
7 8 9
output
15




==================================================================
LBP209
sum of opposite diagonal elements in matrix
Write a program to find sum of opposite diagonal elements in matrix.
input --------> a 3x3 matrix
constraints --> no
output -------> sum of opposite diagonal elements




Matrix Diagonal Concept (Important for Interview)
Example Matrix
1 2 3
4 5 6
7 8 9
________________




1. Main Diagonal (Left to Right)
________________




Main diagonal elements are where:
row index = column index
Formula
a[i][i]
Positions
(0,0) → 1
(1,1) → 5
(2,2) → 9
Main Diagonal Elements
1
5
9
Example Code
s=0
for i in range(3):
#add main diagonal elements
s=s+a[i][i]




print(s)
________________




2. Opposite Diagonal(Right to Left)
________________




Opposite diagonal elements are where:
column index = n - i - 1
Formula
a[i][n-i-1]
For 3x3 matrix:
n = 3
Positions
(0,2) → 3
(1,1) → 5
(2,0) → 7
Opposite Diagonal Elements
3
5
7
Example Code
s=0
for i in range(3):
#add opposite diagonal elements
s=s+a[i][3-i-1]




print(s)
________________




Visual Diagram
Matrix
1 2 3
4 5 6
7 8 9
Main Diagonal
1 x x
x 5 x
x x 9
Opposite Diagonal
x x 3
x 5 x
7 x x
________________




Important Formulas
Main Diagonal
a[i][i]
Opposite Diagonal
a[i][n-i-1]
________________




Interview Tip
If interviewer asks:
"How do you access diagonals in a matrix?"
Answer:
Main diagonal → a[i][i]
Opposite diagonal → a[i][n-i-1]




python implementation:
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])




#initialize sum variable
s=0
#loop through rows
for i in range(3):
#add opposite diagonal element
#formula → a[i][n-i-1]
#here n = 3
s=s+a[i][3-i-1]




#print final sum of opposite diagonal elements
print(s)
example
input
1 2 3
4 5 6
7 8 9
output
15
LBP – Sum of both diagonals in matrix
python implementation:
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])




#initialize sum variable
s=0
#loop through rows
for i in range(3):
#add main diagonal element
s=s+a[i][i]




#add opposite diagonal element
s=s+a[i][3-i-1]




#print sum of both diagonals
print(s)
#LBP – Sum of both diagonals in matrix




#create empty list to store matrix
a=[]




#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
   a.append([int(i) for i in input().split()])








#initialize sum variable
s=0




#loop through rows
for i in range(3):




   s=s+a[i][i]#add main diagonal element
   s=s+a[i][3-i-1]#add opposite diagonal element








#print sum of both diagonals
print(s)








example
input
1 2 3
4 5 6
7 8 9
main diagonal = 1 + 5 + 9 = 15
opposite diagonal = 3 + 5 + 7 = 15
total = 30
output
30
==================================================================
LBP210
sum of first and last element in the matrix
Write a program to find sum of first and last element in a matrix.
input --------> a 3x3 matrix
constraints --> no
output -------> sum of first and last element in matrix
python implementation:
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])




#print sum of first and last element in matrix
print(a[0][0] + a[2][2])
example
input
1 2 3
4 5 6
7 8 9
first element = 1
last element = 9
sum = 10
output
10
==================================================================LBP211
find the product of diagonal matrix
Write a program to find the product of diagonal matrix.
input --------> a 3x3 matrix
constraints --> no
output -------> find the product of diagonal matrix
python implementation:
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])




#initialize product variable
s=1
#loop through rows
for i in range(3):
#loop through columns
for j in range(3):




            #check for main diagonal element
            if i==j:




                #multiply diagonal elements
                s=s*a[i][j]




#print final product of diagonal elements
print(s)
example
input
1 2 3
4 5 6
7 8 9
main diagonal elements
1
5
9
product = 1 × 5 × 9 = 45
output
45
==================================================================
LBP212
find the product of opposite diagonal matrix
Write a program to find the product of opposite diagonal matrix.
input --------> a 3x3 matrix
constraints --> no
output -------> find the product of opposite diagonal matrix
python implementation:
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])




#initialize product variable
s=1
#loop through rows
for i in range(3):
#multiply opposite diagonal elements
#formula → a[i][n-i-1]
#here n = 3
s=s*a[i][3-i-1]




#print final product of opposite diagonal elements
print(s)
example
input
1 2 3
4 5 6
7 8 9
opposite diagonal elements
3
5
7
product = 3 × 5 × 7 = 105
output
105


=====================================================
LBP213
max element in matrix
Implement a program to print max element in an matrix
input -------> a 3x3 matrix
constraint-> no
output -----> max element in matrix
python implementation:
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])


#initialize max with first element of matrix
max=a[0][0]
#loop through rows
for i in range(3):
#loop through columns
for j in range(3):


            #check if current element is greater than max
            if max < a[i][j]:


                #update max value
                max=a[i][j]


#print maximum element in matrix
print(max)
example
input
1 2 -10
5 6 -7
8 1 -20
output
8
===============================================================
LBP214
min element in matrix
Implement a program to print min element in an matrix
input -------> a 3x3 matrix
constraint-> no
output -----> min element in matrix
python implementation:
#create empty list to store matrix
a=[]
#loop to read matrix rows
for i in range(3):
#take space separated numbers from user
#split() separates numbers
#int(i) converts each value to integer
a.append([int(i) for i in input().split()])


#initialize min with first element of matrix
        min=a[0][0]
#loop through rows
for i in range(3):
#loop through columns
for j in range(3):


    #check if current element is smaller than min
                    if min > a[i][j]:


        #update min value
                        min=a[i][j]


#print minimum element in matrix
print(min)
example
input
1 2 -10
5 6 -7
8 1 -20
output
-20
========================================================================
PLB215


MAX ELEMENT IN EACH ROW OF A MATRIX


Problem Statement:
Implement a program to print max element in each row of a matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
Print max element in each row of a matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# create empty list to store matrix
a = []


# loop to take input for 3 rows
for i in range(3):
    # take input and convert into integer list
    row = [int(x) for x in input().split()]
    a.append(row)   # append row to matrix


# loop through each row
for i in range(3):


    # assume first element of row is max
    max_val = a[i][0]


    # check all elements in that row
    for j in range(3):
        if a[i][j] > max_val:
            max_val = a[i][j]   # update max


    # print max of current row
    print(max_val)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
3
6
9




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
If print(max_val) is written outside the loop,
then only last row max will be printed.


Correct approach:
print inside the row loop.




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
For each row:
- take first element as max
- compare with all elements
- update max
- print max
--------------------------------------------------
========================================================================
PLB216


MIN ELEMENT IN EACH ROW OF A MATRIX


Problem Statement:
Implement a program to print min element in each row of a matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
Print min element in each row of a matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# create empty list to store matrix
a = []


# loop to take input for 3 rows
for i in range(3):
    # take input and convert into integer list
    row = [int(x) for x in input().split()]
    a.append(row)   # append row to matrix


# loop through each row
for i in range(3):


    # assume first element of row is minimum
    min_val = a[i][0]


    # check all elements in that row
    for j in range(3):
        if a[i][j] < min_val:
            min_val = a[i][j]   # update minimum


    # print minimum of current row
    print(min_val)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
1
4
7




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
If print(min_val) is written outside the loop,
then only last row minimum will be printed.


Correct approach:
print inside the row loop.




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
For each row:
- take first element as min
- compare with all elements
- update min
- print min






--------------------------------------------------
================================================================
PLB217


TRANSPOSE OF THE GIVEN MATRIX


Problem Statement:
Implement a program to print transpose of a matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
Print transpose of the matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# create empty list to store matrix
a = []


# loop to take input for 3 rows
for i in range(3):
    # take input and convert into integer list
    row = [int(x) for x in input().split()]
    a.append(row)   # append row to matrix


# print transpose of matrix
for i in range(3):          # column loop
    for j in range(3):      # row loop
        print(a[j][i], end=' ')   # swap i and j
    print()   # move to next line




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
1 4 7
2 5 8
3 6 9




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
If you print a[i][j], original matrix will print.


For transpose:
use a[j][i] (row and column swap)




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
- Swap rows with columns
- Access element as a[j][i]
- Print in matrix format




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
=================================================================
PLB218


TRACE OF THE GIVEN MATRIX


Problem Statement:
Implement a program to find trace (sum of diagonal elements) of the given matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
Print trace of the matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# create empty list to store matrix
a = []


# loop to take input for 3 rows
for i in range(3):
    # take input and convert into integer list
    row = [int(x) for x in input().split()]
    a.append(row)   # append row to matrix


# initialize sum variable
s = 0


# loop through matrix
for i in range(3):
    for j in range(3):
        if i == j:              # diagonal condition
            s = s + a[i][j]    # add diagonal element


# print trace (sum of diagonal)
print(s)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
15




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
Diagonal elements are where i == j


Positions:
(0,0), (1,1), (2,2)


If condition is wrong, sum will be incorrect.




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
- Initialize sum = 0
- Traverse matrix
- If i == j → add element
- Print sum




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
PLB219


FIND THE FREQUENCY OF ODD AND EVEN


Problem Statement:
Write a program to find frequency of odd and even elements in the matrix excluding 0


Input:
a 3x3 matrix


Constraint:
No


Output:
Odd elements count and even elements count




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# create empty list to store matrix
a = []


# loop to take input for 3 rows
for i in range(3):
    # take input and convert into integer list
    row = [int(x) for x in input().split()]
    a.append(row)   # append row to matrix


# initialize counters
odd = 0
even = 0


# traverse matrix
for i in range(3):
    for j in range(3):


        # skip zero
        if a[i][j] == 0:
            continue


        # check even
        if a[i][j] % 2 == 0:
            even = even + 1
        else:
            odd = odd + 1


# print results
print(odd)
print(even)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 0
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
5
3




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
Zero should not be counted in even numbers.


Use:
if a[i][j] == 0:
    continue




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
- Initialize odd and even counters
- Traverse matrix
- Skip zero
- If %2==0 → even++
- Else → odd++
- Print both




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================
PLB220


IDENTITY MATRIX


Definition:
An identity matrix is a square matrix in which:
- All diagonal elements are 1
- All non-diagonal elements are 0


Example:
1 0 0
0 1 0
0 0 1




Problem Statement:
Implement a program to check whether the given matrix is identity matrix or not


Input:
a 3x3 matrix


Constraint:
No


Output:
Yes or No




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# assume matrix is identity
flag = True


# create empty list to store matrix
a = []


# loop to take input for 3 rows
for i in range(3):
    # take input and convert into integer list
    row = [int(x) for x in input().split()]
    a.append(row)   # append row to matrix


# check identity matrix condition
for i in range(3):
    for j in range(3):


        # diagonal elements should be 1
        if i == j and a[i][j] != 1:
            flag = False
            break


        # non-diagonal elements should be 0
        if i != j and a[i][j] != 0:
            flag = False
            break


# print result
if flag:
    print("Yes")
else:
    print("No")




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 0 0
0 1 0
0 0 1




--------------------------------------------------
OUTPUT
--------------------------------------------------
Yes




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
Diagonal elements → must be 1  
Non-diagonal elements → must be 0  


If any condition fails → not identity matrix




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
- Assume flag = True
- Traverse matrix
- If i==j → check element == 1
- If i!=j → check element == 0
- If any condition fails → flag=False
- Print Yes/No




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB221


TWO MATRICES ARE EQUAL OR NOT


Definition:
Two matrices are equal if:
- They have same dimensions
- All corresponding elements are equal


Example:
Matrix A = Matrix B → Equal  
If any element differs → Not Equal




Problem Statement:
Implement a program to check whether the given matrices are equal or not


Input:
two 3x3 matrices


Constraint:
No


Output:
Yes or No




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# assume matrices are equal
flag = True


# create empty lists for matrices
a = []
b = []


# input first matrix
for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# input second matrix
for i in range(3):
    row = [int(x) for x in input().split()]
    b.append(row)


# compare matrices
for i in range(3):
    for j in range(3):


        # if any element is not equal
        if a[i][j] != b[i][j]:
            flag = False
            break


# print result
if flag:
    print("Yes")
else:
    print("No")




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9


1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
Yes




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
Even one mismatch → matrices are not equal


No need to check further once mismatch found




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
- Assume flag = True
- Compare each element of both matrices
- If mismatch → flag = False
- Print Yes/No




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB222


ADDITION OF TWO MATRICES


Definition:
Matrix addition is the process of adding corresponding elements of two matrices.


Condition:
Both matrices must have same dimensions.


Example:
A + B = C  
c[i][j] = a[i][j] + b[i][j]




Problem Statement:
Write a program to perform addition operation on two matrices


Input:
two 3x3 matrices


Constraint:
No


Output:
Resultant matrix




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
- Input both matrices
- Traverse using loops
- Add corresponding elements
- Store in new matrix
- Print result




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# create empty lists for matrices
a = []
b = []
c = []


# input first matrix
for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# input second matrix
for i in range(3):
    row = [int(x) for x in input().split()]
    b.append(row)


# perform addition
for i in range(3):
    temp = []   # store one row result


    for j in range(3):
        temp.append(a[i][j] + b[i][j])   # add elements


    c.append(temp)   # add row to result matrix


# print result matrix
for i in range(3):
    for j in range(3):
        print(c[i][j], end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9


1 1 1
1 1 1
1 1 1




--------------------------------------------------
OUTPUT
--------------------------------------------------
2 3 4
5 6 7
8 9 10




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
Both matrices must be of same size


Always add corresponding elements:
a[i][j] + b[i][j]




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
======================================================================PLB224


MULTIPLICATION OF TWO MATRICES


Definition:
Matrix multiplication is performed by multiplying rows of first matrix with columns of second matrix.


Formula:
c[i][j] = sum of (a[i][k] * b[k][j])


Condition:
Number of columns in first matrix = number of rows in second matrix




Problem Statement:
Write a program to perform multiplication operation on two matrices


Input:
two 3x3 matrices


Constraint:
No


Output:
Resultant matrix




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
- Input both matrices
- Initialize result matrix with 0
- Use three loops:
    i → row of first matrix
    j → column of second matrix
    k → multiplication index
- Multiply and add:
    c[i][j] += a[i][k] * b[k][j]
- Print result matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# create empty lists for matrices
a = []
b = []


# initialize result matrix with zeros
c = [[0,0,0],[0,0,0],[0,0,0]]


# input first matrix
for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# input second matrix
for i in range(3):
    row = [int(x) for x in input().split()]
    b.append(row)


# perform multiplication
for i in range(3):
    for j in range(3):
        for k in range(3):
            c[i][j] = c[i][j] + (a[i][k] * b[k][j])


# print result matrix
for i in range(3):
    for j in range(3):
        print(c[i][j], end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9


1 0 0
0 1 0
0 0 1




--------------------------------------------------
OUTPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
Do not use a[i][j] * b[i][j] ❌  
Correct formula:
a[i][k] * b[k][j] ✅


Also initialize result matrix with 0




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================
PLB225


SORT ALL THE ELEMENTS IN A MATRIX IN ASC ORDER


Definition:
Sorting a matrix means arranging all elements in ascending order.


Approach:
Convert matrix into a single list → sort → put back into matrix




Problem Statement:
Implement a program to sort all the elements in ascending order in the matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
Resultant sorted matrix




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
- Input matrix
- Convert matrix into 1D list
- Sort the list
- Put elements back into matrix
- Print sorted matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix rows
l1 = [int(x) for x in input().split()]
l2 = [int(x) for x in input().split()]
l3 = [int(x) for x in input().split()]


# create matrix
l = [l1, l2, l3]


# empty list to store all elements
temp = []


# convert matrix into 1D list
for i in range(3):
    for j in range(3):
        temp.append(l[i][j])


# sort list
temp.sort()


# put back sorted elements into matrix
k = 0
for i in range(3):
    for j in range(3):
        l[i][j] = temp[k]
        k = k + 1


# print sorted matrix
for i in range(3):
    for j in range(3):
        print(l[i][j], end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
9 3 1
6 5 2
8 7 4




--------------------------------------------------
OUTPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
Matrix cannot be directly sorted


First convert into list → sort → rebuild matrix




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB226


SORT ALL THE ELEMENTS IN A MATRIX IN DESC ORDER


Definition:
Sorting in descending order means arranging elements from largest to smallest.


Approach:
Convert matrix into a single list → sort in reverse → put back into matrix




Problem Statement:
Implement a program to sort all the elements in descending order in the matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
Resultant sorted matrix




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
- Input matrix
- Convert matrix into 1D list
- Sort the list in descending order
- Put elements back into matrix
- Print sorted matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix rows
l1 = [int(x) for x in input().split()]
l2 = [int(x) for x in input().split()]
l3 = [int(x) for x in input().split()]


# create matrix
l = [l1, l2, l3]


# empty list to store all elements
temp = []


# convert matrix into 1D list
for i in range(3):
    for j in range(3):
        temp.append(l[i][j])


# sort list in descending order
temp.sort(reverse=True)


# put back sorted elements into matrix
k = 0
for i in range(3):
    for j in range(3):
        l[i][j] = temp[k]
        k = k + 1


# print sorted matrix
for i in range(3):
    for j in range(3):
        print(l[i][j], end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
9 8 7
6 5 4
3 2 1




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
Use:
sort(reverse=True)


Without reverse → ascending order only




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB227


SORT ALL THE ELEMENTS IN A ROW IN ASC ORDER


Definition:
Sorting means arranging elements in a specific order.


Types of Sorting:
1. Ascending Order → smallest to largest (1,2,3,...)
2. Descending Order → largest to smallest (9,8,7,...)


Sorting Algorithms:


- Bubble Sort --> Repeatedly swap adjacent elements if they are in wrong order  
  Example: [5,2,4] → [2,5,4] → [2,4,5]  
  Use: Simple logic, small datasets


- Selection Sort --> Select minimum element and place it at correct position  
  Example: [5,2,4] → [2,5,4] → [2,4,5]  
  Use: When number of swaps needs to be minimized


- Insertion Sort --> Insert each element into its correct position in sorted part  
  Example: [5,2,4] → [2,5,4] → [2,4,5]  
  Use: Efficient for small or nearly sorted data


- Merge Sort --> Divide array into halves, sort and merge them  
  Example: [5,2,4] → [5] [2,4] → [2,4] → [2,4,5]  
  Use: Stable and efficient for large datasets


- Quick Sort --> Pick pivot, partition elements, and recursively sort  
  Example: [5,2,4] → pivot=5 → [2,4] [5] → [2,4,5]  
  Use: Fast in practice for large datasets




In this program:
We are using Python's inbuilt sort() function.


Note:
Python sort() uses Timsort algorithm 
(which is a combination of Merge Sort and Insertion Sort)


We are using Ascending Order sorting on each row.




Problem Statement:
Implement a program to sort all the row-wise elements in ascending order


Input:
a 3x3 matrix


Constraint:
No


Output:
Result matrix




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
- Input matrix
- Traverse each row
- Apply sort() on each row
- Print matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix rows
l1 = [int(x) for x in input().split()]
l2 = [int(x) for x in input().split()]
l3 = [int(x) for x in input().split()]


# create matrix
l = [l1, l2, l3]


# sort each row
for i in range(3):
    l[i].sort()   # uses Timsort internally


# print matrix
for i in range(3):
    for j in range(3):
        print(l[i][j], end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
9 3 1
6 5 2
8 7 4




--------------------------------------------------
OUTPUT
--------------------------------------------------
1 3 9
2 5 6
4 7 8




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
Sorting is done row-wise, not entire matrix


Use:
l[i].sort()




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB228


SORT ALL THE ELEMENTS IN A ROW IN DESC ORDER


Definition:
Sorting means arranging elements in a specific order.


Types of Sorting:
1. Ascending Order → smallest to largest (1,2,3,...)
2. Descending Order → largest to smallest (9,8,7,...)


In this program:
We are using Python's inbuilt sort() function


Note:
Python sort() uses Timsort algorithm  
(Combination of Merge Sort and Insertion Sort)


We are using Descending Order sorting on each row




Problem Statement:
Implement a program to sort all the row-wise elements in descending order


Input:
a 3x3 matrix


Constraint:
No


Output:
Result matrix




--------------------------------------------------
LOGIC (SHORT)
--------------------------------------------------
- Input matrix
- Traverse each row
- Apply sort(reverse=True) on each row
- Print matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix rows
l1 = [int(x) for x in input().split()]
l2 = [int(x) for x in input().split()]
l3 = [int(x) for x in input().split()]


# create matrix
l = [l1, l2, l3]


# sort each row in descending order
for i in range(3):
    l[i].sort(reverse=True)   # uses Timsort internally


# print matrix
for i in range(3):
    for j in range(3):
        print(l[i][j], end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
3 2 1
6 5 4
9 8 7




--------------------------------------------------
IMPORTANT NOTE (COMMON MISTAKE)
--------------------------------------------------
Use:
sort(reverse=True)


Without reverse → ascending order only




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================
PLB229


SORT ALL THE ELEMENTS IN A COLUMN IN ASC ORDER


Definition:
Column-wise sorting means sorting each column separately in ascending order.


Example samajh:


Input matrix:
1 3 2
7 6 9
4 8 5


Column wise dekho:


Column 1 → [1,7,4] → sort → [1,4,7]  
Column 2 → [3,6,8] → already sorted  
Column 3 → [2,9,5] → sort → [2,5,9]


Final matrix:
1 3 2
4 6 5
7 8 9




Problem Statement:
Implement a program to sort all the column values in ascending order


Input:
a 3x3 matrix


Constraint:
No


Output:
Result matrix




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


Method 1 (Easy - Direct Column Approach):


- Input matrix
- For each column:
    - Store column elements in a list
    - Sort that list
    - Put sorted values back into matrix
- Print matrix




--------------------------------------------------
PYTHON IMPLEMENTATION (EASY METHOD)
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# column-wise sorting
for j in range(3):   # column loop


    temp = []


    # take column elements
    for i in range(3):
        temp.append(a[i][j])


    # sort column
    temp.sort()


    # put back into matrix
    for i in range(3):
        a[i][j] = temp[i]


# print result
for i in range(3):
    for j in range(3):
        print(a[i][j], end=' ')
    print()




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Row-wise → l[i].sort()


Column-wise → manually extract column OR use transpose trick




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB230


SORT ALL THE ELEMENTS IN A COLUMN IN DESC ORDER


Definition:
Column-wise sorting means sorting each column separately.


Here we sort in descending order (largest to smallest).




Problem Statement:
Implement a program to sort all the column values in descending order


Input:
a 3x3 matrix


Constraint:
No


Output:
Result matrix




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- For each column:
    - Store column elements in a list
    - Sort the list in descending order
    - Put sorted values back into matrix
- Print matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# column-wise sorting in descending order
for j in range(3):   # column loop


    temp = []


    # take column elements
    for i in range(3):
        temp.append(a[i][j])


    # sort in descending order
    temp.sort(reverse=True)


    # put back into matrix
    for i in range(3):
        a[i][j] = temp[i]


# print result
for i in range(3):
    for j in range(3):
        print(a[i][j], end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 3 2
7 6 9
4 8 5




--------------------------------------------------
OUTPUT
--------------------------------------------------
7 8 9
4 6 5
1 3 2




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Column-wise sorting cannot be done directly


Use:
- temp list approach (easy) OR
- transpose trick




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB231


SPARSE MATRIX


Definition:
A sparse matrix is a matrix in which most of the elements are 0.


Condition:
Number of zero elements > number of non-zero elements




Problem Statement:
Implement a program to check whether the given matrix is sparse matrix or not


Input:
a 3x3 matrix


Constraint:
No


Output:
Yes or No




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Count number of zero elements
- Count number of non-zero elements
- If zero > non-zero → print Yes
- Else → print No




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# initialize counters
zero = 0
non_zero = 0


# count elements
for i in range(3):
    for j in range(3):
        if a[i][j] == 0:
            zero = zero + 1
        else:
            non_zero = non_zero + 1


# check sparse condition
if zero > non_zero:
    print("Yes")
else:
    print("No")




--------------------------------------------------
ALTERNATE SHORT METHOD
--------------------------------------------------


# using count()
count = 0


for row in a:
    count = count + row.count(0)


print("Yes" if count > 4 else "No")




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
No




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 0 0
0 1 0
0 0 1




--------------------------------------------------
OUTPUT
--------------------------------------------------
Yes




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Total elements in 3x3 = 9


Sparse condition:
zeros > 9/2 → zeros > 4




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB232


SWAPPING OF TWO ROWS


Definition:
Row swapping means exchanging two rows of a matrix.




Problem Statement:
Implement a program to swap two given rows


Input:
matrix and m and n values


Constraint:
No


Output:
Modified matrix




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Input row numbers m and n
- Convert to index:
    m-1 and n-1 (because index starts from 0)
- Swap rows:
    a[m-1] ↔ a[n-1]
- Print matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# input row numbers
m = int(input())
n = int(input())


# swap rows (convert to 0-based index)
a[m-1], a[n-1] = a[n-1], a[m-1]


# print matrix
for i in range(3):
    for j in range(3):
        print(a[i][j], end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
11 22 33
44 55 66
77 88 99
1
2




--------------------------------------------------
OUTPUT
--------------------------------------------------
44 55 66
11 22 33
77 88 99




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
User gives row numbers starting from 1


But Python uses index starting from 0


So always use:
m-1 and n-1




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB233


SWAPPING OF TWO COLUMNS


Definition:
Column swapping means exchanging two columns of a matrix.




Problem Statement:
Implement a program to swap two given columns


Input:
matrix and m and n values


Constraint:
No


Output:
Modified matrix




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Input column numbers m and n
- Convert to index:
    m-1 and n-1 (because index starts from 0)
- For each row:
    swap elements of column m and n
- Print matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# input column numbers
m = int(input())
n = int(input())


# swap columns
for i in range(3):
    a[i][m-1], a[i][n-1] = a[i][n-1], a[i][m-1]


# print matrix
for i in range(3):
    for j in range(3):
        print(a[i][j], end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
11 22 33
44 55 66
77 88 99
1
2




--------------------------------------------------
OUTPUT
--------------------------------------------------
22 11 33
55 44 66
88 77 99




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
User gives column numbers starting from 1


But Python uses index starting from 0


So always use:
m-1 and n-1




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------


========================================================================PLB234


INTERCHANGE THE DIAGONALS


Definition:
A matrix has two diagonals:
1. Main diagonal → a[i][i]
2. Opposite diagonal → a[i][n-i-1]


Interchanging diagonals means swapping elements of these two diagonals.




Problem Statement:
Program to accept a matrix of order 3x3 and interchange the diagonals


Input:
a 3x3 matrix


Constraint:
No


Output:
Modified matrix




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- For each row i:
    - Swap:
      a[i][i] ↔ a[i][n-i-1]
- Print matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# interchange diagonals
for i in range(3):
    a[i][i], a[i][3-i-1] = a[i][3-i-1], a[i][i]


# print matrix
for i in range(3):
    for j in range(3):
        print(a[i][j], end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
STEP UNDERSTANDING
--------------------------------------------------
Main diagonal → 1, 5, 9  
Opp diagonal  → 3, 5, 7  


Swap:
1 ↔ 3  
5 ↔ 5  
9 ↔ 7




--------------------------------------------------
OUTPUT
--------------------------------------------------
3 2 1
4 5 6
9 8 7




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Formula:
Main diagonal → a[i][i]  
Opp diagonal  → a[i][n-i-1]


For 3x3:
a[i][3-i-1]




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================
PLB235


UPPER TRIANGULAR MATRIX


Definition:
An upper triangular matrix is a matrix in which all elements below the main diagonal are 0.


Condition:
If i > j → a[i][j] must be 0




Problem Statement:
Program to accept a matrix and check whether it is upper triangular matrix or not


Input:
a 3x3 matrix


Constraint:
No


Output:
Yes or No




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix positions (i,j):


(0,0) (0,1) (0,2)
(1,0) (1,1) (1,2)
(2,0) (2,1) (2,2)


Main diagonal:
(0,0), (1,1), (2,2)


Below diagonal (IMPORTANT PART):
(1,0), (2,0), (2,1)  → these must be 0


Example:


1  2  3
0  5  6
0  0  9


Here:
✔ below diagonal = all 0 → YES




Condition to check:
i > j → element must be 0




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Assume flag = True
- Traverse matrix:
    - If i > j and element ≠ 0 → flag = False
- Print Yes/No




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# assume matrix is upper triangular
flag = True


# check condition
for i in range(3):
    for j in range(3):
        if i > j and a[i][j] != 0:
            flag = False


# print result
print("Yes" if flag else "No")




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
0 5 6
0 0 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
Yes




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Only check BELOW diagonal


Condition:
i > j → must be 0




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB237


SCALAR MATRIX MULTIPLICATION


Definition:
Scalar multiplication means multiplying every element of the matrix by a constant number.




Problem Statement:
Implement a program to read a matrix and multiplier and return scalar matrix multiplication


Input:
a 3x3 matrix and multiplier


Constraint:
No


Output:
Resultant matrix




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix:
1 2 3
4 5 6
7 8 9


Scalar (k) = 2


Multiply each element:


1×2  2×2  3×2
4×2  5×2  6×2
7×2  8×2  9×2


Result:
2  4  6
8 10 12
14 16 18




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Input scalar value k
- Traverse matrix:
    - Multiply each element by k
- Print result matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# input scalar
k = int(input())


# multiply matrix with scalar
for i in range(3):
    for j in range(3):
        print(a[i][j] * k, end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9
2




--------------------------------------------------
OUTPUT
--------------------------------------------------
2 4 6
8 10 12
14 16 18




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Each element is multiplied individually


Formula:
a[i][j] * k




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------








========================================================================PLB238


SYMMETRIC MATRIX


Definition:
A matrix is symmetric if it is equal to its transpose.


Condition:
a[i][j] == a[j][i]




Problem Statement:
Implement a program to read a matrix and check whether the given matrix is symmetric matrix or not


Input:
a 3x3 matrix


Constraint:
No


Output:
Yes or No




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix positions:


(0,0) (0,1) (0,2)
(1,0) (1,1) (1,2)
(2,0) (2,1) (2,2)


Check symmetry:


a[0][1] == a[1][0]
a[0][2] == a[2][0]
a[1][2] == a[2][1]


Example:


1 2 3
2 5 6
3 6 9


✔ symmetric (mirror across diagonal)




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Assume flag = True
- Traverse matrix:
    - If a[i][j] != a[j][i] → flag = False
- Print Yes/No




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# assume symmetric
flag = True


# check condition
for i in range(3):
    for j in range(3):
        if a[i][j] != a[j][i]:
            flag = False


# print result
print("Yes" if flag else "No")




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
2 5 6
3 6 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
Yes




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
No




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Matrix must be equal to its transpose


Condition:
a[i][j] == a[j][i]




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB239


PRINT DIAGONAL ELEMENTS


Definition:
Diagonal elements are elements where row index = column index.


Condition:
i == j → diagonal element




Problem Statement:
Implement a program to read a matrix and display only diagonal elements


Input:
a 3x3 matrix


Constraint:
No


Output:
Print only diagonal elements




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix positions:


(0,0) (0,1) (0,2)
(1,0) (1,1) (1,2)
(2,0) (2,1) (2,2)


Diagonal positions:
(0,0), (1,1), (2,2)


Example:


1 2 3
4 5 6
7 8 9


Diagonal elements:
1   5   9




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Traverse matrix
- If i == j → print element
- Else → print space




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# print diagonal elements
for i in range(3):
    for j in range(3):
        if i == j:
            print(a[i][j], end=' ')
        else:
            print(" ", end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
1      
   5   
      9




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Condition:
i == j → main diagonal




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB240


SQUARE OF EACH ELEMENT OF MATRIX


Definition:
Square of a number means multiplying the number by itself.


Formula:
x² = x * x




Problem Statement:
Implement a program to find square of each element present in a matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
Resultant matrix




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix:
1 2 3
4 5 6
7 8 9


Square each element:


1×1  2×2  3×3
4×4  5×5  6×6
7×7  8×8  9×9


Result:
1   4   9
16 25  36
49 64  81




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Traverse matrix
- Square each element (a[i][j] * a[i][j])
- Print result matrix




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# print square of each element
for i in range(3):
    for j in range(3):
        print(a[i][j] * a[i][j], end=' ')
    print()




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
1 4 9
16 25 36
49 64 81




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Formula:
a[i][j] * a[i][j]




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB241


SUM OF EVEN INDEXED ROWS IN MATRIX


Definition:
Even indexed rows means rows whose index is even (0, 2, 4, ...)


Note:
Index starts from 0




Problem Statement:
Implement a program to find sum of even indexed rows in the given matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
sum as an integer




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix with index:


0 → 1 2 3   ✔ (even index)
1 → 4 5 6   ✘ (odd index)
2 → 7 8 9   ✔ (even index)


Take only row 0 and row 2:


Row 0 → 1 + 2 + 3 = 6  
Row 2 → 7 + 8 + 9 = 24  


Total sum = 6 + 24 = 30




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Initialize sum = 0
- Traverse rows:
    - If row index i % 2 == 0:
        - Add all elements of that row
- Print sum




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# initialize sum
s = 0


# calculate sum of even indexed rows
for i in range(3):
    if i % 2 == 0:   # even index row
        for j in range(3):
            s = s + a[i][j]


# print result
print(s)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
30




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Even index condition:
i % 2 == 0




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB242


SUM OF ODD INDEXED ROWS IN MATRIX


Definition:
Odd indexed rows means rows whose index is odd (1, 3, 5, ...)


Note:
Index starts from 0




Problem Statement:
Implement a program to find sum of odd indexed rows in the given matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
sum as an integer




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix with index:


0 → 1 2 3   ✘ (even index)
1 → 4 5 6   ✔ (odd index)
2 → 7 8 9   ✘ (even index)


Take only row 1:


Row 1 → 4 + 5 + 6 = 15  


Total sum = 15




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Initialize sum = 0
- Traverse rows:
    - If row index i % 2 != 0:
        - Add all elements of that row
- Print sum




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# initialize sum
s = 0


# calculate sum of odd indexed rows
for i in range(3):
    if i % 2 != 0:   # odd index row
        for j in range(3):
            s = s + a[i][j]


# print result
print(s)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
15




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Odd index condition:
i % 2 != 0




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB243


SUM OF EVEN INDEXED COLUMNS IN MATRIX


Definition:
Even indexed columns means columns whose index is even (0, 2, 4, ...)


Note:
Index starts from 0




Problem Statement:
Implement a program to find sum of even indexed columns in the given matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
sum as an integer




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix with column index:


               0    1   2
                 ↓    ↓   ↓
1 2 3 → ✔ ✘ ✔
4 5 6 → ✔ ✘ ✔
7 8 9 → ✔ ✘ ✔


Take only column 0 and column 2:


Column 0 → 1 + 4 + 7 = 12  
Column 2 → 3 + 6 + 9 = 18  


Total sum = 12 + 18 = 30




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Initialize sum = 0
- Traverse matrix:
    - If column index j % 2 == 0:
        - Add element
- Print sum




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# initialize sum
s = 0


# calculate sum of even indexed columns
for i in range(3):
    for j in range(3):
        if j % 2 == 0:   # even column index
            s = s + a[i][j]


# print result
print(s)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
30




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Even column condition:
j % 2 == 0




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================
PLB244


SUM OF ODD INDEXED COLUMNS IN MATRIX


Definition:
Odd indexed columns means columns whose index is odd (1, 3, 5, ...)


Note:
Index starts from 0




Problem Statement:
Implement a program to find sum of odd indexed columns in the given matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
sum as an integer




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix with column index:


              0  1   2
              ↓   ↓   ↓
1 2 3 → ✘ ✔ ✘
4 5 6 → ✘ ✔ ✘
7 8 9 → ✘ ✔ ✘


Take only column 1:


Column 1 → 2 + 5 + 8 = 15  


Total sum = 15




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Initialize sum = 0
- Traverse matrix:
    - If column index j % 2 != 0:
        - Add element
- Print sum




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# initialize sum
s = 0


# calculate sum of odd indexed columns
for i in range(3):
    for j in range(3):
        if j % 2 != 0:   # odd column index
            s = s + a[i][j]


# print result
print(s)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
15




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Odd column condition:
j % 2 != 0




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB245


SUM OF ELEMENTS WHERE (ROW INDEX + COLUMN INDEX) IS EVEN


Definition:
Select those elements where (i + j) is even




Problem Statement:
Implement a program to find sum of elements where sum of row index and column index is even


Input:
a 3x3 matrix


Constraint:
No


Output:
sum as an integer




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix with index:


      j=0 j=1 j=2
      ↓   ↓   ↓
i=0 → 1   2   3
i=1 → 4   5   6
i=2 → 7   8   9




Check (i + j):


(0+0)=0 ✔   (0+1)=1 ✘   (0+2)=2 ✔  
(1+0)=1 ✘   (1+1)=2 ✔   (1+2)=3 ✘  
(2+0)=2 ✔   (2+1)=3 ✘   (2+2)=4 ✔  


Selected elements:
1, 3, 5, 7, 9


Sum:
1 + 3 + 5 + 7 + 9 = 25




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Initialize sum = 0
- Traverse matrix:
    - If (i + j) % 2 == 0:
        - Add element
- Print sum




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# initialize sum
s = 0


# calculate sum
for i in range(3):
    for j in range(3):
        if (i + j) % 2 == 0:   # condition
            s = s + a[i][j]


# print result
print(s)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
25




--------------------------------------------------
IMPORTANT FORMULA
--------------------------------------------------
(i + j) % 2 == 0




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB246


SUM OF ELEMENTS WHERE (ROW INDEX + COLUMN INDEX) IS ODD


Definition:
Select those elements where (i + j) is odd




Problem Statement:
Implement a program to find sum of elements where sum of row index and column index is odd


Input:
a 3x3 matrix


Constraint:
No


Output:
sum as an integer




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix with index:


      j=0 j=1 j=2
      ↓   ↓   ↓
i=0 → 1   2   3
i=1 → 4   5   6
i=2 → 7   8   9




Check (i + j):


(0+0)=0 ✘   (0+1)=1 ✔   (0+2)=2 ✘  
(1+0)=1 ✔   (1+1)=2 ✘   (1+2)=3 ✔  
(2+0)=2 ✘   (2+1)=3 ✔   (2+2)=4 ✘  


Selected elements:
2, 4, 6, 8


Sum:
2 + 4 + 6 + 8 = 20




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Initialize sum = 0
- Traverse matrix:
    - If (i + j) % 2 != 0:
        - Add element
- Print sum




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# initialize sum
s = 0


# calculate sum
for i in range(3):
    for j in range(3):
        if (i + j) % 2 != 0:   # odd condition
            s = s + a[i][j]


# print result
print(s)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
20




--------------------------------------------------
IMPORTANT FORMULA
--------------------------------------------------
(i + j) % 2 != 0




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB247


SUM OF PRIME ELEMENTS IN MATRIX


Definition:
Prime numbers are numbers which have only 2 factors → 1 and itself  
Example: 2, 3, 5, 7, 11...




Problem Statement:
Implement a program to find sum of prime elements in the given matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
sum as an integer




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix:


1   2   3
4   5   6
7   8   9




Prime numbers in matrix:
2, 3, 5, 7


Sum:
2 + 3 + 5 + 7 = 17




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Initialize sum = 0
- Traverse each element
- Check if number is prime:
    - Count factors
    - If exactly 2 → prime
- Add prime numbers to sum
- Print result




--------------------------------------------------
PRIME CHECK LOGIC
--------------------------------------------------


n = 5


Factors:
1, 5 → count = 2 → PRIME ✔


n = 6


Factors:
1, 2, 3, 6 → count = 4 → NOT PRIME ✘




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# function to check prime
def isprime(n):
    if n < 2:   # 0 and 1 are not prime
        return False

    count = 0

    for i in range(1, n+1):
        if n % i == 0:
            count += 1

    return count == 2   # prime if exactly 2 factors




# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# initialize sum
s = 0


# calculate sum of prime elements
for i in range(3):
    for j in range(3):
        if isprime(a[i][j]):
            s = s + a[i][j]


# print result
print(s)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
1 2 3
4 5 6
7 8 9




--------------------------------------------------
OUTPUT
--------------------------------------------------
17




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Prime condition:
number should have exactly 2 factors




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================
PLB248


COUNT OF PRIME DIGITS IN MATRIX


Definition:
Prime digits are → 2, 3, 5, 7




Problem Statement:
Implement a program to count number of prime digits present in the matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
prime digits count




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix:


12   23   45
67   89   10
11   32   75




Break into digits:


12 → 1,2 → ✔ (2)
23 → 2,3 → ✔✔
45 → 4,5 → ✔ (5)
67 → 6,7 → ✔ (7)
89 → 8,9 → ✘
10 → 1,0 → ✘
11 → 1,1 → ✘
32 → 3,2 → ✔✔
75 → 7,5 → ✔✔




Prime digits:
2,3,5,7


Total count = 10




--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------


- Input matrix
- Initialize count = 0
- Traverse each element
- Convert number to string
- Traverse each digit:
    - If digit in (2,3,5,7):
        - Increase count
- Print count




--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------


# input matrix
a = []


for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# initialize count
c = 0


# count prime digits
for i in range(3):
    for j in range(3):
        for digit in str(a[i][j]):   # convert number to digits
            if digit in "2357":      # check prime digits
                c = c + 1


# print result
print(c)




--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
12 23 45
67 89 10
11 32 75




--------------------------------------------------
OUTPUT
--------------------------------------------------
10




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Prime digits:
2, 3, 5, 7




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB249


REVERSE OF EACH ELEMENT IN MATRIX


Definition:
Reverse each number present in the matrix  
Example: 123 → 321




Problem Statement:
Implement a program to reverse each element in the matrix


Input:
a 3x3 matrix


Constraint:
No


Output:
resultant matrix




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix:


12   34   56
78   90   123
45   67   89




Reverse each element:
12  → 21  
34  → 43  
56  → 65  
78  → 87  
90  → 09 → 9  
123 → 321  
45  → 54  
67  → 76  
89  → 98  

Result Matrix:
21   43   65
87   9    321
54   76   98
--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------
- Input matrix
- Traverse each element
- Convert number to string
- Reverse string using slicing [::-1]
- Print reversed number
--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------
# input matrix
a = []
for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# reverse each element
for i in range(3):
    for j in range(3):
        # convert to string and reverse
        rev = str(a[i][j])[::-1]

        # convert back to int to remove leading zero
        print(int(rev), end=' ')
    print()
--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
12 34 56
78 90 123
45 67 89
--------------------------------------------------
OUTPUT
--------------------------------------------------
21 43 65
87 9 321
54 76 98




--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
[::-1] → reverse string




--------------------------------------------------
END OF PROGRAM
--------------------------------------------------
========================================================================PLB250


KEEP PALINDROME NUMBERS AND REPLACE OTHERS WITH 0


Definition:
Palindrome number → number same forward and backward  
Example: 121, 33, 7




Problem Statement:
Implement a program to keep all palindrome numbers as it is and replace remaining with 0


Input:
a 3x3 matrix


Constraint:
No


Output:
resultant matrix




--------------------------------------------------
LOGIC (WITH TEXT DIAGRAM)
--------------------------------------------------


Matrix:


121   34   55
78    99   10
11    23   7




Check palindrome:


121 → ✔  
34  → ✘  
55  → ✔  
78  → ✘  
99  → ✔  
10  → ✘  
11  → ✔  
23  → ✘  
7   → ✔  




Result Matrix:
121   0    55
0     99   0
11    0    7
--------------------------------------------------
LOGIC (STEP BY STEP)
--------------------------------------------------
- Input matrix
- Traverse each element
- Convert number to string
- Check:
    if string == reverse string
        → palindrome
    else
        → replace with 0
- Print result
--------------------------------------------------
PYTHON IMPLEMENTATION WITH COMMENTS
--------------------------------------------------
# input matrix
a = []
for i in range(3):
    row = [int(x) for x in input().split()]
    a.append(row)


# process matrix
for i in range(3):
    for j in range(3):
        s = str(a[i][j])      # convert to string
        if s == s[::-1]:      # palindrome check
            print(a[i][j], end=' ')
        else:
            print(0, end=' ')
    print()
--------------------------------------------------
EXAMPLE INPUT
--------------------------------------------------
121 34 55
78 99 10
11 23 7
--------------------------------------------------
OUTPUT
--------------------------------------------------
121 0 55
0 99 0
11 0 7
--------------------------------------------------
IMPORTANT NOTE
--------------------------------------------------
Palindrome condition:
s == s[::-1]
--------------------------------------------------
END OF PROGRAM
--------------------------------------------------