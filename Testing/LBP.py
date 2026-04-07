# Take size
n = int(input())

# Take elements
L = [int(i) for i in input().split() ]


# Create empty list for unique elements
LL = []

# Store unique elements
for i in L:
    if i not in LL:
        LL.append(i)

# Print result
for i in LL:
    print(i, end=' ')

