
def last_flagged(seq):
    seq = iter(seq)
    a = next(seq)
    for b in seq:
        yield a, False
        a = b
    yield a, True

mylist = [1,2,3,4,5]
mylist.append(6)
for item,is_last in last_flagged(mylist):
    if is_last:
        print("Last: ", item)
    else:
        print("Not last: ", item)