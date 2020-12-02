import string
from time import sleep


def with_async_state(func, cnt=10):
    for i in range(cnt):
        try:
            res = func()
            return res
        except Exception as e:
            print('Bad try: %s' % i)
            print(e)
            sleep(i)
            if i == (cnt - 1):
                raise e


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


def pretty_data(data):
    result = ''
    for item in data:
        if item not in string.printable:
            result += '.'
        else:
            result += item
    return result
