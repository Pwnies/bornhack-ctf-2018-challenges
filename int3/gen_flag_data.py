import sys

if len(sys.argv) != 2:
    print "%s <flag_file>" % sys.argv[0]
    exit(1)

flag = open(sys.argv[1], "r").read().strip()
flag_data = len(flag)*[0]
for i in range(len(flag)):
    for j in range(len(flag)-i):
        flag_data[j] ^= ord(flag[j+i])

print "#define FLAG_LENGTH %d" % len(flag)
print "char flag_data[FLAG_LENGTH] = {%s};" % ",".join(map(str, flag_data))
