#!/usr/bin/python2.7

a = lambda x: lambda y: y if x == 0 else a(x-1)(y+1)
b = lambda x: lambda y: y if x == 1 else a(b(x-1)(y))(y)
c = lambda x: 0 if x == 1 else a(c(a(b(3)(x))(1) if x & 1 else x >> 1))(1)
d = []

print "The flag is: %s" % "".join(chr(c(e)) for e in d)
