A larger part of the program should go into the computation for the basis.  As
it is now only up to about the initialization of the second SHA256 context is
used.  You can totally put in breakpoints after here and not be screwed over. I
suggest that the window is moved 7B per iteration instead of just 1.  This would
land us around the start of `sha256_transform`, and it's just such a nice
number.
