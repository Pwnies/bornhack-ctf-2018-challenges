---
title: Painful Network Graphics
author: br0ns
date: 2018-07-25
---

# Overview

A (very weak) byte-wise substitution cipher is used to encrypt a PNG file.  The
cipher key (i.e. the permutation) should (as in I hope) not be able to be
brute-force'd without looking long and hard at the encrypted PNG.

It took me a while (too long) to make/solve this, so I recon 500pts is not too
much.

# Handout

- `crypto.py`
- `flag.png.enc`

# Solution

See `doit.c`.  Code has a lot of comments.  Syntax is reasonably pretty,
semantics is not (eh, better than the other way around, I recon).  Please have a
seat before you go looky-looky.
