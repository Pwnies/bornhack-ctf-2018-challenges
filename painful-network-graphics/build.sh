#!/bin/sh
python gencrypto.py
python addmeta.py flag.meta.yml < flag-no-meta.png > flag.png
python crypto.py veK6daithahvaidor5woph6iay8li1la2FooYaen enc < flag.png > flag.png.enc
