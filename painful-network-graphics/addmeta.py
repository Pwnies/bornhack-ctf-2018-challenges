import sys
import struct
import zlib
import binascii
import time
import oyaml as yaml

# Reproducible builds, please (or set to None for current time)
modtime = 1532427739

keywords = {
    'Title',
    'Author',
    'Description',
    'Copyright',
    'Creation Time',
    'Software',
    'Disclaimer',
    'Warning',
    'Source',
    'Comment',
}

def crc32(data):
    return binascii.crc32(data) & 0xffffffff

def insertmeta(meta, fd):
    for k, v in meta.items():
        if k not in keywords:
            print >>sys.stderr, '!! Invalid keyword: %s' % k
            continue
        print >>sys.stderr, '%s: %s' % (k, v)
        text = '%s\0%s' % (k, v)
        ztxt = '%s\0\0%s' % (k, zlib.compress(v))
        if len(text) < len(ztxt):
            type = 'tEXt'
            data = text
        else:
            type = 'zTXt'
            data = ztxt
        fd.write(''.join([
            struct.pack('>I', len(data)),
            type,
            data,
            struct.pack('>I', crc32(type + data)),
        ]))

    # Add iTIME
    t = time.gmtime(modtime)
    type = 'tIME'
    data = struct.pack(
        '>HBBBBB',
        t.tm_year,
        t.tm_mon,
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec,
    )
    fd.write(''.join([
        struct.pack('>I', len(data)),
        type,
        data,
        struct.pack('>I', crc32(type + data)),
    ]))

def addmeta(meta, fdi=sys.stdin, fdo=sys.stdout):
    meta = yaml.load(file(meta))
    skip = False

    # Skip magic
    fdo.write(fdi.read(8))

    # Process chunks
    while True:
        length = fdi.read(4)
        type = fdi.read(4)
        data = fdi.read(struct.unpack('>I', length)[0])
        crc = fdi.read(4)
        chunk = ''.join([length, type, data, crc])

        # skip existing meta-data (i.e. tEXt, zTXt, iTXt, tIME)
        if type in ('tEXt', 'zTXt', 'iTXt', 'tIME'):
            continue

        # Insert metadata before first IDAT chunk
        if not skip and type == 'IDAT':
            insertmeta(meta, fdo)
            skip = True

        fdo.write(chunk)

        # End of file
        if type == 'IEND':
            break

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print >>sys.stderr, \
            'usage: %s <meta file> < <png in> > <png out>' % sys.argv[0]
        exit(1)
    addmeta(sys.argv[1])
