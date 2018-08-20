#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <byteswap.h>
#include <string.h>
#include <math.h>
#include <zlib.h>

/* Resources:
 * - PNG:     https://en.wikipedia.org/wiki/Portable_Network_Graphics,
              https://www.w3.org/TR/PNG
 * - ZLIB:    https://tools.ietf.org/html/rfc1950
 * - DEFLATE: https://tools.ietf.org/html/rfc1951
 * - DPI:     https://en.wikipedia.org/wiki/Dots_per_inch
 */

#define log(fmt, ...)                           \
  fprintf(stderr, fmt "\n", ## __VA_ARGS__)

#define die(fmt, ...)                           \
  do {                                          \
    fprintf(stderr, fmt "\n", ## __VA_ARGS__);  \
    exit(EXIT_FAILURE);                         \
  } while (0)

#define PNG_MAGIC "\x89PNG\r\n\x1a\n"

typedef unsigned char byte;

byte sbox[] = {

    0x2d, 0xf9, 0x56, 0xd6, 0x4e, 0x64, 0xea, 0x9b,
    0x22, 0x3b, 0x03, 0x6a, 0xf1, 0x5e, 0x4a, 0x43,
    0x14, 0x4c, 0x41, 0x8c, 0xb7, 0x24, 0x0c, 0xf8,
    0x17, 0xb6, 0x87, 0x31, 0x5d, 0x89, 0x50, 0x9f,
    0xc3, 0x53, 0xcf, 0xb0, 0x15, 0x69, 0x32, 0xef,
    0xfa, 0x57, 0x73, 0x29, 0x8a, 0x78, 0x74, 0xeb,
    0x54, 0x4b, 0x60, 0x9c, 0xbe, 0x62, 0x86, 0x7a,
    0x55, 0xff, 0x1a, 0xdc, 0xd7, 0x96, 0x3d, 0x30,
    0xf4, 0x12, 0xc7, 0x0f, 0x71, 0xd9, 0xad, 0xb5,
    0xb8, 0x5b, 0xd1, 0x6d, 0x65, 0xe5, 0x4f, 0x04,
    0x8e, 0x7e, 0x46, 0x21, 0x3f, 0xf5, 0x02, 0x2b,
    0x93, 0x5f, 0x19, 0x8d, 0x48, 0x84, 0x0d, 0xc2,
    0x8b, 0x91, 0xf6, 0x1e, 0xaf, 0xc9, 0x98, 0x77,
    0x45, 0xfd, 0x79, 0xc0, 0xc1, 0x1b, 0x37, 0xc5,
    0xe8, 0x97, 0xa1, 0x2a, 0x88, 0xc4, 0x4d, 0x7c,
    0x00, 0x0b, 0x6e, 0xe2, 0xb4, 0xe0, 0x51, 0xe9,
    0xab, 0x6f, 0x83, 0xe6, 0xee, 0x8f, 0x94, 0x3a,
    0xb1, 0x1d, 0x39, 0x26, 0xd3, 0xe3, 0x63, 0xfc,
    0x40, 0x75, 0xac, 0xb2, 0xce, 0x42, 0xdb, 0x44,
    0x66, 0xa4, 0x72, 0x9e, 0x80, 0x06, 0x07, 0x1f,
    0xc8, 0x9a, 0x70, 0xd8, 0x99, 0xd2, 0x28, 0xf7,
    0x5c, 0x18, 0xcb, 0x33, 0x92, 0x52, 0xdf, 0x05,
    0xa0, 0x2e, 0xbd, 0xdd, 0x67, 0x47, 0xf2, 0xcc,
    0xa8, 0x6c, 0xd4, 0x68, 0xe7, 0x58, 0x6b, 0xca,
    0x34, 0xb9, 0x59, 0x20, 0x61, 0x81, 0xa3, 0xd5,
    0x23, 0x11, 0xbf, 0x7d, 0x10, 0xed, 0x36, 0x08,
    0xe1, 0x0e, 0xa5, 0x13, 0xde, 0x95, 0x0a, 0x3c,
    0xc6, 0xbb, 0xf0, 0x3e, 0x09, 0xb3, 0xba, 0x7f,
    0xaa, 0xd0, 0x7b, 0x49, 0x38, 0x76, 0x82, 0xfe,
    0xf3, 0xae, 0x9d, 0x2f, 0xcd, 0xec, 0x1c, 0x27,
    0xda, 0x16, 0x5a, 0xa2, 0x90, 0xe4, 0x35, 0xa7,
    0xa9, 0x01, 0xa6, 0x25, 0x85, 0xfb, 0xbc, 0x2c

};

bool same_cycle(byte x, byte y) {
  byte z;

  if (x == y) {
    return true;
  }

  for (z = sbox[y];; z = sbox[z]) {
    if (z == x) {
      return true;
    }
    if (z == y) {
      return false;
    }
  }
}

typedef struct {
  uint32_t length;
  char type[4];
  byte data[0];
} chunk_t;
#define CHUNK_AT(ct, offset) ((chunk_t*)&(ct)[offset])
#define NEXT_CHUNK(chunk) ((chunk_t*)&(chunk)->data[(chunk)->length + 4])

/* Encryption key (PT->CT), decryption key (CT->PT) */
byte ekey[0x100], dkey[0x100];
/* Mappings that must no longer be changed, i.e are "pinned". */
bool epin[0x100], dpin[0x100];

void init(void) {
  int i;

  for (i = 0; i < 0x100; i++) {
    ekey[i] = i;
    dkey[i] = i;
    epin[i] = false;
    dpin[i] = false;
  }
}

static inline
void encrypt(byte *ct, byte *pt, size_t len) {
  /* TODO: */
}

static inline
void optimistic_decrypt(void *ptvp, void *ctvp, size_t len) {
  size_t i;
  byte *pt = ptvp, *ct = ctvp;

  for (i = 0; i < len; i++) {
    pt[i] = dkey[ct[i]];
  }
}

static inline
void partial_decrypt(void *ptvp, void *ctvp, size_t len) {
  size_t i;
  byte *pt = ptvp, *ct = ctvp;

  for (i = 0; i < len; i++) {
    pt[i] = dpin[ct[i]] ? dkey[ct[i]] : '?';
  }
}

static inline
size_t decrypt(void *ptvp, void *ctvp, size_t len) {
  size_t i;
  byte *pt = ptvp, *ct = ctvp;

  for (i = 0; i < len; i++) {
    if (!dpin[ct[i]]) {
      break;
    }
    pt[i] = dkey[ct[i]];
  }
  return i;
}

#define must_decrypt(pt, ct, len) assert((len) == decrypt((pt), (ct), (len)))

static inline
chunk_t *decrypt_chunk_header(chunk_t *ct) {
  chunk_t *pt;

  pt = malloc(8);
  must_decrypt(pt, ct, 8);
  pt->length = bswap_32(pt->length);

  return pt;
}

/* NB: Does not decrypt (nor copy) CRC */
static inline
chunk_t *decrypt_chunk(chunk_t *ct) {
  chunk_t *pt;

  pt = decrypt_chunk_header(ct);
  pt = realloc(pt, 12 + pt->length);
  must_decrypt(pt->data, ct->data, pt->length);

  return pt;
}

/* NB: Does not decrypt (nor copy) CRC */
static inline
chunk_t *optimistic_decrypt_chunk(chunk_t *ct) {
  chunk_t *pt;

  pt = decrypt_chunk_header(ct);
  pt = realloc(pt, 12 + pt->length);
  optimistic_decrypt(pt->data, ct->data, pt->length);

  return pt;
}

/* Add PT->CT mapping, but don't pin it */
bool map(byte p, byte c) {
  if (p == c) {
    return false;
  }
  if (!same_cycle(p, c)) {
    return false;
  }
  if (epin[p]) {
    return ekey[p] == c;
  }
  if (dpin[c]) {
    return false;
  }

  ekey[p] = c;
  dkey[c] = p;

  return true;
}

/* Add a PT->CT mapping, and pin it from now on */
bool pin(byte p, byte c) {
  if (map(p, c)) {
    epin[p] = true;
    dpin[c] = true;
    return true;
  }
  return false;
}

/* Remove PT->CT mapping */
void unpin(byte p, byte c) {
  ekey[p] = p;
  dkey[c] = c;
  epin[p] = false;
  dpin[c] = false;
}

/* Add multiple mappings */
bool map_many(void *ptvp, void *ctvp, size_t numb) {
  unsigned i;
  byte *pt = ptvp, *ct = ctvp;

  for (i = 0; i < numb; i++) {
    if (!map(pt[i], ct[i])) {
      return false;
    }
  }

  return true;
}

bool pin_many(void *ptvp, void *ctvp, size_t numb) {
  unsigned i;
  byte *pt = ptvp, *ct = ctvp;

  if (!map_many(pt, ct, numb)) {
    return false;
  }

  for (i = 0; i < numb; i++) {
    epin[pt[i]] = true;
    dpin[ct[i]] = true;
  }

  return true;
}

/* Map numbers; PNG uses network byte-order */
bool map_16(uint16_t pt, void *ct) {
  pt = bswap_16(pt);
  return map_many(&pt, ct, 2);
}

bool pin_16(uint16_t pt, void *ct) {
  pt = bswap_16(pt);
  return pin_many(&pt, ct, 2);
}

bool map_32(uint32_t pt, void *ct) {
  pt = bswap_32(pt);
  return map_many(&pt, ct, 4);
}

bool pin_32(uint32_t pt, void *ct) {
  pt = bswap_32(pt);
  return pin_many(&pt, ct, 4);
}

/* Map a chunk length field in the CT to the correct value */
bool map_length(size_t length, chunk_t *chunk) {
  return map_32((uint32_t)length, &chunk->length);
}

bool pin_length(size_t length, chunk_t *chunk) {
  return pin_32((uint32_t)length, &chunk->length);
}

bool pin_length_to_next(chunk_t *this, chunk_t *next) {
  size_t length;

  length = (void*)next - (void*)this - 12;
  return pin_length(length, this);
}

/* Map a chunk type field in the CT to the correct type */
bool map_type(char *type, chunk_t *chunk) {
  return map_many(type, &chunk->type, 4);
}

bool pin_type(char *type, chunk_t *chunk) {
  return pin_many(type, &chunk->type, 4);
}

bool map_crc(chunk_t *chunk) {
  uint32_t crc;
  chunk_t *pt_chunk;
  bool ret;

  pt_chunk = optimistic_decrypt_chunk(chunk);
  crc = crc32(0, (byte*)pt_chunk->type, pt_chunk->length + 4);
  ret = map_32(crc, &chunk->data[pt_chunk->length]);
  free(pt_chunk);

  return ret;
}

bool pin_crc(chunk_t *chunk) {
  uint32_t crc;
  chunk_t *pt_chunk;
  bool ret;

  pt_chunk = decrypt_chunk(chunk);
  crc = crc32(0, (byte*)pt_chunk->type, pt_chunk->length + 4);
  ret = pin_32(crc, &chunk->data[pt_chunk->length]);
  free(pt_chunk);

  return ret;
}

#define must_pin(p, c)                 assert(pin((p), (c)))
#define must_pin_16(p, c)              assert(pin_16((p), (c)))
#define must_pin_32(p, c)              assert(pin_32((p), (c)))
#define must_pin_many(p, c, n)         assert(pin_many((p), (c), (n)))
#define must_pin_length(p, c)          assert(pin_length((p), (c)))
#define must_pin_length_to_next(a, b)  assert(pin_length_to_next((a), (b)))
#define must_pin_type(p, c)            assert(pin_type((p), (c)))
#define must_pin_crc(c)                assert(pin_crc((c)))

/* Find data in (partially) decrypted PT.  Returns pointer to CT. */
void *find(void *ctvp, size_t ct_len, void *ptvp, size_t pt_len) {
  /* TODO: Implement KMP string matching */
  byte needle[pt_len], *pt = ptvp, *ct = ctvp;
  unsigned i, j;

  for (i = 0; i < pt_len; i++) {
    needle[i] = ekey[pt[i]];
  }

  for (i = 0; i < ct_len - sizeof(needle) + 1; i++) {
    for (j = 0; j < sizeof(needle); j++) {
      if (ct[i + j] != needle[j]) {
        break;
      }
    }
    if (j == sizeof(needle)) {
      return &ct[i];
    }
  }

  return NULL;
}

size_t chunk_length(chunk_t *ct) {
  size_t length;

  must_decrypt(&length, ct, 4);
  return bswap_32(length);
}

/* NB: the chunk must be a pointer into the CT. */
chunk_t *next_chunk(chunk_t *ct) {
  return (chunk_t*)&ct->data[chunk_length(ct) + 4];
}

/* Find a chunk by looking for type field in (partially) decrypted PT.
 * NB: False positives are possible
 */
chunk_t *find_chunk(void *ct, size_t numb, char *type) {
  /* Account for length and CRC fields */
  ct = find(ct + 4, numb - 4 - 4, type, 4);

  return ct ? ct - 4 : NULL;
}

chunk_t *find_chunk_after(void *ct, size_t numb, chunk_t *prev, char *type) {
  off_t off;

  if (NULL == prev) {
    /* If no previous chunk search from after the PNG magic */
    off = 8;
  } else {
    /* Minimal offset into CT: skip at least length + type + CRC */
    off = (void*)prev - ct + 12;
  }
  return find_chunk(ct + off, numb - off, type);
}

void read_file(char *path, byte **datap, size_t *numbp) {
  int fd, ret;
  size_t n, numb;
  struct stat st;
  byte *data;

  fd = open(path, O_RDONLY);
  if (-1 == fd) {
    perror("open()");
    exit(EXIT_FAILURE);
  }

  if (-1 == fstat(fd, &st)) {
    perror("fstat()");
    exit(EXIT_FAILURE);
  }

  if (NULL == (data = malloc(st.st_size))) {
    perror("malloc()");
    exit(EXIT_FAILURE);
  }

  numb = (size_t)st.st_size;

  for (n = 0; n < numb;) {
    switch ((ret = read(fd, &data[n], numb - n))) {
    case 0:
      fprintf(stderr, "read(): returned 0\n");
      exit(EXIT_FAILURE);
    case -1:
      if (EINTR == errno) {
        continue;
      }
      perror("read()");
      exit(EXIT_FAILURE);
    default:
      n += ret;
    }
  }

  *datap = data;
  *numbp = numb;
}

void write_file(char *path, byte *data, size_t numb) {
  int fd, ret;
  size_t n;


  fd = open(path, O_WRONLY | O_CREAT, 0644);
  if (-1 == fd) {
    perror("open()");
    exit(EXIT_FAILURE);
  }

  for (n = 0; n < numb;) {
    switch ((ret = write(fd, &data[n], numb - n))) {
    case 0:
      fprintf(stderr, "write(): returned 0\n");
      exit(EXIT_FAILURE);
    case -1:
      if (errno == EINTR) {
        continue;
      }
      perror("write()");
      exit(EXIT_FAILURE);
    default:
      n += ret;
    }
  }
}

unsigned mappings() {
  unsigned i, n;
  for (n = 0, i = 0; i < 0x100; i++) {
    if (epin[i]) {
      n++;
    }
  }
  return n;
}

void dump_key() {
  unsigned i;

  fprintf(stderr, "Partial encryption key (PT <-> CT):\n");
  for (i = 0; i < 0x100; i++) {
    if (epin[i]) {
      fprintf(stderr, "  0x%02x <-> ", i);
      fprintf(stderr, "0x%02x\n", ekey[i]);
    } else {
      /* fprintf(stderr, "?\n"); */
    }
  }
}

void step1(byte *ct, size_t ct_len) {
  log("Step 1 : Pin magic, IHDR and IEND");
  log("  We assume that the image is 8-bit/color RGBA.");

  chunk_t *IHDR, *IEND;

  /* Magic bytes */
  must_pin_many(PNG_MAGIC, ct, 8);

  /* First chunk must be IHDR
   * The size is 13B:
   *  - width (4)
   *  - height (4)
   *  - depth (1)
   *  - color type (1)
   *  - compression method (1)
   *  - filter method (1)
   *  - interlace method (1)
   */
  IHDR = CHUNK_AT(ct, 8);
  must_pin_length(0x0d, IHDR);
  must_pin_type("IHDR" , IHDR);

  /* Depth is probably 8 bits per channel
   * XXX: Assumption (confirmed by hint #1).
   */
  must_pin(0x08, IHDR->data[8]);
  /* Color type is probably 6 (RGBA)
   * XXX: Assumption (confirmed by hint #1).
   */
  must_pin(0x06, IHDR->data[9]);
  /* Compression must be 0 (DEFLATE) */
  must_pin(0x00, IHDR->data[10]);
  /* Challenge specific: we already have a mapping for 0 so it turns out that
   * both filtering and interlacing is off (0).
   */
  must_pin(0x00, IHDR->data[11]);
  must_pin(0x00, IHDR->data[12]);

  /* IEND chunk */
  IEND = CHUNK_AT(ct, ct_len - 12);
  must_pin_length(0, IEND);
  must_pin_type("IEND", IEND);
  must_pin_crc(IEND);
}

void step2(byte *ct, size_t ct_len) {
  log("Step 2: Find probable IDAT headers.");
  log("  We know 'I' and 'D' from step 1, so we can find all 'ID\?\?' chunks.  The one");
  log("  with the most occurrences is probably the right one.");

  size_t i, best, besti, count[0x10000] = {0};
  byte I, D, A, T;

  I = ekey['I'];
  D = ekey['D'];

  for (i = 0; i < ct_len - 3; i++) {
    if (I == ct[i] && D == ct[i + 1]) {
      count[ct[i + 2] << 8 | ct[i + 3]] += 1;
    }
  }

  log("   A  T");
  for (best = 0, i = 0; i < 0x10000; i++) {
    if (count[i]) {
      log("  %02x %02x: %d", i >> 8, i & 0xff, count[i]);
    }
    if (count[i] > best) {
      best = count[i];
      besti = i;
    }
  }

  A = besti >> 8;
  T = besti & 0xff;
  must_pin('A', A);
  must_pin('T', T);

  log("  Found:");
  log("    'A' -> 0x%02x", A);
  log("    'T' -> 0x%02x", T);
}

void step3(byte *ct, size_t ct_len) {
  log("Step 3: Find the lengths of IDAT chunk.");
  log("  According to the standard, no other chunks may be mixed in.  In addition we");
  log("  can guess the last IDAT chunk ends just before IEND.");

  size_t len, i;
  chunk_t *prev, *this;

  prev = NULL;
  for (;;) {
    this = find_chunk_after(ct, ct_len, prev, "IDAT");
    if (!this) {
      break;
    }
    if (prev) {
      len = (void*)this - (void*)prev - 12;
      must_pin_length(len, prev);
      log("  IDAT @ 0x%x : 0x%x", (unsigned)((byte*)this - ct), len);
    }
    prev = this;

    /* Advance CT pointer */
    i = (byte*)this - ct + 12;
  }

  /* Account for IDAT and IEND chunks */
  len = &ct[ct_len] - (byte*)prev - 2 * 12;
  must_pin_length(len, prev);
  log("  IDAT @ 0x%x : 0x%x", (unsigned)((byte*)prev - ct), len);
}

void step4(byte *ct, size_t ct_len) {
  log("Step 4 : Make a best guess at ZLIB stream header.");
  log("  We assume DEFLATE with 32k window, default (2) compression, and no preset");
  log("  dictionary.");

  /* ZLIB header:
   *   CM (compression method, 4b)   : 8 (DEFLATE)
   *   CINFO (compression info, 4b)  : 7 (window size = 32K is standard)
   *   FCHECK (check bits, 5b)       : 28 (must have CMF % 31 == 0)
   *   FDICT (preset dictionary, 1b) : 0 (probably not)
   *   FLEVEL (compression level, 3b): 2 (default)
   * XXX: Assumption (partially confirmed by hint #2).
   */

  unsigned int cmf;
  size_t i, prev, len;
  chunk_t *chunk;

  chunk = find_chunk(ct, ct_len, "IDAT");
  cmf             = 2;
  cmf <<= 1; cmf |= 0;
  cmf <<= 5; cmf |= 28;
  cmf <<= 4; cmf |= 7;
  cmf <<= 4; cmf |= 8;

  /* Find first IDAT, where the stream starts. */
  must_pin(cmf & 0xff, chunk->data[0]);
  must_pin(cmf >> 8, chunk->data[1]);
  log("  0x%02x -> 0x%02x", cmf & 0xff, chunk->data[0]);
  log("  0x%02x -> 0x%02x", cmf >> 8, chunk->data[1]);
}

void step5(byte *ct, size_t ct_len) {
  log("Step 5: Pin sBIT chunk.");
  log("  Now we get challenge specific; looking at the partially decrypted image, we");
  log("  spot an sBIT chunk just after the IHDR.  We assume 8 bit sample depth for all");
  log("  channels.");

  chunk_t *sBIT;

  sBIT = CHUNK_AT(ct, 0x21);
  must_pin_length(4, sBIT);
  must_pin_type("sBIT", sBIT);

  /* Given that we have an RGBA image with an 8 bit color depth we probably also
   * have a sample depth of 8 on all four channels.
   *
   * XXX: Assumption.
   */
  must_pin(8, sBIT->data[0]);
  must_pin(8, sBIT->data[1]);
  must_pin(8, sBIT->data[2]);
  must_pin(8, sBIT->data[3]);

  /* And now we have a full chunk, so we get the CRC as well. */
  must_pin_crc(sBIT);
}

void step6(byte *ct, size_t ct_len) {
  log("Step 6: Pin pHYs chunk header");
  log("  We notice a pHYs chunk just after the sBIT chunk.  It always has length 9.");

  chunk_t *pHYs;

  pHYs = CHUNK_AT(ct, 0x31);
  must_pin_length(9, pHYs);
  must_pin_type("pHYs", pHYs);
}

void step7(byte *ct, size_t ct_len) {
  log("Step 7: Pin tEXt and zTXt types and sizes.");
  log("  The type of the chunk following pHYs has an E as its second letter and the");
  log("  first and last letters are the same, and so it can only be a tEXt chunk.  We");
  log("  can reasonably guess it's size.  The same goes for the next chunk.");
  log("  The following chunk is either iTXt or zTXt, but we can see that it's keyword");
  log("  starts with a D which makes it either 'Disclaimer' or 'Description', but both");
  log("  it's second and sixth letter differs from the first letter in the type field,");
  log("  so the type must be zTXt.  Again, the size can be guessed at.");
  log("  The sizes of the following tEXt and zTXt chunk(s) are also easily guessed.");

  chunk_t *tEXt, *zTXt, *prev;
  unsigned i;

  tEXt = CHUNK_AT(ct, 0x46);
  must_pin_length(30, tEXt);
  must_pin_type("tEXt", tEXt);

  tEXt = next_chunk(tEXt);
  must_pin_length(12, tEXt);
  must_pin_type("tEXt", tEXt);

  zTXt = next_chunk(tEXt);
  must_pin_type("zTXt", zTXt);

  prev = zTXt;
  for (i = 0; i < 4; i++) {
    tEXt = find_chunk_after(ct, ct_len, prev, "tEXt");
    must_pin_length_to_next(prev, tEXt);
    prev = tEXt;
  }

  zTXt = find_chunk_after(ct, ct_len, prev, "zTXt");
  must_pin_length_to_next(prev, zTXt);

  /* Size of last chunk is gleaned from the partially decrypted flag.png */
  must_pin_length(752, zTXt);
}

void step8(byte *ct, size_t ct_len) {
  log("Step 8: Reconstruct meta data keywords and sizes.");
  log("  tEXt, iTXt and zTXt chunks follow the format `<keyword>\\x00<data>`, where");
  log("  <data> depends on the chunk type; for tEXt it is just regular ASCII with no");
  log("  NULL terminator.  There's a limited number of standard keywords, and so we can");
  log("  reconstruct them.  We can also be reasonably sure of the chunk sizes.");

  chunk_t *tEXt, *zTXt, *prev;

  log("    tEXt: Title");
  tEXt = find_chunk(ct, ct_len, "tEXt");
  must_pin_many("Title\0", tEXt->data, 6);

  log("    tEXt: Author");
  tEXt = next_chunk(tEXt);
  must_pin_many("Author\0", tEXt->data, 7);

  log("    zTXt: Description");
  zTXt = next_chunk(tEXt);
  must_pin_many("Description\0", zTXt->data, 12);

  log("    tEXt: Copyright");
  tEXt = next_chunk(zTXt);
  must_pin_many("Copyright\0", tEXt->data, 10);

  log("    tEXt: Creation Time");
  tEXt = next_chunk(tEXt);
  must_pin_many("Creation Time\0", tEXt->data, 14);

  log("    tEXt: Software");
  tEXt = next_chunk(tEXt);
  must_pin_many("Software\0", tEXt->data, 9);

  log("    tEXt: Disclaimer");
  tEXt = next_chunk(tEXt);
  must_pin_many("Disclaimer\0", tEXt->data, 11);

  log("    zTXt: Warning");
  zTXt = next_chunk(tEXt);
  must_pin_many("Warning\0", zTXt->data, 8);
}

void step9(byte *ct, size_t ct_len) {
  log("Step 9: Reconstruct meta data.");
  log("  At this point we have uncovered enough of the key that we can make some");
  log("  educated guesses at the meta data itself.  And then we get mappings for the");
  log("  CRC sums as well \\o/.");
  log("");

  chunk_t *tEXt, *zTXt;
  unsigned a, b, c, d, gooda, goodb, goodc, goodd, n;

  log("  Title: Painful Networ? Graphics");
  log("    The name of the challenge.  Easy.");
  tEXt = find_chunk(ct, ct_len, "tEXt");
  must_pin_many("Painful Network Graphics", &tEXt->data[6], 24);
  must_pin_crc(tEXt);

  log("  Author: ?r?ns");
  log("    Nick can be found in Bornhack CTF 2017 repository on GitHub.");
  tEXt = next_chunk(tEXt);
  must_pin_many("br0ns", &tEXt->data[7], 5);
  must_pin_crc(tEXt);

  log("  Copyright: Copyright Pwnies ????");
  log("    Can easily be brute-forced if not guessed.  Even going through the full");
  log("    byte-range there is only one valid candidate: 2018.");
  zTXt = next_chunk(tEXt);
  tEXt = next_chunk(zTXt);
  must_pin_many("Copyright Pwnies 2018", &tEXt->data[10], 21);
  must_pin_crc(tEXt);

  /* Uncomment to run brute-force */
  for (n = 0, a = 0; a < 0x100; a++) {
    if (!map(a, tEXt->data[27])) {
      continue;
    }
    for (b = 0; b < 0x100; b++) {
      if (!map(b, tEXt->data[28])) {
        continue;
      }
      for (c = 0; c < 0x100; c++) {
        if (!map(c, tEXt->data[29])) {
          continue;
        }
        for (d = 0; d < 0x100; d++) {
          if (!map(d, tEXt->data[30])) {
            continue;
          }
          if (map_crc(tEXt)) {
            log("     - %c%c%c%c", a, b, c, d);
            n++;
            gooda = a;
            goodb = b;
            goodc = c;
            goodd = d;
          }
        }
      }
    }
  }
  if (1 == n) {
    must_pin(gooda, tEXt->data[27]);
    must_pin(goodb, tEXt->data[28]);
    must_pin(goodc, tEXt->data[29]);
    must_pin(goodd, tEXt->data[30]);
    must_pin_crc(tEXt);
  } else {
    log("    !! Could not determine copyright notice");
  }

  log("  Creation Time: ?uly 1? 2018");
  log("    Again this is easy to brute-force.");
  tEXt = next_chunk(tEXt);

  for (n = 0, a = 0; a < 0x100; a++) {
    if (!map(a, tEXt->data[14])) {
      continue;
    }
    for (b = 0; b < 0x100; b++) {
      if (!map(b, tEXt->data[20])) {
        continue;
      }
      if (map_crc(tEXt)) {
        log("     - '%c' & '%c'", a, b);
        n++;
        gooda = a;
        goodb = b;
      }
    }
  }
  if (1 == n) {
    must_pin(gooda, tEXt->data[14]);
    must_pin(goodb, tEXt->data[20]);
    must_pin_crc(tEXt);
  } else {
    log("    !! Could not determine creation time");
  }

  log("  Software  : www?in?scape?org");
  log("    So easy it hurts.");
  tEXt = next_chunk(tEXt);
  must_pin_many("www.inkscape.org", &tEXt->data[9], 12);
  must_pin_crc(tEXt);

  log("  Disclaimer: ?e cannot be held liable for any loss of sanity");
  log("    We already know 'w', so the first letter must be 'W'.");
  tEXt = next_chunk(tEXt);
  must_pin_many("We cannot be held liable for any loss of sanity", &tEXt->data[11], 47);
  must_pin_crc(tEXt);
}

void step10(byte *ct, size_t ct_len) {
  log("Step 10: Brute-force tIME chunk");
  log("  Following the last zTXt chunk we find tI?E which can only be a tIME chunk.");
  log("  The time is brute-forced with the assumption that the modification time is");
  log("  between 1970 and 2018 (the assumption can be weakened somewhat):");

  chunk_t *tIME;
  unsigned year, mon, day, hour, min, sec, n, goodyear, goodmon, goodday,
    goodhour, goodmin, goodsec;

  /* tIME is the 8th chunk after the first tEXt chunk */
  tIME = find_chunk(ct, ct_len, "tEXt");
  tIME = next_chunk(tIME);
  tIME = next_chunk(tIME);
  tIME = next_chunk(tIME);
  tIME = next_chunk(tIME);
  tIME = next_chunk(tIME);
  tIME = next_chunk(tIME);
  tIME = next_chunk(tIME);
  tIME = next_chunk(tIME);

  must_pin_length(7, tIME);
  must_pin_type("tIME", tIME);

  n = 0;
  for (year = 1970; year <= 2018; year++) {
    if (!map_16(year, &tIME->data[0])) {
      continue;
    }
    for (mon = 1; mon <= 12; mon++) {
      if (!map(mon, tIME->data[2])) {
        continue;
      }
      for (day = 1; day <= 31; day++) {
        if (!map(day, tIME->data[3])) {
          continue;
        }
        for (hour = 0; hour <= 23; hour++) {
          if (!map(hour, tIME->data[4])) {
          continue;
        }
          for (min = 0; min <= 59; min++) {
            if (!map(min, tIME->data[5])) {
              continue;
            }
            for (sec = 0; sec <= 60; sec++) {
              if (!map(sec, tIME->data[6])) {
                continue;
              }
              if (map_crc(tIME)) {
                n++;
                goodyear = year;
                goodmon = mon;
                goodday = day;
                goodhour = hour;
                goodmin = min;
                goodsec = sec;
                log("    - %d-%02d-%02d %02d:%02d:%0d",
                    year,
                    mon,
                    day,
                    hour,
                    min,
                    sec);
              }
            }
          }
        }
      }
    }
  }

  if (1 == n) {
    log("  Found modification time: %d-%02d-%02d %02d:%02d:%0d",
        goodyear,
        goodmon,
        goodday,
        goodhour,
        goodmin,
        goodsec);
    must_pin_16(goodyear, &tIME->data[0]);
    must_pin(goodmon, tIME->data[2]);
    must_pin(goodday, tIME->data[3]);
    must_pin(goodhour, tIME->data[4]);
    must_pin(goodmin, tIME->data[5]);
    must_pin(goodsec, tIME->data[6]);
    must_pin_crc(tIME);
  } else {
    log("  !! Could not determine modification time");
  }

}

void step11(byte *ct, size_t ct_len) {
  log("Step 11: Try common DPI's to determine pixel size/ratio.");
  log("  From looking at the partially decoded PT we guess that there's a pHYs chunk");
  log("  following the sBIT (no other type matches ?H?s).  Since 0 is already mapped we");
  log("  can also guess that the unit is in dots per meter. Furthermore it is apparent");
  log("  that pixels are square.  We brute-force from a list of common pixel sizes:");

  /* List of common DPM values (1DPM = 39.37007874016DPI):
   *  DPI     DPM
   *   72    2835
   *   96    3780
   *  150    5906
   *  300   11811
   * 2540  100000*
   * 4000  157480*
   * (* not possible because the two MSB's are 0)
   */

  unsigned n, dpm, i, dpms[] = {2835, 3780, 5906, 11811};
  chunk_t *pHYs;

  pHYs = CHUNK_AT(ct, 0x31);

  /* Units are in meters */
  must_pin(1, pHYs->data[8]);

  for (n = 0, i = 0; i < sizeof(dpms)/sizeof(dpms[0]); i++) {
    if (map_32(dpms[i], &pHYs->data[0]) && map_crc(pHYs)) {
      n++;
      dpm = dpms[i];
      log("    - %dx%d pixels/meter (%d dpi)", dpm, dpm, (int)(dpm / 39.37007874016));
    }
  }

  /* Lucky? */
  if (1 == n) {
    must_pin_32(dpm, &pHYs->data[0]);
    must_pin_32(dpm, &pHYs->data[4]);
    must_pin_crc(pHYs);
    log("  Found pixel size/ratio: %dx%d pixels/meter (%d dpi)", dpm, dpm,
        (int)(dpm / 39.37007874016));
  } else {
    log("  !! Could not determine pixel size/ratio");
  }
}

void step12(byte *ct, size_t ct_len) {
#define RATIO ((double)100)
#define CMIN  ((double)0.1)
#define CMAX  ((double)100)
  log("Step 12: Brute-force the image dimensions.");
  log("  Let's guess at a compression ratio between %.2f and %.0f and assume that the",
      CMIN, CMAX);
  log("  image is not %.0f times wider than tall or vice versa:", RATIO);

  unsigned goodw, goodh, w, h, n;
  chunk_t *IHDR;

  IHDR = CHUNK_AT(ct, 8);

  /* h <= RATIO * w
   * w <= RATIO * h
   * w * h * 4 >= size / CMAX
   * w * h * 4 <= size / CMIN
   *
   * w * RATIO * w * 4 >= size / CMAX     -->
   * w >= sqrt(size / (CMAX * RATIO * 4))
   *
   * w / RATIO * w * 4 <= size / CMIN     -->
   * w <= sqrt(RATIO * size / (CMIN * 4))
   *
   * w * h * 4 >= size / CMAX             -->
   * h >= size / (w * 4 * CMAX)
   *
   * w * h * 4 >= size / CMIN             -->
   * h <= size / (w * 4 * CMIN)
   */
  n = 0;
  for (w = sqrt(ct_len / (CMAX * RATIO * 4));
       w <= sqrt(RATIO * ct_len / (CMIN * 4));
       w++) {
    for (h = ct_len / (w * 4 * CMAX);
         h <= ct_len / (w * 4 * CMIN); h++) {
      if (map_32(w, &IHDR->data[0]) &&
          map_32(h, &IHDR->data[4]) &&
          map_crc(IHDR)) {
        n++;
        goodw = w;
        goodh = h;
        log("    - %dx%d", w, h);
      }
    }
  }

  /* Lucky? */
  if (1 == n) {
    must_pin_32(goodw, &IHDR->data[0]);
    must_pin_32(goodh, &IHDR->data[4]);
    must_pin_crc(IHDR);
    log("  Found image dimensions: %dx%d", goodw, goodh);
  } else {
    log("  !! Could not determine image dimensions.");
  }
}


int crack_zlib(byte *ct, size_t ct_len, chunk_t *verify_chunk) {
  /* ZLIB needs somewhere to but its bytes */
  byte outbuf[1<<20], pt[ct_len], c, p;
  unsigned i, nexti;
  int ret;
  z_stream strm;

  /* A backtracking search is perhaps most easily implemented as a recursive
   * function.  But all those recursive calls are not good for performance at
   * all.  So here we "unroll" the recursion to a loop, a couple of goto's and
   * an explicit stack for local variables.
   *
   * The label `DESCENT` acts as the entry-point of the recursive function, and
   * `ASCENT` as the point-of-return after a recursive call (no need to save the
   * return address).  Two macros, `CALL` and `RETURN`, mimic the recursive call
   * and return statements, respectively.
   *
   * Only two local variables need saving: the index of the next un-mapped byte
   * in the CT (`i`) and the next PT byte to try and map it to (`p`).  For all
   * practical scenarios both can be packed into an `unsigned`.  The next free
   * slot on the stack is at index `stack_top`.
   */
  unsigned stack[0x100], stack_top = 0;
#define PUSH(i, p)                              \
  stack[stack_top++] = (i) << 8 | (p);

#define POP(i, p)                               \
  do {                                          \
    stack_top--;                                \
    i = stack[stack_top] >> 8;                  \
    p = stack[stack_top] & 0xff;                \
  } while (0)

#define RETURN()                                \
  do {                                          \
    if (!stack_top) {                           \
      ret = 1;                                  \
      goto EXIT;                                \
    }                                           \
    POP(i, p);                                  \
    c = ct[i];                                  \
    goto ASCENT;                                \
  } while (0)

#define CALL(nexti)                             \
  do {                                          \
    PUSH(i, p);                                 \
    i = (nexti);                                \
    goto DESCENT;                               \
  } while (0)

  /* This may take a while, so lets add a nice spinner */
#define SPINNER ((char[]){'/', '-', '\\', '|'})
#define TICK 100000
  unsigned long steps;

  /* First we decrypt as far as we can go. */
  i = decrypt(pt, ct, ct_len);

  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  ret = inflateInit(&strm);
  if (ret != Z_OK) {
    exit(1);
  }

  steps = 0;
  for (;;) {
    /* The "entry-point" of the unrolled recursion */
  DESCENT:

    /* Everything has been decrypted */
    if (i == ct_len) {
      /* Verify CRC */
      if (pin_crc(verify_chunk)) {
        ret = 0;
        goto EXIT;
      } else {
        RETURN();
      }
    }

    c = ct[i];
    /* Loop over available mappings
     *
     * A trick: we know that 0 was already mapped, so we start at 1 and exploit
     * that `p` wraps to 0 at the end.
     */
    for (p = 1; p; p++) {
      /* Let's try it */
      if (!pin(p, c)) {
        continue;
      }

      /* Spinner \o/ */
      steps++;
      if (steps % TICK == 0) {
        fprintf(stderr, "\e[G%c", SPINNER[(steps / TICK) % 4]);
        fflush(stderr);
      }

      /* Decrypt as far as we can go */
      nexti = i + decrypt(&pt[i], &ct[i], ct_len - i);
      assert(nexti > i);

      /* Try to decompress it */
      strm.avail_in = nexti;
      strm.next_in = pt;

      strm.avail_out = sizeof(outbuf);
      strm.next_out = outbuf;

      inflateReset(&strm);
      ret = inflate(&strm, Z_FINISH);

      switch (ret) {
      case Z_OK:
      case Z_STREAM_END:
      case Z_BUF_ERROR:
        /* Mapping good so far; recurse */
        CALL(nexti);

        /* After a recursive "call" this is where we return to */
      ASCENT:
        break;

      case Z_DATA_ERROR:
      case Z_NEED_DICT:
        /* Wrong mapping; try next */
        break;

      default:
        log("!! Unexpected return value from `inflate`: %d\n", ret);
        exit(EXIT_FAILURE);
      }

      /* Clear mapping to be ready for the next */
      unpin(p, c);
    }

    RETURN();
  }

 EXIT:
  inflateEnd(&strm);

  /* Clear spinner */
  fprintf(stderr, "\e[G\e[K");
  fflush(stderr);

  if (0 != ret) {
    log("!! ZLIB stream: no solution\n");
  }
  return ret;
}

void step13(byte *ct, size_t ct_len) {
  log("Step 13: Brute-force contents of zTXt 'Description' chunk.");
  log("  The search tree is pretty huge, but we can exploit that not everything is a");
  log("  valid DEFLATE stream and prune it early in many cases.");

  chunk_t *zTXt;
  size_t len;
  off_t offset;
  byte *ct2;

  zTXt = find_chunk(ct, ct_len, "zTXt");
  offset = strlen("Description") + 2;
  /* zTXt = find_chunk_after(ct, ct_len, zTXt, "zTXt"); */
  /* offset = strlen("Warning") + 2; */
  len = chunk_length(zTXt) - offset;
  ct2 = &zTXt->data[offset];
  crack_zlib(ct2, len, zTXt);
  must_pin_crc(zTXt);
}

void step14(byte *ct, size_t ct_len) {
  log("Step 14: Brute-force contents of first IDAT chunk.");
  log("  Notice that step 13 was needed for this step to be practical.  After this step");
  log("  we should have recovered the full encryption key.");

  chunk_t *IDAT;
  size_t len;
  byte *ct2;

  IDAT = find_chunk(ct, ct_len, "IDAT");
  len = chunk_length(IDAT);
  ct2 = IDAT->data;
  crack_zlib(ct2, len, IDAT);
  must_pin_crc(IDAT);

  assert(mappings() == 0x100);
}

void crack(byte *ct, size_t ct_len) {
#define STEP(n)                                             \
  do {                                                      \
    step##n(ct, ct_len);                                    \
    log("Now have %d mappings", mappings());                \
  } while (0)

  STEP(1);
  STEP(2);
  STEP(3);
  STEP(4);
  STEP(5);
  STEP(6);
  STEP(7);
  STEP(8);
  if (1) {
    log("(Step 9 involves a good amount of guess-work, so we skip it to be fair.)");
  } else {
    STEP(9);
  }
  STEP(10);
  STEP(11);
  STEP(12);
  STEP(13);
  STEP(14);
}

int main(int argc, char *argv[]) {
  byte *ct, *pt;
  size_t ct_len;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <path>\n", argv[0]);
    return EXIT_FAILURE;
  }

  init();
  read_file(argv[1], &ct, &ct_len);

  crack(ct, ct_len);

  pt = malloc(ct_len);
  partial_decrypt(pt, ct, ct_len);
  /* optimistic_decrypt(pt, ct, ct_len); */
  write_file("flag.png", pt, ct_len);

  return EXIT_SUCCESS;
}
