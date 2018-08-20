
#define NUM_PHASES 1
#define BUFFER_UNIT_T uint8_t
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/time.h>
#ifdef __APPLE__
#   include <mach-o/dyld.h>
#endif

#define RETC_PRINT_USAGE     1
#define RETC_PRINT_INFO      2

#define OUTBUFFER_SIZE       (16*1024)
#define INBUFFER_SIZE        (16*1024)
#define INITIAL_BUFFER_SIZE  (4096*8)
#define OUTBUFFER_STACK_SIZE (1024)

#ifdef FLAG_NOINLINE
#define INLINE static
#endif
#ifndef INLINE
#define INLINE static inline
#endif

#ifndef BUFFER_UNIT_T
#warning "BUFFER_UNIT_T not defined. Falling back to default 'uint8_t'"
#define BUFFER_UNIT_T uint8_t
#endif

#ifndef NUM_PHASES
#error "NUM_PHASES not defined."
#endif

#ifndef OUTSTREAM
#define OUTSTREAM stdout
#endif

// Order of descriptors provided by pipe()
#define  READ_FD 0
#define WRITE_FD 1

typedef BUFFER_UNIT_T buffer_unit_t;
typedef struct {
  buffer_unit_t *data;
  size_t size;         /* size in bytes */
  size_t bitpos;       /* bit offset from data  */
} buffer_t;

#define BUFFER_UNIT_SIZE (sizeof(buffer_unit_t))
#define BUFFER_UNIT_BITS (BUFFER_UNIT_SIZE * 8)

unsigned char *next;
buffer_t outbuf;
buffer_t *outbuf_ptr;
size_t count = 0;

unsigned char inbuf[INBUFFER_SIZE*2];
size_t in_size = 0;
int in_cursor = 0;
#define avail (in_size - in_cursor)

// Output buffer stack

typedef struct {
  buffer_t **data;
  size_t capacity;
  size_t size;
} buf_stack;

buf_stack outbuf_stack;

void pushoutbuf(buffer_t *buf) {
  if (outbuf_stack.size == outbuf_stack.capacity) {
    outbuf_stack.capacity *= 2;
    outbuf_stack.data = realloc(outbuf_stack.data, outbuf_stack.capacity*sizeof(buffer_t *));
  }
  outbuf_stack.data[outbuf_stack.size++] = outbuf_ptr;
  outbuf_ptr = buf;
}

void popoutbuf() {
  if (outbuf_stack.size <= 0) {
    fprintf(stderr, "Error: Tried popping an empty buffer stack");
    exit(1);
  }
  outbuf_ptr = outbuf_stack.data[--outbuf_stack.size];
}

void init_outbuf_stack()
{
  outbuf_ptr = &outbuf;
  outbuf_stack.size = 0;
  outbuf_stack.capacity = OUTBUFFER_STACK_SIZE;
  outbuf_stack.data = malloc(OUTBUFFER_STACK_SIZE*sizeof(buffer_t *));
}

// Program interface

void printCompilationInfo();
void init();
void match(int phase);

void buf_flush(buffer_t *buf)
{
  size_t word_index = buf->bitpos / BUFFER_UNIT_BITS;
  // If we do not have a single complete word to flush, return.
  // Not just an optimization! The zeroing logic below assumes word_index > 0.
  if (word_index == 0)
  {
    return;
  }
  if (fwrite(buf->data, BUFFER_UNIT_SIZE, word_index, OUTSTREAM) == -1)
  {
    fprintf(stderr, "Error writing to output stream.\n");
    exit(1);
  }
  // Since partially written words are not flushed, they need to be moved to the
  // beginning of the buffer.
  if (buf->bitpos % BUFFER_UNIT_BITS != 0)
  {
    buf->data[0] = buf->data[word_index];
  }
  else
  {
    // If we flushed everything, re-establish the invariant that the word at the
    // cursor is garbage-free by simply zeroing it.
    buf->data[0] = 0;
  }

  // Rewind cursor
  buf->bitpos = buf->bitpos - word_index * BUFFER_UNIT_BITS;
}

// Write first 'bits' of 'w' to 'buf', starting from the MOST significant bit.
// Precondition: Remaining bits of 'w' must be zero.
INLINE
bool buf_writeconst(buffer_t *buf, buffer_unit_t w, size_t bits)
{
  size_t word_index = buf->bitpos / BUFFER_UNIT_BITS;
  size_t offset = buf->bitpos % BUFFER_UNIT_BITS;
  size_t bits_available = BUFFER_UNIT_BITS - offset;

#ifdef FLAG_WORDALIGNED
  buf->data[word_index] = w;
#else
  buf->data[word_index] |= w >> offset;
  // test for offset > 0 important; shifting by the word size is undefined behaviour.
  buf->data[word_index+1] = (offset == 0) ? 0 : (w << bits_available);
#endif

  buf->bitpos += bits;

  // Is cursor in last word?
  return (buf->bitpos >= buf->size * 8 - BUFFER_UNIT_BITS);
}

void buf_resize(buffer_t *buf, size_t shift)
{
  size_t new_size = buf->size << shift;
  buffer_unit_t *data2 = calloc(new_size, 1);
  memcpy(data2, buf->data, buf->size);
  free(buf->data);
  buf->data = data2;
  buf->size = new_size;
}

INLINE
void buf_writearray(buffer_t *dst, const buffer_unit_t *arr, size_t bits)
{
  if (dst->bitpos % BUFFER_UNIT_BITS == 0)
  {
    int count = (bits / BUFFER_UNIT_BITS) + (bits % BUFFER_UNIT_BITS ? 1 : 0);
    memcpy(&dst->data[dst->bitpos / BUFFER_UNIT_BITS], arr, count * BUFFER_UNIT_SIZE);
    dst->bitpos += bits;
    dst->data[dst->bitpos / BUFFER_UNIT_BITS] = 0;
  } else
  {
    int word_index = 0;
    for (word_index = 0; word_index < bits / BUFFER_UNIT_BITS; word_index++)
    {
      buf_writeconst(dst, arr[word_index], BUFFER_UNIT_BITS);
    }

    if (bits % BUFFER_UNIT_BITS != 0)
    {
      buf_writeconst(dst, arr[word_index], bits % BUFFER_UNIT_BITS);
    }
  }
}

INLINE
void reset(buffer_t *buf)
{
  buf->data[0] = 0;
  buf->bitpos = 0;
}

void init_buffer(buffer_t *buf)
{
  buf->data = malloc(INITIAL_BUFFER_SIZE);
  buf->size = INITIAL_BUFFER_SIZE;
  buf->bitpos = 0;
  buf->data[0] = 0;
}

void destroy_buffer(buffer_t *buf)
{
  if (buf->data != NULL)
    free(buf->data);
  buf->data = NULL;
}

INLINE
void outputconst(buffer_unit_t w, size_t bits)
{
  if (buf_writeconst(outbuf_ptr, w, bits))
  {
    if (outbuf_stack.size == 0)
    {
      buf_flush(outbuf_ptr);
    }
  }
}

INLINE
void appendarray(buffer_t *dst, const buffer_unit_t *arr, size_t bits)
{
  size_t total_bits = dst->bitpos + bits;
  if (total_bits >= (dst->size - 1) * BUFFER_UNIT_BITS * BUFFER_UNIT_SIZE)
  {
    size_t shift = 1;
    while (total_bits >= ((dst->size << shift) - 1) * BUFFER_UNIT_BITS * BUFFER_UNIT_SIZE)
    {
      shift++;
    }
    buf_resize(dst, shift);
  }

  buf_writearray(dst, arr, bits);
}

INLINE
void append(buffer_t *buf, buffer_unit_t w, size_t bits)
{
  if (buf_writeconst(buf, w, bits))
  {
    buf_resize(buf, 1);
  }
}

INLINE
void concat(buffer_t *dst, buffer_t *src)
{
  appendarray(dst, src->data, src->bitpos);
}

INLINE
void outputarray(const buffer_unit_t *arr, size_t bits)
{
  int word_count = bits / BUFFER_UNIT_BITS;
  // Write completed words
  size_t word_index = 0;
  for (word_index = 0; word_index < word_count; word_index++)
  {
    outputconst(arr[word_index], BUFFER_UNIT_BITS);
  }

  int remaining = bits % BUFFER_UNIT_BITS;
  if (remaining != 0)
  {
    outputconst(arr[bits / BUFFER_UNIT_BITS], remaining);
  }
}

INLINE
void output(buffer_t *buf)
{
  outputarray(buf->data, buf->bitpos);
}

INLINE
void consume(int c)
{
  count     += c;
  in_cursor += c;
  next      += c;
}

INLINE
int readnext(int minCount, int maxCount)
{
  // We can always take epsilon transitions
  if (minCount == 0) return 1;

  if (avail < maxCount)
  {
    int remaining = avail;
    memmove(&inbuf[INBUFFER_SIZE - remaining], &inbuf[INBUFFER_SIZE+in_cursor], remaining);
    in_cursor = -remaining;
    in_size = fread(&inbuf[INBUFFER_SIZE], 1, INBUFFER_SIZE, stdin);
  }
  if (avail < minCount)
  {
    return 0;
  }
  next = &inbuf[INBUFFER_SIZE+in_cursor];
  return 1;
}

INLINE
int cmp(unsigned char *str1, unsigned char *str2, int l)
{
  int i = 0;
  for (i = 0; i < l; i++)
  {
    if (str1[i] != str2[i])
      return 0;
  }
  return 1;
}

void printUsage(char *name)
{
  fprintf(stdout, "Normal usage: %s < infile > outfile\n", name);
  fprintf(stdout, "- \"%s\": reads from stdin and writes to stdout.\n", name);
  fprintf(stdout, "- \"%s -i\": prints compilation info.\n", name);
  fprintf(stdout, "- \"%s -t\": runs normally, but prints timing to stderr.\n", name);
}

void flush_outbuf()
{
  if (outbuf.bitpos % BUFFER_UNIT_BITS != 0)
  {
    outputconst(0, BUFFER_UNIT_BITS);
  }
  if (outbuf_stack.size > 0)
  {
    fprintf(stderr, "Error: buffer stack ended non-empty\n");
    exit(1);
  }
  buf_flush(&outbuf);
  fflush(stdout);
}

void init_outbuf()
{
  outbuf.size = OUTBUFFER_SIZE + BUFFER_UNIT_SIZE;
  outbuf.data = malloc(outbuf.size);
  reset(&outbuf);
  init_outbuf_stack();
}

void run(int phase)
{
  init_outbuf();
  init();

  match(phase);

  flush_outbuf();
}

#ifndef FLAG_NOMAIN
static struct option long_options[] = {
    { "phase", required_argument, 0, 'p' },
    { 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
  bool do_timing = false;
  int c;
  int option_index = 0;
  int phase;
  bool do_phase = false;

  while ((c = getopt_long (argc, argv, "ihtp:", long_options, &option_index)) != -1)
  {
    switch (c)
    {
      case 'i':
        printCompilationInfo();
        return RETC_PRINT_INFO;
      case 't':
        do_timing = true;
        break;
      case 'p':
        phase = atoi(optarg);
        do_phase = true;
        break;
      case 'h':
      default:
        printUsage(argv[0]);
        return RETC_PRINT_USAGE;
    }
  }

  struct timeval time_before, time_after, time_result;
  long int millis;
  if(do_timing)
  {
    gettimeofday(&time_before, NULL);
  }

  if (do_phase)
  {
    run(phase);
  }
  else
  {
    // set up a pipeline
    // stdin -> prog --phase 1 -> prog --phase 2 -> ... -> prog --phase n -> stdout

    int orig_stdout = dup(STDOUT_FILENO);
    int pipes[NUM_PHASES-1][2];

    int i;
    for (i = 1; i < NUM_PHASES; i++)
    {
      if (i != 1) close(pipes[i-2][WRITE_FD]);

      if (pipe(pipes[i-1]) != 0)
      {
        fprintf(stderr, "Error creating pipe %d.", i);
        return 1;
      }
      dup2(pipes[i-1][WRITE_FD], STDOUT_FILENO);

      if (! fork())
      {
        close(orig_stdout);
        close(pipes[i-1][READ_FD]);

        // Should use snprintf, but I assume something else will break before we hit 10^19 phases.
        char phase[20] = {0};
        sprintf(phase, "%d", i);
        char *args[] = { argv[0], "--phase", phase, 0 };
        return main(3, args);
      }

      close(STDIN_FILENO);
      dup2(pipes[i-1][READ_FD], STDIN_FILENO);
    }

    #if NUM_PHASES>1
    close(pipes[NUM_PHASES-2][WRITE_FD]);
    dup2(orig_stdout, STDOUT_FILENO);
    #endif

    // Run last phase in-process
    run(NUM_PHASES);
  }

  if (do_timing)
  {
    gettimeofday(&time_after, NULL);
    timersub(&time_after, &time_before, &time_result);
    // A timeval contains seconds and microseconds.
    millis = time_result.tv_sec * 1000 + time_result.tv_usec / 1000;
    fprintf(stderr, "time (ms): %ld\n", millis);
  }

  return 0;
}
#endif

/* no tables */
buffer_t buf_0;
buffer_t buf_1;
// \xa
const buffer_unit_t const_1_0[1] = {0xa};
// A soccer match
const buffer_unit_t const_1_1[14] = {0x41,0x20,0x73,0x6f,0x63,0x63,0x65,0x72,0x20,0x6d,0x61,0x74,0x63,0x68};
// An impasta
const buffer_unit_t const_1_2[10] = {0x41,0x6e,0x20,0x69,0x6d,0x70,0x61,0x73,0x74,0x61};
// Because he felt crummy
const buffer_unit_t const_1_3[22] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x68,0x65,0x20,0x66,0x65,0x6c,0x74,0x20,0x63,0x72,0x75,0x6d,0x6d,0x79};
// Because he wanted to see time fly!
const buffer_unit_t const_1_4[34] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x68,0x65,0x20,0x77,0x61,0x6e,0x74,0x65,0x64,0x20,0x74,0x6f,0x20,0x73,0x65,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,0x66,0x6c,0x79,0x21};
// Because he was a little shellfish
const buffer_unit_t const_1_5[33] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x68,0x65,0x20,0x77,0x61,0x73,0x20,0x61,0x20,0x6c,0x69,0x74,0x74,0x6c,0x65,0x20,0x73,0x68,0x65,0x6c,0x6c,0x66,0x69,0x73,0x68};
// Because his mom and dad were in a jam.
const buffer_unit_t const_1_6[38] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x68,0x69,0x73,0x20,0x6d,0x6f,0x6d,0x20,0x61,0x6e,0x64,0x20,0x64,0x61,0x64,0x20,0x77,0x65,0x72,0x65,0x20,0x69,0x6e,0x20,0x61,0x20,0x6a,0x61,0x6d,0x2e};
// Because it's pointless.
const buffer_unit_t const_1_7[23] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x69,0x74,0x27,0x73,0x20,0x70,0x6f,0x69,0x6e,0x74,0x6c,0x65,0x73,0x73,0x2e};
// Because people are dying to get in!
const buffer_unit_t const_1_8[35] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x70,0x65,0x6f,0x70,0x6c,0x65,0x20,0x61,0x72,0x65,0x20,0x64,0x79,0x69,0x6e,0x67,0x20,0x74,0x6f,0x20,0x67,0x65,0x74,0x20,0x69,0x6e,0x21};
// Congratulations, you found the flag!
const buffer_unit_t const_1_9[36] = {0x43,0x6f,0x6e,0x67,0x72,0x61,0x74,0x75,0x6c,0x61,0x74,0x69,0x6f,0x6e,0x73,0x2c,0x20,0x79,0x6f,0x75,0x20,0x66,0x6f,0x75,0x6e,0x64,0x20,0x74,0x68,0x65,0x20,0x66,0x6c,0x61,0x67,0x21};
// Lawsuits!
const buffer_unit_t const_1_10[9] = {0x4c,0x61,0x77,0x73,0x75,0x69,0x74,0x73,0x21};
// No no, tell me a corny joke instead!\xa\xa
const buffer_unit_t const_1_11[38] = {0x4e,0x6f,0x20,0x6e,0x6f,0x2c,0x20,0x74,0x65,0x6c,0x6c,0x20,0x6d,0x65,0x20,0x61,0x20,0x63,0x6f,0x72,0x6e,0x79,0x20,0x6a,0x6f,0x6b,0x65,0x20,0x69,0x6e,0x73,0x74,0x65,0x61,0x64,0x21,0xa,0xa};
// This is not the flag :(\xa
const buffer_unit_t const_1_12[24] = {0x54,0x68,0x69,0x73,0x20,0x69,0x73,0x20,0x6e,0x6f,0x74,0x20,0x74,0x68,0x65,0x20,0x66,0x6c,0x61,0x67,0x20,0x3a,0x28,0xa};
// You look flushed
const buffer_unit_t const_1_13[16] = {0x59,0x6f,0x75,0x20,0x6c,0x6f,0x6f,0x6b,0x20,0x66,0x6c,0x75,0x73,0x68,0x65,0x64};
void printCompilationInfo()
{
  fprintf(stdout, "Compiler info: \nUsing built-in specs.\nCOLLECT_GCC=gcc\nCOLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-linux-gnu/8/lto-wrapper\nOFFLOAD_TARGET_NAMES=nvptx-none\nOFFLOAD_TARGET_DEFAULT=1\nTarget: x86_64-linux-gnu\nConfigured with: ../src/configure -v --with-pkgversion='Debian 8.1.0-12' --with-bugurl=file:///usr/share/doc/gcc-8/README.Bugs --enable-languages=c,ada,c++,go,brig,d,fortran,objc,obj-c++ --prefix=/usr --with-gcc-major-version-only --program-suffix=-8 --program-prefix=x86_64-linux-gnu- --enable-shared --enable-linker-build-id --libexecdir=/usr/lib --without-included-gettext --enable-threads=posix --libdir=/usr/lib --enable-nls --with-sysroot=/ --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --with-default-libstdcxx-abi=new --enable-gnu-unique-object --disable-vtable-verify --enable-libmpx --enable-plugin --enable-default-pie --with-system-zlib --with-target-system-zlib --enable-objc-gc=auto --enable-multiarch --disable-werror --with-arch-32=i686 --with-abi=m64 --with-multilib-list=m32,m64,mx32 --enable-multilib --with-tune=generic --enable-offload-targets=nvptx-none --without-cuda-driver --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu\nThread model: posix\ngcc version 8.1.0 (Debian 8.1.0-12) \n\nCC cmd: \ngcc -O3 -xc -o cruiser -D FLAG_WORDALIGNED -\n\nOptions:\nSST optimization level:  3\nWord size:               UInt8T\nIdentity tables removed: False\n\nSource file: cruiser.kex\nSource md5:  6f3b6521e0da976e478726d3c0091d50\nSST states:  388\n");
}

void init()
{
init_buffer(&buf_1);
}
void match1()
{
  int i = 0;
goto l1_0;
l1_0: if (!readnext(1, 1))
      {
         goto accept1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'V')) || (('X' <= next[0]) && (next[0] <= 255)))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_11,304);
         consume(1);
         goto l1_387;
      }
      if (((avail >= 1) && ((next[0] == 'W') && 1)))
      {
         consume(1);
         goto l1_378;
      }
      goto fail1;
l1_1: if (!readnext(1, 1))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || ((11 <= next[0]) && (next[0] <= 255))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_11,304);
         consume(1);
         goto l1_387;
      }
      goto fail1;
l1_2: if (!readnext(1, 1))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || ((11 <= next[0]) && (next[0] <= 255))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         output(&buf_1);
         outputarray(const_1_0,8);
         consume(1);
         goto l1_387;
      }
      goto fail1;
l1_3: if (!readnext(1, 1))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_11,304);
         consume(1);
         goto l1_387;
      }
      if (((avail >= 1) && ((next[0] == ' ') && 1)))
      {
         consume(1);
         goto l1_134;
      }
      goto fail1;
l1_4: if (!readnext(1, 1))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_11,304);
         consume(1);
         goto l1_387;
      }
      if (((avail >= 1) && ((next[0] == ' ') && 1)))
      {
         consume(1);
         goto l1_187;
      }
      goto fail1;
l1_5: if (!readnext(1, 1))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_11,304);
         consume(1);
         goto l1_387;
      }
      if (((avail >= 1) && ((next[0] == ' ') && 1)))
      {
         consume(1);
         goto l1_188;
      }
      goto fail1;
l1_6: if (!readnext(1, 1))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_11,304);
         consume(1);
         goto l1_387;
      }
      if (((avail >= 1) && ((next[0] == ' ') && 1)))
      {
         consume(1);
         goto l1_103;
      }
      goto fail1;
l1_7: if (!readnext(1, 1))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_11,304);
         consume(1);
         goto l1_387;
      }
      if (((avail >= 1) && ((next[0] == ' ') && 1)))
      {
         consume(1);
         goto l1_122;
      }
      goto fail1;
l1_8: if (!readnext(1, 1))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_11,304);
         consume(1);
         goto l1_387;
      }
      if (((avail >= 1) && ((next[0] == ' ') && 1)))
      {
         consume(1);
         goto l1_348;
      }
      goto fail1;
l1_9: if (!readnext(1, 1))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_11,304);
         consume(1);
         goto l1_387;
      }
      if (((avail >= 1) && ((next[0] == ' ') && 1)))
      {
         consume(1);
         goto l1_189;
      }
      goto fail1;
l1_10: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_257;
       }
       goto fail1;
l1_11: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_258;
       }
       goto fail1;
l1_12: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_124;
       }
       goto fail1;
l1_13: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_191;
       }
       goto fail1;
l1_14: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_192;
       }
       goto fail1;
l1_15: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_125;
       }
       goto fail1;
l1_16: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_286;
       }
       goto fail1;
l1_17: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_119;
       }
       goto fail1;
l1_18: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_194;
       }
       goto fail1;
l1_19: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_126;
       }
       goto fail1;
l1_20: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_195;
       }
       goto fail1;
l1_21: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_351;
       }
       goto fail1;
l1_22: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_196;
       }
       goto fail1;
l1_23: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_265;
       }
       goto fail1;
l1_24: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_198;
       }
       goto fail1;
l1_25: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_199;
       }
       goto fail1;
l1_26: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_289;
       }
       goto fail1;
l1_27: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_201;
       }
       goto fail1;
l1_28: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_268;
       }
       goto fail1;
l1_29: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_127;
       }
       goto fail1;
l1_30: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_202;
       }
       goto fail1;
l1_31: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_291;
       }
       goto fail1;
l1_32: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_203;
       }
       goto fail1;
l1_33: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_204;
       }
       goto fail1;
l1_34: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_176;
       }
       goto fail1;
l1_35: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_128;
       }
       goto fail1;
l1_36: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_90;
       }
       goto fail1;
l1_37: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_105;
       }
       goto fail1;
l1_38: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_92;
       }
       goto fail1;
l1_39: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_208;
       }
       goto fail1;
l1_40: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_209;
       }
       goto fail1;
l1_41: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_147;
       }
       goto fail1;
l1_42: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_296;
       }
       goto fail1;
l1_43: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_297;
       }
       goto fail1;
l1_44: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_210;
       }
       goto fail1;
l1_45: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_324;
       }
       goto fail1;
l1_46: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_63;
       }
       goto fail1;
l1_47: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_96;
       }
       goto fail1;
l1_48: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_129;
       }
       goto fail1;
l1_49: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_298;
       }
       goto fail1;
l1_50: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_299;
       }
       goto fail1;
l1_51: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_99;
       }
       goto fail1;
l1_52: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_362;
       }
       goto fail1;
l1_53: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_304;
       }
       goto fail1;
l1_54: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_120;
       }
       goto fail1;
l1_55: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_100;
       }
       goto fail1;
l1_56: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_353;
       }
       goto fail1;
l1_57: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_354;
       }
       goto fail1;
l1_58: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == ' ') && 1)))
       {
          consume(1);
          goto l1_160;
       }
       goto fail1;
l1_59: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'e')) || (('g' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'f') && 1)))
       {
          consume(1);
          goto l1_64;
       }
       goto fail1;
l1_60: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'e')) || (('g' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'f') && 1)))
       {
          consume(1);
          goto l1_111;
       }
       goto fail1;
l1_61: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'e')) || (('g' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'f') && 1)))
       {
          consume(1);
          goto l1_80;
       }
       goto fail1;
l1_62: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'e')) || (('g' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'f') && 1)))
       {
          consume(1);
          goto l1_9;
       }
       goto fail1;
l1_63: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'e')) || (('g' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'f') && 1)))
       {
          consume(1);
          goto l1_95;
       }
       goto fail1;
l1_64: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_78;
       }
       goto fail1;
l1_65: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_306;
       }
       goto fail1;
l1_66: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_315;
       }
       goto fail1;
l1_67: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_259;
       }
       goto fail1;
l1_68: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_227;
       }
       goto fail1;
l1_69: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_232;
       }
       goto fail1;
l1_70: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_219;
       }
       goto fail1;
l1_71: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_234;
       }
       goto fail1;
l1_72: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_71;
       }
       goto fail1;
l1_73: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_365;
       }
       goto fail1;
l1_74: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_164;
       }
       goto fail1;
l1_75: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_47;
       }
       goto fail1;
l1_76: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_75;
       }
       goto fail1;
l1_77: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'l') && 1)))
       {
          consume(1);
          goto l1_167;
       }
       goto fail1;
l1_78: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_101;
       }
       goto fail1;
l1_79: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_121;
       }
       goto fail1;
l1_80: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_60;
       }
       goto fail1;
l1_81: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_65;
       }
       goto fail1;
l1_82: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_350;
       }
       goto fail1;
l1_83: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_118;
       }
       goto fail1;
l1_84: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_334;
       }
       goto fail1;
l1_85: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_352;
       }
       goto fail1;
l1_86: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_159;
       }
       goto fail1;
l1_87: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_72;
       }
       goto fail1;
l1_88: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_281;
       }
       goto fail1;
l1_89: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_338;
       }
       goto fail1;
l1_90: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_339;
       }
       goto fail1;
l1_91: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_207;
       }
       goto fail1;
l1_92: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_37;
       }
       goto fail1;
l1_93: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_294;
       }
       goto fail1;
l1_94: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_342;
       }
       goto fail1;
l1_95: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_282;
       }
       goto fail1;
l1_96: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_46;
       }
       goto fail1;
l1_97: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_76;
       }
       goto fail1;
l1_98: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_166;
       }
       goto fail1;
l1_99: if (!readnext(1, 1))
       {
          goto fail1;
       }
       if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
       {
          consume(1);
          goto l1_1;
       }
       if (((avail >= 1) && ((next[0] == 10) && 1)))
       {
          outputarray(const_1_11,304);
          consume(1);
          goto l1_387;
       }
       if (((avail >= 1) && ((next[0] == 'a') && 1)))
       {
          consume(1);
          goto l1_50;
       }
       goto fail1;
l1_100: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || (('b' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'a') && 1)))
        {
           consume(1);
           goto l1_54;
        }
        goto fail1;
l1_101: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'f')) || (('h' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'g') && 1)))
        {
           consume(1);
           goto l1_107;
        }
        goto fail1;
l1_102: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'f')) || (('h' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'g') && 1)))
        {
           consume(1);
           goto l1_308;
        }
        goto fail1;
l1_103: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'f')) || (('h' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'g') && 1)))
        {
           consume(1);
           goto l1_253;
        }
        goto fail1;
l1_104: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'f')) || (('h' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'g') && 1)))
        {
           consume(1);
           goto l1_217;
        }
        goto fail1;
l1_105: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'f')) || (('h' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'g') && 1)))
        {
           consume(1);
           goto l1_91;
        }
        goto fail1;
l1_106: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'f')) || (('h' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'g') && 1)))
        {
           consume(1);
           goto l1_151;
        }
        goto fail1;
l1_107: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'z')) || (('|' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '{') && 1)))
        {
           consume(1);
           goto l1_109;
        }
        goto fail1;
l1_108: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '|')) || (('~' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '}') && 1)))
        {
           reset(&buf_1);
           appendarray(&buf_1,const_1_9,288);
           consume(1);
           goto l1_2;
        }
        goto fail1;
l1_109: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '7')) || (('9' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '8') && 1)))
        {
           consume(1);
           goto l1_61;
        }
        goto fail1;
l1_110: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '1')) || (('3' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '2') && 1)))
        {
           consume(1);
           goto l1_116;
        }
        goto fail1;
l1_111: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '1')) || (('3' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '2') && 1)))
        {
           consume(1);
           goto l1_114;
        }
        goto fail1;
l1_112: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '2')) || (('4' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '3') && 1)))
        {
           consume(1);
           goto l1_133;
        }
        goto fail1;
l1_113: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '2')) || (('4' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '3') && 1)))
        {
           consume(1);
           goto l1_110;
        }
        goto fail1;
l1_114: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '2')) || (('4' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '3') && 1)))
        {
           consume(1);
           goto l1_115;
        }
        goto fail1;
l1_115: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '4')) || (('6' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '5') && 1)))
        {
           consume(1);
           goto l1_113;
        }
        goto fail1;
l1_116: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'a')) || (('c' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'b') && 1)))
        {
           consume(1);
           goto l1_79;
        }
        goto fail1;
l1_117: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'a')) || (('c' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'b') && 1)))
        {
           consume(1);
           goto l1_225;
        }
        goto fail1;
l1_118: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'a')) || (('c' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'b') && 1)))
        {
           consume(1);
           goto l1_157;
        }
        goto fail1;
l1_119: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'a')) || (('c' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'b') && 1)))
        {
           consume(1);
           goto l1_83;
        }
        goto fail1;
l1_120: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'a')) || (('c' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'b') && 1)))
        {
           consume(1);
           goto l1_345;
        }
        goto fail1;
l1_121: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_112;
        }
        goto fail1;
l1_122: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_255;
        }
        goto fail1;
l1_123: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_280;
        }
        goto fail1;
l1_124: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_67;
        }
        goto fail1;
l1_125: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_329;
        }
        goto fail1;
l1_126: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_262;
        }
        goto fail1;
l1_127: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_144;
        }
        goto fail1;
l1_128: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_239;
        }
        goto fail1;
l1_129: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_97;
        }
        goto fail1;
l1_130: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_247;
        }
        goto fail1;
l1_131: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_130;
        }
        goto fail1;
l1_132: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'b')) || (('d' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'c') && 1)))
        {
           consume(1);
           goto l1_168;
        }
        goto fail1;
l1_133: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '3')) || (('5' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '4') && 1)))
        {
           consume(1);
           goto l1_108;
        }
        goto fail1;
l1_134: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_251;
        }
        goto fail1;
l1_135: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_220;
        }
        goto fail1;
l1_136: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_222;
        }
        goto fail1;
l1_137: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_223;
        }
        goto fail1;
l1_138: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_224;
        }
        goto fail1;
l1_139: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_328;
        }
        goto fail1;
l1_140: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_318;
        }
        goto fail1;
l1_141: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_226;
        }
        goto fail1;
l1_142: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_230;
        }
        goto fail1;
l1_143: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_231;
        }
        goto fail1;
l1_144: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_87;
        }
        goto fail1;
l1_145: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_175;
        }
        goto fail1;
l1_146: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_242;
        }
        goto fail1;
l1_147: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_178;
        }
        goto fail1;
l1_148: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_94;
        }
        goto fail1;
l1_149: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_343;
        }
        goto fail1;
l1_150: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_245;
        }
        goto fail1;
l1_151: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_213;
        }
        goto fail1;
l1_152: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_55;
        }
        goto fail1;
l1_153: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_278;
        }
        goto fail1;
l1_154: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'x')) || (('z' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'y') && 1)))
        {
           consume(1);
           goto l1_14;
        }
        goto fail1;
l1_155: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'x')) || (('z' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'y') && 1)))
        {
           consume(1);
           goto l1_172;
        }
        goto fail1;
l1_156: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'x')) || (('z' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'y') && 1)))
        {
           consume(1);
           goto l1_15;
        }
        goto fail1;
l1_157: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'x')) || (('z' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'y') && 1)))
        {
           consume(1);
           goto l1_16;
        }
        goto fail1;
l1_158: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'x')) || (('z' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'y') && 1)))
        {
           consume(1);
           goto l1_229;
        }
        goto fail1;
l1_159: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'x')) || (('z' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'y') && 1)))
        {
           consume(1);
           goto l1_25;
        }
        goto fail1;
l1_160: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'x')) || (('z' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'y') && 1)))
        {
           consume(1);
           goto l1_277;
        }
        goto fail1;
l1_161: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'c')) || (('e' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'd') && 1)))
        {
           consume(1);
           goto l1_256;
        }
        goto fail1;
l1_162: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'c')) || (('e' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'd') && 1)))
        {
           consume(1);
           goto l1_28;
        }
        goto fail1;
l1_163: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'c')) || (('e' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'd') && 1)))
        {
           consume(1);
           goto l1_35;
        }
        goto fail1;
l1_164: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'c')) || (('e' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'd') && 1)))
        {
           consume(1);
           goto l1_323;
        }
        goto fail1;
l1_165: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'c')) || (('e' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'd') && 1)))
        {
           consume(1);
           goto l1_70;
        }
        goto fail1;
l1_166: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'c')) || (('e' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'd') && 1)))
        {
           consume(1);
           goto l1_180;
        }
        goto fail1;
l1_167: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'c')) || (('e' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'd') && 1)))
        {
           consume(1);
           goto l1_327;
        }
        goto fail1;
l1_168: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_66;
        }
        goto fail1;
l1_169: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_186;
        }
        goto fail1;
l1_170: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_221;
        }
        goto fail1;
l1_171: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_316;
        }
        goto fail1;
l1_172: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_319;
        }
        goto fail1;
l1_173: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_68;
        }
        goto fail1;
l1_174: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_69;
        }
        goto fail1;
l1_175: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_290;
        }
        goto fail1;
l1_176: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_205;
        }
        goto fail1;
l1_177: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_237;
        }
        goto fail1;
l1_178: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_295;
        }
        goto fail1;
l1_179: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_368;
        }
        goto fail1;
l1_180: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_361;
        }
        goto fail1;
l1_181: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_106;
        }
        goto fail1;
l1_182: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_214;
        }
        goto fail1;
l1_183: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_215;
        }
        goto fail1;
l1_184: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_309;
        }
        goto fail1;
l1_185: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_310;
        }
        goto fail1;
l1_186: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_81;
        }
        goto fail1;
l1_187: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_135;
        }
        goto fail1;
l1_188: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_252;
        }
        goto fail1;
l1_189: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_137;
        }
        goto fail1;
l1_190: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_10;
        }
        goto fail1;
l1_191: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_138;
        }
        goto fail1;
l1_192: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_139;
        }
        goto fail1;
l1_193: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_332;
        }
        goto fail1;
l1_194: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_141;
        }
        goto fail1;
l1_195: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_263;
        }
        goto fail1;
l1_196: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_264;
        }
        goto fail1;
l1_197: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_142;
        }
        goto fail1;
l1_198: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_143;
        }
        goto fail1;
l1_199: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_266;
        }
        goto fail1;
l1_200: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_26;
        }
        goto fail1;
l1_201: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_267;
        }
        goto fail1;
l1_202: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_145;
        }
        goto fail1;
l1_203: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_270;
        }
        goto fail1;
l1_204: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_88;
        }
        goto fail1;
l1_205: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_33;
        }
        goto fail1;
l1_206: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_89;
        }
        goto fail1;
l1_207: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_240;
        }
        goto fail1;
l1_208: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_146;
        }
        goto fail1;
l1_209: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_341;
        }
        goto fail1;
l1_210: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_150;
        }
        goto fail1;
l1_211: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_44;
        }
        goto fail1;
l1_212: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_98;
        }
        goto fail1;
l1_213: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_300;
        }
        goto fail1;
l1_214: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_152;
        }
        goto fail1;
l1_215: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_250;
        }
        goto fail1;
l1_216: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_58;
        }
        goto fail1;
l1_217: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_305;
        }
        goto fail1;
l1_218: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_312;
        }
        goto fail1;
l1_219: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_313;
        }
        goto fail1;
l1_220: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_3;
        }
        goto fail1;
l1_221: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_6;
        }
        goto fail1;
l1_222: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_7;
        }
        goto fail1;
l1_223: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_8;
        }
        goto fail1;
l1_224: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_12;
        }
        goto fail1;
l1_225: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_331;
        }
        goto fail1;
l1_226: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_17;
        }
        goto fail1;
l1_227: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_185;
        }
        goto fail1;
l1_228: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_84;
        }
        goto fail1;
l1_229: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_335;
        }
        goto fail1;
l1_230: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_336;
        }
        goto fail1;
l1_231: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_23;
        }
        goto fail1;
l1_232: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_200;
        }
        goto fail1;
l1_233: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_27;
        }
        goto fail1;
l1_234: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_321;
        }
        goto fail1;
l1_235: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_30;
        }
        goto fail1;
l1_236: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_32;
        }
        goto fail1;
l1_237: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_284;
        }
        goto fail1;
l1_238: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_206;
        }
        goto fail1;
l1_239: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_367;
        }
        goto fail1;
l1_240: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_36;
        }
        goto fail1;
l1_241: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_38;
        }
        goto fail1;
l1_242: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_340;
        }
        goto fail1;
l1_243: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_93;
        }
        goto fail1;
l1_244: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_41;
        }
        goto fail1;
l1_245: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_43;
        }
        goto fail1;
l1_246: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_45;
        }
        goto fail1;
l1_247: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_344;
        }
        goto fail1;
l1_248: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_325;
        }
        goto fail1;
l1_249: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_326;
        }
        goto fail1;
l1_250: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_56;
        }
        goto fail1;
l1_251: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_285;
        }
        goto fail1;
l1_252: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_4;
        }
        goto fail1;
l1_253: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_5;
        }
        goto fail1;
l1_254: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_279;
        }
        goto fail1;
l1_255: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_254;
        }
        goto fail1;
l1_256: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_347;
        }
        goto fail1;
l1_257: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_62;
        }
        goto fail1;
l1_258: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_355;
        }
        goto fail1;
l1_259: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_123;
        }
        goto fail1;
l1_260: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_349;
        }
        goto fail1;
l1_261: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_140;
        }
        goto fail1;
l1_262: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_356;
        }
        goto fail1;
l1_263: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_19;
        }
        goto fail1;
l1_264: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_173;
        }
        goto fail1;
l1_265: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_197;
        }
        goto fail1;
l1_266: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_24;
        }
        goto fail1;
l1_267: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_174;
        }
        goto fail1;
l1_268: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_320;
        }
        goto fail1;
l1_269: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_73;
        }
        goto fail1;
l1_270: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_31;
        }
        goto fail1;
l1_271: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_357;
        }
        goto fail1;
l1_272: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_165;
        }
        goto fail1;
l1_273: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_272;
        }
        goto fail1;
l1_274: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_360;
        }
        goto fail1;
l1_275: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_131;
        }
        goto fail1;
l1_276: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_283;
        }
        goto fail1;
l1_277: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_363;
        }
        goto fail1;
l1_278: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_364;
        }
        goto fail1;
l1_279: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'j')) || (('l' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'k') && 1)))
        {
           consume(1);
           goto l1_170;
        }
        goto fail1;
l1_280: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'j')) || (('l' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'k') && 1)))
        {
           consume(1);
           goto l1_11;
        }
        goto fail1;
l1_281: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'j')) || (('l' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'k') && 1)))
        {
           consume(1);
           goto l1_236;
        }
        goto fail1;
l1_282: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'j')) || (('l' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'k') && 1)))
        {
           consume(1);
           goto l1_246;
        }
        goto fail1;
l1_283: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'j')) || (('l' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'k') && 1)))
        {
           consume(1);
           goto l1_249;
        }
        goto fail1;
l1_284: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_311;
        }
        goto fail1;
l1_285: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_301;
        }
        goto fail1;
l1_286: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_193;
        }
        goto fail1;
l1_287: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_18;
        }
        goto fail1;
l1_288: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_21;
        }
        goto fail1;
l1_289: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_86;
        }
        goto fail1;
l1_290: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_29;
        }
        goto fail1;
l1_291: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_269;
        }
        goto fail1;
l1_292: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_34;
        }
        goto fail1;
l1_293: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_39;
        }
        goto fail1;
l1_294: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_358;
        }
        goto fail1;
l1_295: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_40;
        }
        goto fail1;
l1_296: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_148;
        }
        goto fail1;
l1_297: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_149;
        }
        goto fail1;
l1_298: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_212;
        }
        goto fail1;
l1_299: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_275;
        }
        goto fail1;
l1_300: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'r')) || (('t' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_52;
        }
        goto fail1;
l1_301: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'o')) || (('q' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'p') && 1)))
        {
           consume(1);
           goto l1_169;
        }
        goto fail1;
l1_302: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'o')) || (('q' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'p') && 1)))
        {
           consume(1);
           goto l1_42;
        }
        goto fail1;
l1_303: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'o')) || (('q' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'p') && 1)))
        {
           consume(1);
           goto l1_51;
        }
        goto fail1;
l1_304: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'o')) || (('q' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'p') && 1)))
        {
           consume(1);
           goto l1_248;
        }
        goto fail1;
l1_305: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '>')) || (('@' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '?') && 1)))
        {
           consume(1);
           goto l1_371;
        }
        goto fail1;
l1_306: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '>')) || (('@' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '?') && 1)))
        {
           reset(&buf_1);
           appendarray(&buf_1,const_1_3,176);
           consume(1);
           goto l1_2;
        }
        goto fail1;
l1_307: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '>')) || (('@' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '?') && 1)))
        {
           reset(&buf_1);
           appendarray(&buf_1,const_1_4,272);
           consume(1);
           goto l1_2;
        }
        goto fail1;
l1_308: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '>')) || (('@' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '?') && 1)))
        {
           reset(&buf_1);
           appendarray(&buf_1,const_1_6,304);
           consume(1);
           goto l1_2;
        }
        goto fail1;
l1_309: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '>')) || (('@' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '?') && 1)))
        {
           reset(&buf_1);
           appendarray(&buf_1,const_1_10,72);
           consume(1);
           goto l1_2;
        }
        goto fail1;
l1_310: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '>')) || (('@' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '?') && 1)))
        {
           reset(&buf_1);
           appendarray(&buf_1,const_1_13,128);
           consume(1);
           goto l1_2;
        }
        goto fail1;
l1_311: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '>')) || (('@' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '?') && 1)))
        {
           reset(&buf_1);
           appendarray(&buf_1,const_1_8,280);
           consume(1);
           goto l1_2;
        }
        goto fail1;
l1_312: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '>')) || (('@' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '?') && 1)))
        {
           reset(&buf_1);
           appendarray(&buf_1,const_1_5,264);
           consume(1);
           goto l1_2;
        }
        goto fail1;
l1_313: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '>')) || (('@' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '?') && 1)))
        {
           reset(&buf_1);
           appendarray(&buf_1,const_1_2,80);
           consume(1);
           goto l1_2;
        }
        goto fail1;
l1_314: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '>')) || (('@' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '?') && 1)))
        {
           reset(&buf_1);
           appendarray(&buf_1,const_1_1,112);
           consume(1);
           goto l1_2;
        }
        goto fail1;
l1_315: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '>')) || (('@' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == '?') && 1)))
        {
           reset(&buf_1);
           appendarray(&buf_1,const_1_7,184);
           consume(1);
           goto l1_2;
        }
        goto fail1;
l1_316: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_161;
        }
        goto fail1;
l1_317: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_154;
        }
        goto fail1;
l1_318: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_317;
        }
        goto fail1;
l1_319: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_102;
        }
        goto fail1;
l1_320: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_233;
        }
        goto fail1;
l1_321: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_104;
        }
        goto fail1;
l1_322: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_163;
        }
        goto fail1;
l1_323: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_369;
        }
        goto fail1;
l1_324: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_273;
        }
        goto fail1;
l1_325: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_132;
        }
        goto fail1;
l1_326: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_53;
        }
        goto fail1;
l1_327: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'm')) || (('o' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'n') && 1)))
        {
           consume(1);
           goto l1_370;
        }
        goto fail1;
l1_328: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_260;
        }
        goto fail1;
l1_329: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_155;
        }
        goto fail1;
l1_330: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_156;
        }
        goto fail1;
l1_331: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_330;
        }
        goto fail1;
l1_332: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_82;
        }
        goto fail1;
l1_333: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_184;
        }
        goto fail1;
l1_334: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_20;
        }
        goto fail1;
l1_335: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_288;
        }
        goto fail1;
l1_336: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_22;
        }
        goto fail1;
l1_337: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_218;
        }
        goto fail1;
l1_338: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_177;
        }
        goto fail1;
l1_339: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_271;
        }
        goto fail1;
l1_340: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_241;
        }
        goto fail1;
l1_341: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_243;
        }
        goto fail1;
l1_342: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_244;
        }
        goto fail1;
l1_343: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_179;
        }
        goto fail1;
l1_344: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_49;
        }
        goto fail1;
l1_345: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_276;
        }
        goto fail1;
l1_346: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'q')) || (('s' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'r') && 1)))
        {
           consume(1);
           goto l1_183;
        }
        goto fail1;
l1_347: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'v')) || (('x' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'w') && 1)))
        {
           consume(1);
           goto l1_307;
        }
        goto fail1;
l1_348: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'v')) || (('x' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'w') && 1)))
        {
           consume(1);
           goto l1_171;
        }
        goto fail1;
l1_349: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'v')) || (('x' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'w') && 1)))
        {
           consume(1);
           goto l1_13;
        }
        goto fail1;
l1_350: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'v')) || (('x' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'w') && 1)))
        {
           consume(1);
           goto l1_117;
        }
        goto fail1;
l1_351: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'v')) || (('x' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'w') && 1)))
        {
           consume(1);
           goto l1_228;
        }
        goto fail1;
l1_352: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'v')) || (('x' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'w') && 1)))
        {
           consume(1);
           goto l1_158;
        }
        goto fail1;
l1_353: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'v')) || (('x' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'w') && 1)))
        {
           consume(1);
           goto l1_182;
        }
        goto fail1;
l1_354: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'v')) || (('x' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'w') && 1)))
        {
           consume(1);
           goto l1_346;
        }
        goto fail1;
l1_355: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 't')) || (('v' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'u') && 1)))
        {
           consume(1);
           goto l1_190;
        }
        goto fail1;
l1_356: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 't')) || (('v' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'u') && 1)))
        {
           consume(1);
           goto l1_333;
        }
        goto fail1;
l1_357: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 't')) || (('v' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'u') && 1)))
        {
           consume(1);
           goto l1_322;
        }
        goto fail1;
l1_358: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 't')) || (('v' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'u') && 1)))
        {
           consume(1);
           goto l1_337;
        }
        goto fail1;
l1_359: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 't')) || (('v' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'u') && 1)))
        {
           consume(1);
           goto l1_74;
        }
        goto fail1;
l1_360: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 't')) || (('v' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'u') && 1)))
        {
           consume(1);
           goto l1_48;
        }
        goto fail1;
l1_361: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 't')) || (('v' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'u') && 1)))
        {
           consume(1);
           goto l1_366;
        }
        goto fail1;
l1_362: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 't')) || (('v' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'u') && 1)))
        {
           consume(1);
           goto l1_303;
        }
        goto fail1;
l1_363: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 't')) || (('v' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'u') && 1)))
        {
           consume(1);
           goto l1_57;
        }
        goto fail1;
l1_364: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 't')) || (('v' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'u') && 1)))
        {
           consume(1);
           goto l1_77;
        }
        goto fail1;
l1_365: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'u')) || (('w' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'v') && 1)))
        {
           consume(1);
           goto l1_235;
        }
        goto fail1;
l1_366: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'l')) || (('n' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'm') && 1)))
        {
           consume(1);
           goto l1_314;
        }
        goto fail1;
l1_367: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'l')) || (('n' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'm') && 1)))
        {
           consume(1);
           goto l1_238;
        }
        goto fail1;
l1_368: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'l')) || (('n' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'm') && 1)))
        {
           consume(1);
           goto l1_302;
        }
        goto fail1;
l1_369: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '&')) || (('(' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 39) && 1)))
        {
           consume(1);
           goto l1_211;
        }
        goto fail1;
l1_370: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '&')) || (('(' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 39) && 1)))
        {
           consume(1);
           goto l1_216;
        }
        goto fail1;
l1_371: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_12,192);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == ' ') && 1)))
        {
           consume(1);
           goto l1_59;
        }
        goto fail1;
l1_372: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == ' ') && 1)))
        {
           consume(1);
           goto l1_384;
        }
        goto fail1;
l1_373: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == ' ') && 1)))
        {
           consume(1);
           goto l1_381;
        }
        goto fail1;
l1_374: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || ((('!' <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255))))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == ' ') && 1)))
        {
           consume(1);
           goto l1_376;
        }
        if (((avail >= 1) && ((next[0] == 'e') && 1)))
        {
           consume(1);
           goto l1_292;
        }
        goto fail1;
l1_375: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 31)) || (('!' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == ' ') && 1)))
        {
           consume(1);
           goto l1_382;
        }
        goto fail1;
l1_376: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'k')) || ((('m' <= next[0]) && (next[0] <= 'x')) || (('z' <= next[0]) && (next[0] <= 255))))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'l') && 1)))
        {
           consume(1);
           goto l1_85;
        }
        if (((avail >= 1) && ((next[0] == 'y') && 1)))
        {
           consume(1);
           goto l1_274;
        }
        goto fail1;
l1_377: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || ((('b' <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255))))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'a') && 1)))
        {
           consume(1);
           goto l1_287;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_359;
        }
        goto fail1;
l1_378: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'g')) || (('i' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'h') && 1)))
        {
           consume(1);
           goto l1_379;
        }
        goto fail1;
l1_379: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '`')) || ((('b' <= next[0]) && (next[0] <= 'x')) || (('z' <= next[0]) && (next[0] <= 255))))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'a') && 1)))
        {
           consume(1);
           goto l1_385;
        }
        if (((avail >= 1) && ((next[0] == 'y') && 1)))
        {
           consume(1);
           goto l1_373;
        }
        goto fail1;
l1_380: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'c')) || (('e' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'd') && 1)))
        {
           consume(1);
           goto l1_372;
        }
        goto fail1;
l1_381: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'c')) || ((('e' <= next[0]) && (next[0] <= 'h')) || ((('j' <= next[0]) && (next[0] <= 'r')) || ((('t' <= next[0]) && (next[0] <= 'v')) || (('x' <= next[0]) && (next[0] <= 255))))))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'd') && 1)))
        {
           consume(1);
           goto l1_383;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_293;
        }
        if (((avail >= 1) && ((next[0] == 's') && 1)))
        {
           consume(1);
           goto l1_153;
        }
        if (((avail >= 1) && ((next[0] == 'w') && 1)))
        {
           consume(1);
           goto l1_377;
        }
        goto fail1;
l1_382: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'c')) || ((('e' <= next[0]) && (next[0] <= 'k')) || (('m' <= next[0]) && (next[0] <= 255))))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'd') && 1)))
        {
           consume(1);
           goto l1_386;
        }
        if (((avail >= 1) && ((next[0] == 'l') && 1)))
        {
           consume(1);
           goto l1_181;
        }
        goto fail1;
l1_383: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_380;
        }
        goto fail1;
l1_384: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'I')) || ((('K' <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255))))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'J') && 1)))
        {
           consume(1);
           goto l1_261;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_136;
        }
        goto fail1;
l1_385: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 's')) || (('u' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 't') && 1)))
        {
           consume(1);
           goto l1_375;
        }
        goto fail1;
l1_386: if (!readnext(1, 1))
        {
           goto fail1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'h')) || ((('j' <= next[0]) && (next[0] <= 'n')) || (('p' <= next[0]) && (next[0] <= 255))))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'i') && 1)))
        {
           consume(1);
           goto l1_162;
        }
        if (((avail >= 1) && ((next[0] == 'o') && 1)))
        {
           consume(1);
           goto l1_374;
        }
        goto fail1;
l1_387: if (!readnext(1, 1))
        {
           goto accept1;
        }
        if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'V')) || (('X' <= next[0]) && (next[0] <= 255)))) && 1)))
        {
           consume(1);
           goto l1_1;
        }
        if (((avail >= 1) && ((next[0] == 10) && 1)))
        {
           outputarray(const_1_11,304);
           consume(1);
           goto l1_387;
        }
        if (((avail >= 1) && ((next[0] == 'W') && 1)))
        {
           consume(1);
           goto l1_378;
        }
        goto fail1;
  accept1:
    return;
  fail1:
    fprintf(stderr, "Match error at input symbol %zu!\n", count);
    exit(1);
}

void match(int phase)
{
  switch(phase) {
    case 1: match1(); break;
    default:
      fprintf(stderr, "Invalid phase: %d given\n", phase);
      exit(1);
  }
}
