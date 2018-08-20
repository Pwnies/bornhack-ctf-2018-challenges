
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
// "Smiles", because there is a mile between each 's'
const buffer_unit_t const_1_1[50] = {0x22,0x53,0x6d,0x69,0x6c,0x65,0x73,0x22,0x2c,0x20,0x62,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x74,0x68,0x65,0x72,0x65,0x20,0x69,0x73,0x20,0x61,0x20,0x6d,0x69,0x6c,0x65,0x20,0x62,0x65,0x74,0x77,0x65,0x65,0x6e,0x20,0x65,0x61,0x63,0x68,0x20,0x27,0x73,0x27};
// 1s}
const buffer_unit_t const_1_2[3] = {0x31,0x73,0x7d};
// 33d_tO_ma
const buffer_unit_t const_1_3[9] = {0x33,0x33,0x64,0x5f,0x74,0x4f,0x5f,0x6d,0x61};
// A heavy discussion
const buffer_unit_t const_1_4[18] = {0x41,0x20,0x68,0x65,0x61,0x76,0x79,0x20,0x64,0x69,0x73,0x63,0x75,0x73,0x73,0x69,0x6f,0x6e};
// A nervous wreck
const buffer_unit_t const_1_5[15] = {0x41,0x20,0x6e,0x65,0x72,0x76,0x6f,0x75,0x73,0x20,0x77,0x72,0x65,0x63,0x6b};
// A refrigerator
const buffer_unit_t const_1_6[14] = {0x41,0x20,0x72,0x65,0x66,0x72,0x69,0x67,0x65,0x72,0x61,0x74,0x6f,0x72};
// A soccer match
const buffer_unit_t const_1_7[14] = {0x41,0x20,0x73,0x6f,0x63,0x63,0x65,0x72,0x20,0x6d,0x61,0x74,0x63,0x68};
// A trum-pet!
const buffer_unit_t const_1_8[11] = {0x41,0x20,0x74,0x72,0x75,0x6d,0x2d,0x70,0x65,0x74,0x21};
// A watch dog
const buffer_unit_t const_1_9[11] = {0x41,0x20,0x77,0x61,0x74,0x63,0x68,0x20,0x64,0x6f,0x67};
// An Investigator
const buffer_unit_t const_1_10[15] = {0x41,0x6e,0x20,0x49,0x6e,0x76,0x65,0x73,0x74,0x69,0x67,0x61,0x74,0x6f,0x72};
// An impasta
const buffer_unit_t const_1_11[10] = {0x41,0x6e,0x20,0x69,0x6d,0x70,0x61,0x73,0x74,0x61};
// Because he felt crummy
const buffer_unit_t const_1_12[22] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x68,0x65,0x20,0x66,0x65,0x6c,0x74,0x20,0x63,0x72,0x75,0x6d,0x6d,0x79};
// Because he took a short cut.
const buffer_unit_t const_1_13[28] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x68,0x65,0x20,0x74,0x6f,0x6f,0x6b,0x20,0x61,0x20,0x73,0x68,0x6f,0x72,0x74,0x20,0x63,0x75,0x74,0x2e};
// Because he wanted to see time fly!
const buffer_unit_t const_1_14[34] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x68,0x65,0x20,0x77,0x61,0x6e,0x74,0x65,0x64,0x20,0x74,0x6f,0x20,0x73,0x65,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,0x66,0x6c,0x79,0x21};
// Because he was a little shellfish
const buffer_unit_t const_1_15[33] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x68,0x65,0x20,0x77,0x61,0x73,0x20,0x61,0x20,0x6c,0x69,0x74,0x74,0x6c,0x65,0x20,0x73,0x68,0x65,0x6c,0x6c,0x66,0x69,0x73,0x68};
// Because he was out-standing in his field.
const buffer_unit_t const_1_16[41] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x68,0x65,0x20,0x77,0x61,0x73,0x20,0x6f,0x75,0x74,0x2d,0x73,0x74,0x61,0x6e,0x64,0x69,0x6e,0x67,0x20,0x69,0x6e,0x20,0x68,0x69,0x73,0x20,0x66,0x69,0x65,0x6c,0x64,0x2e};
// Because his mom and dad were in a jam.
const buffer_unit_t const_1_17[38] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x68,0x69,0x73,0x20,0x6d,0x6f,0x6d,0x20,0x61,0x6e,0x64,0x20,0x64,0x61,0x64,0x20,0x77,0x65,0x72,0x65,0x20,0x69,0x6e,0x20,0x61,0x20,0x6a,0x61,0x6d,0x2e};
// Because it was framed!
const buffer_unit_t const_1_18[22] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x69,0x74,0x20,0x77,0x61,0x73,0x20,0x66,0x72,0x61,0x6d,0x65,0x64,0x21};
// Because it's a little meteor
const buffer_unit_t const_1_19[28] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x69,0x74,0x27,0x73,0x20,0x61,0x20,0x6c,0x69,0x74,0x74,0x6c,0x65,0x20,0x6d,0x65,0x74,0x65,0x6f,0x72};
// Because it's pointless.
const buffer_unit_t const_1_20[23] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x69,0x74,0x27,0x73,0x20,0x70,0x6f,0x69,0x6e,0x74,0x6c,0x65,0x73,0x73,0x2e};
// Because of his coffin.
const buffer_unit_t const_1_21[22] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x6f,0x66,0x20,0x68,0x69,0x73,0x20,0x63,0x6f,0x66,0x66,0x69,0x6e,0x2e};
// Because people are dying to get in!
const buffer_unit_t const_1_22[35] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x70,0x65,0x6f,0x70,0x6c,0x65,0x20,0x61,0x72,0x65,0x20,0x64,0x79,0x69,0x6e,0x67,0x20,0x74,0x6f,0x20,0x67,0x65,0x74,0x20,0x69,0x6e,0x21};
// Because the chicken joke wasn't invented yet.
const buffer_unit_t const_1_23[45] = {0x42,0x65,0x63,0x61,0x75,0x73,0x65,0x20,0x74,0x68,0x65,0x20,0x63,0x68,0x69,0x63,0x6b,0x65,0x6e,0x20,0x6a,0x6f,0x6b,0x65,0x20,0x77,0x61,0x73,0x6e,0x27,0x74,0x20,0x69,0x6e,0x76,0x65,0x6e,0x74,0x65,0x64,0x20,0x79,0x65,0x74,0x2e};
// Firecrackers!
const buffer_unit_t const_1_24[13] = {0x46,0x69,0x72,0x65,0x63,0x72,0x61,0x63,0x6b,0x65,0x72,0x73,0x21};
// Frostbite
const buffer_unit_t const_1_25[9] = {0x46,0x72,0x6f,0x73,0x74,0x62,0x69,0x74,0x65};
// He neverlands!
const buffer_unit_t const_1_26[14] = {0x48,0x65,0x20,0x6e,0x65,0x76,0x65,0x72,0x6c,0x61,0x6e,0x64,0x73,0x21};
// He wanted cold hard cash!
const buffer_unit_t const_1_27[25] = {0x48,0x65,0x20,0x77,0x61,0x6e,0x74,0x65,0x64,0x20,0x63,0x6f,0x6c,0x64,0x20,0x68,0x61,0x72,0x64,0x20,0x63,0x61,0x73,0x68,0x21};
// I just love baskin' robins.
const buffer_unit_t const_1_28[27] = {0x49,0x20,0x6a,0x75,0x73,0x74,0x20,0x6c,0x6f,0x76,0x65,0x20,0x62,0x61,0x73,0x6b,0x69,0x6e,0x27,0x20,0x72,0x6f,0x62,0x69,0x6e,0x73,0x2e};
// In the dictionary
const buffer_unit_t const_1_29[17] = {0x49,0x6e,0x20,0x74,0x68,0x65,0x20,0x64,0x69,0x63,0x74,0x69,0x6f,0x6e,0x61,0x72,0x79};
// It was two-tired!
const buffer_unit_t const_1_30[17] = {0x49,0x74,0x20,0x77,0x61,0x73,0x20,0x74,0x77,0x6f,0x2d,0x74,0x69,0x72,0x65,0x64,0x21};
// Lawsuits!
const buffer_unit_t const_1_31[9] = {0x4c,0x61,0x77,0x73,0x75,0x69,0x74,0x73,0x21};
// Look grandpa, no hands!
const buffer_unit_t const_1_32[23] = {0x4c,0x6f,0x6f,0x6b,0x20,0x67,0x72,0x61,0x6e,0x64,0x70,0x61,0x2c,0x20,0x6e,0x6f,0x20,0x68,0x61,0x6e,0x64,0x73,0x21};
// Nacho Cheese
const buffer_unit_t const_1_33[12] = {0x4e,0x61,0x63,0x68,0x6f,0x20,0x43,0x68,0x65,0x65,0x73,0x65};
// No no, tell me a corny joke instead!\xa\xa
const buffer_unit_t const_1_34[38] = {0x4e,0x6f,0x20,0x6e,0x6f,0x2c,0x20,0x74,0x65,0x6c,0x6c,0x20,0x6d,0x65,0x20,0x61,0x20,0x63,0x6f,0x72,0x6e,0x79,0x20,0x6a,0x6f,0x6b,0x65,0x20,0x69,0x6e,0x73,0x74,0x65,0x61,0x64,0x21,0xa,0xa};
// Oh Snap!
const buffer_unit_t const_1_35[8] = {0x4f,0x68,0x20,0x53,0x6e,0x61,0x70,0x21};
// Quattro Sinko
const buffer_unit_t const_1_36[13] = {0x51,0x75,0x61,0x74,0x74,0x72,0x6f,0x20,0x53,0x69,0x6e,0x6b,0x6f};
// Remorse code.
const buffer_unit_t const_1_37[13] = {0x52,0x65,0x6d,0x6f,0x72,0x73,0x65,0x20,0x63,0x6f,0x64,0x65,0x2e};
// Sue
const buffer_unit_t const_1_38[3] = {0x53,0x75,0x65};
// The Space bar!
const buffer_unit_t const_1_39[14] = {0x54,0x68,0x65,0x20,0x53,0x70,0x61,0x63,0x65,0x20,0x62,0x61,0x72,0x21};
// The dock
const buffer_unit_t const_1_40[8] = {0x54,0x68,0x65,0x20,0x64,0x6f,0x63,0x6b};
// The month of March!
const buffer_unit_t const_1_41[19] = {0x54,0x68,0x65,0x20,0x6d,0x6f,0x6e,0x74,0x68,0x20,0x6f,0x66,0x20,0x4d,0x61,0x72,0x63,0x68,0x21};
// They take the psycho path.
const buffer_unit_t const_1_42[26] = {0x54,0x68,0x65,0x79,0x20,0x74,0x61,0x6b,0x65,0x20,0x74,0x68,0x65,0x20,0x70,0x73,0x79,0x63,0x68,0x6f,0x20,0x70,0x61,0x74,0x68,0x2e};
// This is not the flag :(\xa
const buffer_unit_t const_1_43[24] = {0x54,0x68,0x69,0x73,0x20,0x69,0x73,0x20,0x6e,0x6f,0x74,0x20,0x74,0x68,0x65,0x20,0x66,0x6c,0x61,0x67,0x20,0x3a,0x28,0xa};
// Trouble
const buffer_unit_t const_1_44[7] = {0x54,0x72,0x6f,0x75,0x62,0x6c,0x65};
// You look flushed
const buffer_unit_t const_1_45[16] = {0x59,0x6f,0x75,0x20,0x6c,0x6f,0x6f,0x6b,0x20,0x66,0x6c,0x75,0x73,0x68,0x65,0x64};
// You stay here, I'll go on a head
const buffer_unit_t const_1_46[32] = {0x59,0x6f,0x75,0x20,0x73,0x74,0x61,0x79,0x20,0x68,0x65,0x72,0x65,0x2c,0x20,0x49,0x27,0x6c,0x6c,0x20,0x67,0x6f,0x20,0x6f,0x6e,0x20,0x61,0x20,0x68,0x65,0x61,0x64};
// You're too young to smoke!
const buffer_unit_t const_1_47[26] = {0x59,0x6f,0x75,0x27,0x72,0x65,0x20,0x74,0x6f,0x6f,0x20,0x79,0x6f,0x75,0x6e,0x67,0x20,0x74,0x6f,0x20,0x73,0x6d,0x6f,0x6b,0x65,0x21};
// a Vel-Crow
const buffer_unit_t const_1_48[10] = {0x61,0x20,0x56,0x65,0x6c,0x2d,0x43,0x72,0x6f,0x77};
// eed_tO_ma
const buffer_unit_t const_1_49[9] = {0x65,0x65,0x64,0x5f,0x74,0x4f,0x5f,0x6d,0x61};
// flag{U_n
const buffer_unit_t const_1_50[8] = {0x66,0x6c,0x61,0x67,0x7b,0x55,0x5f,0x6e};
// flag{you_n
const buffer_unit_t const_1_51[10] = {0x66,0x6c,0x61,0x67,0x7b,0x79,0x6f,0x75,0x5f,0x6e};
// is}
const buffer_unit_t const_1_52[3] = {0x69,0x73,0x7d};
// tZh_th
const buffer_unit_t const_1_53[6] = {0x74,0x5a,0x68,0x5f,0x74,0x68};
// tch_th
const buffer_unit_t const_1_54[6] = {0x74,0x63,0x68,0x5f,0x74,0x68};
void printCompilationInfo()
{
  fprintf(stdout, "Compiler info: \nUsing built-in specs.\nCOLLECT_GCC=gcc\nCOLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-linux-gnu/8/lto-wrapper\nOFFLOAD_TARGET_NAMES=nvptx-none\nOFFLOAD_TARGET_DEFAULT=1\nTarget: x86_64-linux-gnu\nConfigured with: ../src/configure -v --with-pkgversion='Debian 8.1.0-12' --with-bugurl=file:///usr/share/doc/gcc-8/README.Bugs --enable-languages=c,ada,c++,go,brig,d,fortran,objc,obj-c++ --prefix=/usr --with-gcc-major-version-only --program-suffix=-8 --program-prefix=x86_64-linux-gnu- --enable-shared --enable-linker-build-id --libexecdir=/usr/lib --without-included-gettext --enable-threads=posix --libdir=/usr/lib --enable-nls --with-sysroot=/ --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --with-default-libstdcxx-abi=new --enable-gnu-unique-object --disable-vtable-verify --enable-libmpx --enable-plugin --enable-default-pie --with-system-zlib --with-target-system-zlib --enable-objc-gc=auto --enable-multiarch --disable-werror --with-arch-32=i686 --with-abi=m64 --with-multilib-list=m32,m64,mx32 --enable-multilib --with-tune=generic --enable-offload-targets=nvptx-none --without-cuda-driver --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu\nThread model: posix\ngcc version 8.1.0 (Debian 8.1.0-12) \n\nCC cmd: \ngcc -O3 -xc -o cruiser -D FLAG_WORDALIGNED -\n\nOptions:\nSST optimization level:  3\nWord size:               UInt8T\nIdentity tables removed: False\n\nSource file: cruiser.kex\nSource md5:  cda43b230399454c6a76fcb32cfcf999\nSST states:  9\n");
}

void init()
{
init_buffer(&buf_1);
}
void match1()
{
  int i = 0;
goto l1_0;
l1_0: if (!readnext(1, 72))
      {
         goto accept1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'G')) || ((('I' <= next[0]) && (next[0] <= 'V')) || (('X' <= next[0]) && (next[0] <= 255))))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_34,304);
         consume(1);
         goto l1_8;
      }
      if (((avail >= 1) && ((next[0] == 'H') && 1)))
      {
         if (((avail >= '*') && (cmp(&next[1],(unsigned char *) "ow""\x20""do""\x20""crazy""\x20""people""\x20""go""\x20""through""\x20""the""\x20""forest?",41) && 1)))
         {
            reset(&buf_1);
            appendarray(&buf_1,const_1_42,208);
            consume(42);
            goto l1_2;
         }
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 'W') && 1)))
      {
         if (((avail >= 2) && ((next[1] == 'h') && 1)))
         {
            if (((avail >= 4) && (cmp(&next[2],(unsigned char *) "at",2) && 1)))
            {
               if (((avail >= 5) && ((next[4] == ' ') && 1)))
               {
                  if (((avail >= 6) && ((next[5] == 'd') && 1)))
                  {
                     if (((avail >= 9) && (cmp(&next[6],(unsigned char *) "id""\x20""",3) && 1)))
                     {
                        if (((avail >= 13) && (cmp(&next[9],(unsigned char *) "one""\x20""",4) && 1)))
                        {
                           if (((avail >= ' ') && (cmp(&next[13],(unsigned char *) "hat""\x20""say""\x20""to""\x20""another?",19) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_46,256);
                              consume(32);
                              goto l1_2;
                           }
                           if (((avail >= ',') && (cmp(&next[13],(unsigned char *) "toilet""\x20""say""\x20""to""\x20""the""\x20""other""\x20""toilet?",31) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_45,128);
                              consume(44);
                              goto l1_2;
                           }
                        }
                        if (((avail >= 13) && (cmp(&next[9],(unsigned char *) "the""\x20""",4) && 1)))
                        {
                           if (((avail >= '>') && (cmp(&next[13],(unsigned char *) "cat""\x20""say""\x20""after""\x20""eating""\x20""two""\x20""robins""\x20""lying""\x20""in""\x20""the""\x20""sun?",49) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_28,216);
                              consume(62);
                              goto l1_2;
                           }
                           if (((avail >= '8') && (cmp(&next[13],(unsigned char *) "digital""\x20""clock""\x20""say""\x20""to""\x20""the""\x20""grandfather""\x20""clock?",43) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_32,184);
                              consume(56);
                              goto l1_2;
                           }
                           if (((avail >= '6') && (cmp(&next[13],(unsigned char *) "elder""\x20""chimney""\x20""say""\x20""to""\x20""the""\x20""younger""\x20""chimney?",41) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_47,208);
                              consume(54);
                              goto l1_2;
                           }
                           if (((avail >= '&') && (cmp(&next[13],(unsigned char *) "lawyer""\x20""name""\x20""his""\x20""daughter?",25) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_38,24);
                              consume(38);
                              goto l1_2;
                           }
                           if (((avail >= 'H') && (cmp(&next[13],(unsigned char *) "worker""\x20""at""\x20""the""\x20""rubber""\x20""band""\x20""factory""\x20""say""\x20""when""\x20""he""\x20""lost""\x20""his""\x20""job?",59) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_35,64);
                              consume(72);
                              goto l1_2;
                           }
                        }
                     }
                     if (((avail >= 7) && ((next[6] == 'o') && 1)))
                     {
                        if (((avail >= 8) && ((next[7] == ' ') && 1)))
                        {
                           if (((avail >= 30) && (cmp(&next[8],(unsigned char *) "lawyers""\x20""wear""\x20""to""\x20""court?",22) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_31,72);
                              consume(30);
                              goto l1_2;
                           }
                           if (((avail >= 12) && (cmp(&next[8],(unsigned char *) "you""\x20""",4) && 1)))
                           {
                              if (((avail >= 17) && (cmp(&next[12],(unsigned char *) "call""\x20""",5) && 1)))
                              {
                                 if (((avail >= 18) && ((next[17] == 'a') && 1)))
                                 {
                                    if (((avail >= 31) && (cmp(&next[18],(unsigned char *) """\x20""fake""\x20""noodle?",13) && 1)))
                                    {
                                       reset(&buf_1);
                                       appendarray(&buf_1,const_1_11,80);
                                       consume(31);
                                       goto l1_2;
                                    }
                                    if (((avail >= 21) && (cmp(&next[18],(unsigned char *) "n""\x20""a",3) && 1)))
                                    {
                                       if (((avail >= '(') && (cmp(&next[21],(unsigned char *) "lligator""\x20""in""\x20""a""\x20""vest?",19) && 1)))
                                       {
                                          reset(&buf_1);
                                          appendarray(&buf_1,const_1_10,120);
                                          consume(40);
                                          goto l1_2;
                                       }
                                       if (((avail >= '7') && (cmp(&next[21],(unsigned char *) "pology""\x20""written""\x20""in""\x20""dots""\x20""and""\x20""dashes?",34) && 1)))
                                       {
                                          reset(&buf_1);
                                          appendarray(&buf_1,const_1_37,104);
                                          consume(55);
                                          goto l1_2;
                                       }
                                    }
                                 }
                                 if (((avail >= ')') && (cmp(&next[17],(unsigned char *) "cheese""\x20""that""\x20""isn't""\x20""yours?",24) && 1)))
                                 {
                                    reset(&buf_1);
                                    appendarray(&buf_1,const_1_33,96);
                                    consume(41);
                                    goto l1_2;
                                 }
                                 if (((avail >= '9') && (cmp(&next[17],(unsigned char *) "four""\x20""bullfighters""\x20""standing""\x20""in""\x20""quicksand?",40) && 1)))
                                 {
                                    reset(&buf_1);
                                    appendarray(&buf_1,const_1_36,104);
                                    consume(57);
                                    goto l1_2;
                                 }
                                 if (((avail >= '.') && (cmp(&next[17],(unsigned char *) "two""\x20""fat""\x20""people""\x20""having""\x20""a""\x20""chat?",29) && 1)))
                                 {
                                    reset(&buf_1);
                                    appendarray(&buf_1,const_1_4,144);
                                    consume(46);
                                    goto l1_2;
                                 }
                              }
                              if (((avail >= '8') && (cmp(&next[12],(unsigned char *) "get""\x20""when""\x20""you""\x20""cross""\x20""a""\x20""snowman""\x20""with""\x20""a""\x20""vampire?",44) && 1)))
                              {
                                 reset(&buf_1);
                                 appendarray(&buf_1,const_1_25,72);
                                 consume(56);
                                 goto l1_2;
                              }
                           }
                        }
                        if (((avail >= '*') && (cmp(&next[7],(unsigned char *) "es""\x20""it""\x20""take""\x20""to""\x20""solve""\x20""this""\x20""challenge?",35) && 1)))
                        {
                           consume(42);
                           goto l1_3;
                        }
                        if (((avail >= 29) && (cmp(&next[7],(unsigned char *) "g""\x20""keeps""\x20""the""\x20""best""\x20""time?",22) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_9,88);
                           consume(29);
                           goto l1_2;
                        }
                     }
                  }
                  if (((avail >= '4') && (cmp(&next[5],(unsigned char *) "is""\x20""an""\x20""astronaut's""\x20""favorite""\x20""place""\x20""on""\x20""a""\x20""computer?",47) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_39,112);
                     consume(52);
                     goto l1_2;
                  }
                  if (((avail >= 13) && (cmp(&next[5],(unsigned char *) "kind""\x20""of""\x20""",8) && 1)))
                  {
                     if (((avail >= '%') && (cmp(&next[13],(unsigned char *) "bird""\x20""sticks""\x20""to""\x20""sweaters?",24) && 1)))
                     {
                        reset(&buf_1);
                        appendarray(&buf_1,const_1_48,80);
                        consume(37);
                        goto l1_2;
                     }
                     if (((avail >= '4') && (cmp(&next[13],(unsigned char *) "crackers""\x20""do""\x20""firemen""\x20""like""\x20""in""\x20""their""\x20""soup?",39) && 1)))
                     {
                        reset(&buf_1);
                        appendarray(&buf_1,const_1_24,104);
                        consume(52);
                        goto l1_2;
                     }
                  }
                  if (((avail >= 7) && (cmp(&next[5],(unsigned char *) "li",2) && 1)))
                  {
                     if (((avail >= '2') && (cmp(&next[7],(unsigned char *) "es""\x20""at""\x20""the""\x20""bottom""\x20""of""\x20""the""\x20""ocean""\x20""and""\x20""twitches?",43) && 1)))
                     {
                        reset(&buf_1);
                        appendarray(&buf_1,const_1_5,120);
                        consume(50);
                        goto l1_2;
                     }
                     if (((avail >= ' ') && (cmp(&next[7],(unsigned char *) "ghts""\x20""up""\x20""a""\x20""soccer""\x20""stadium?",25) && 1)))
                     {
                        reset(&buf_1);
                        appendarray(&buf_1,const_1_7,112);
                        consume(32);
                        goto l1_2;
                     }
                  }
                  if (((avail >= '!') && (cmp(&next[5],(unsigned char *) "pet""\x20""makes""\x20""the""\x20""loudest""\x20""noise?",28) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_8,88);
                     consume(33);
                     goto l1_2;
                  }
                  if (((avail >= '#') && (cmp(&next[5],(unsigned char *) "runs""\x20""but""\x20""doesn't""\x20""get""\x20""anywhere?",30) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_6,112);
                     consume(35);
                     goto l1_2;
                  }
               }
               if (((avail >= '/') && (cmp(&next[4],(unsigned char *) "'s""\x20""easy""\x20""to""\x20""get""\x20""into""\x20""but""\x20""hard""\x20""to""\x20""get""\x20""out""\x20""of?",43) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_44,56);
                  consume(47);
                  goto l1_2;
               }
            }
            if (((avail >= 3) && ((next[2] == 'e') && 1)))
            {
               if (((avail >= '&') && (cmp(&next[3],(unsigned char *) "n""\x20""does""\x20""Friday""\x20""come""\x20""before""\x20""Thursday?",35) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_29,136);
                  consume(38);
                  goto l1_2;
               }
               if (((avail >= '%') && (cmp(&next[3],(unsigned char *) "re""\x20""do""\x20""boats""\x20""go""\x20""when""\x20""they""\x20""get""\x20""sick?",34) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_40,64);
                  consume(37);
                  goto l1_2;
               }
            }
            if (((avail >= 6) && (cmp(&next[2],(unsigned char *) "ich""\x20""",4) && 1)))
            {
               if (((avail >= ',') && (cmp(&next[6],(unsigned char *) "is""\x20""the""\x20""longest""\x20""word""\x20""in""\x20""the""\x20""dictionary?",38) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_1,400);
                  consume(44);
                  goto l1_2;
               }
               if (((avail >= '"') && (cmp(&next[6],(unsigned char *) "month""\x20""do""\x20""soldiers""\x20""hate""\x20""most?",28) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_41,152);
                  consume(34);
                  goto l1_2;
               }
            }
            if (((avail >= 4) && (cmp(&next[2],(unsigned char *) "y""\x20""",2) && 1)))
            {
               if (((avail >= 13) && (cmp(&next[4],(unsigned char *) "couldn't""\x20""",9) && 1)))
               {
                  if (((avail >= ')') && (cmp(&next[13],(unsigned char *) "dracula's""\x20""wife""\x20""get""\x20""to""\x20""sleep?",28) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_21,176);
                     consume(41);
                     goto l1_2;
                  }
                  if (((avail >= ',') && (cmp(&next[13],(unsigned char *) "the""\x20""bicycle""\x20""stand""\x20""up""\x20""by""\x20""itself?",31) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_30,136);
                     consume(44);
                     goto l1_2;
                  }
               }
               if (((avail >= 5) && ((next[4] == 'd') && 1)))
               {
                  if (((avail >= 8) && (cmp(&next[5],(unsigned char *) "id""\x20""",3) && 1)))
                  {
                     if (((avail >= '1') && (cmp(&next[8],(unsigned char *) "Johnny""\x20""throw""\x20""the""\x20""clock""\x20""out""\x20""of""\x20""the""\x20""window?",41) && 1)))
                     {
                        reset(&buf_1);
                        appendarray(&buf_1,const_1_14,272);
                        consume(49);
                        goto l1_2;
                     }
                     if (((avail >= 12) && (cmp(&next[8],(unsigned char *) "the""\x20""",4) && 1)))
                     {
                        if (((avail >= ' ') && (cmp(&next[12],(unsigned char *) "barber""\x20""win""\x20""the""\x20""race?",20) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_13,224);
                           consume(32);
                           goto l1_2;
                        }
                        if (((avail >= '&') && (cmp(&next[12],(unsigned char *) "cookie""\x20""go""\x20""to""\x20""the""\x20""hospital?",26) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_12,176);
                           consume(38);
                           goto l1_2;
                        }
                        if (((avail >= '$') && (cmp(&next[12],(unsigned char *) "dinosaur""\x20""cross""\x20""the""\x20""road?",24) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_23,360);
                           consume(36);
                           goto l1_2;
                        }
                        if (((avail >= '-') && (cmp(&next[12],(unsigned char *) "man""\x20""put""\x20""his""\x20""money""\x20""in""\x20""the""\x20""freezer?",33) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_27,200);
                           consume(45);
                           goto l1_2;
                        }
                        if (((avail >= 31) && (cmp(&next[12],(unsigned char *) "picture""\x20""go""\x20""to""\x20""jail?",19) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_18,176);
                           consume(31);
                           goto l1_2;
                        }
                        if (((avail >= '#') && (cmp(&next[12],(unsigned char *) "scarecrow""\x20""win""\x20""an""\x20""award?",23) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_16,328);
                           consume(35);
                           goto l1_2;
                        }
                     }
                  }
                  if (((avail >= '5') && (cmp(&next[5],(unsigned char *) "oes""\x20""a""\x20""Moon-rock""\x20""taste""\x20""better""\x20""than""\x20""an""\x20""Earth-rock?",48) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_19,224);
                     consume(53);
                     goto l1_2;
                  }
               }
               if (((avail >= 7) && (cmp(&next[4],(unsigned char *) "is""\x20""",3) && 1)))
               {
                  if (((avail >= 31) && (cmp(&next[7],(unsigned char *) "Peter""\x20""Pan""\x20""always""\x20""flying?",24) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_26,112);
                     consume(31);
                     goto l1_2;
                  }
                  if (((avail >= '&') && (cmp(&next[7],(unsigned char *) "there""\x20""a""\x20""gate""\x20""around""\x20""cemetaries?",31) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_22,280);
                     consume(38);
                     goto l1_2;
                  }
               }
               if (((avail >= '-') && (cmp(&next[4],(unsigned char *) "shouldn't""\x20""you""\x20""write""\x20""with""\x20""a""\x20""broken""\x20""pencil?",41) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_20,184);
                  consume(45);
                  goto l1_2;
               }
               if (((avail >= 5) && ((next[4] == 'w') && 1)))
               {
                  if (((avail >= '#') && (cmp(&next[5],(unsigned char *) "as""\x20""the""\x20""baby""\x20""strawberry""\x20""crying?",30) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_17,304);
                     consume(35);
                     goto l1_2;
                  }
                  if (((avail >= '+') && (cmp(&next[5],(unsigned char *) "ouldn't""\x20""the""\x20""shrimp""\x20""share""\x20""his""\x20""treasure?",38) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_15,264);
                     consume(43);
                     goto l1_2;
                  }
               }
            }
         }
         consume(1);
         goto l1_1;
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
         outputarray(const_1_34,304);
         consume(1);
         goto l1_8;
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
         goto l1_8;
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
         outputarray(const_1_43,192);
         consume(1);
         goto l1_8;
      }
      if (((avail >= 1) && ((next[0] == ' ') && 1)))
      {
         consume(1);
         goto l1_4;
      }
      goto fail1;
l1_4: if (!readnext(1, 5))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'T')) || ((('V' <= next[0]) && (next[0] <= 'x')) || (('z' <= next[0]) && (next[0] <= 255))))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_34,304);
         consume(1);
         goto l1_8;
      }
      if (((avail >= 1) && ((next[0] == 'U') && 1)))
      {
         if (((avail >= 3) && (cmp(&next[1],(unsigned char *) "_n",2) && 1)))
         {
            reset(&buf_1);
            appendarray(&buf_1,const_1_50,64);
            consume(3);
            goto l1_5;
         }
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 'y') && 1)))
      {
         if (((avail >= 5) && (cmp(&next[1],(unsigned char *) "ou_n",4) && 1)))
         {
            reset(&buf_1);
            appendarray(&buf_1,const_1_51,80);
            consume(5);
            goto l1_5;
         }
         consume(1);
         goto l1_1;
      }
      goto fail1;
l1_5: if (!readnext(1, 9))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '2')) || ((('4' <= next[0]) && (next[0] <= 'd')) || (('f' <= next[0]) && (next[0] <= 255))))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_34,304);
         consume(1);
         goto l1_8;
      }
      if (((avail >= 1) && ((next[0] == '3') && 1)))
      {
         if (((avail >= 9) && (cmp(&next[1],(unsigned char *) "3d_tO_ma",8) && 1)))
         {
            appendarray(&buf_1,const_1_3,72);
            consume(9);
            goto l1_6;
         }
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 'e') && 1)))
      {
         if (((avail >= 9) && (cmp(&next[1],(unsigned char *) "ed_tO_ma",8) && 1)))
         {
            appendarray(&buf_1,const_1_49,72);
            consume(9);
            goto l1_6;
         }
         consume(1);
         goto l1_1;
      }
      goto fail1;
l1_6: if (!readnext(1, 6))
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
         outputarray(const_1_34,304);
         consume(1);
         goto l1_8;
      }
      if (((avail >= 1) && ((next[0] == 't') && 1)))
      {
         if (((avail >= 6) && (cmp(&next[1],(unsigned char *) "Zh_th",5) && 1)))
         {
            appendarray(&buf_1,const_1_53,48);
            consume(6);
            goto l1_7;
         }
         if (((avail >= 6) && (cmp(&next[1],(unsigned char *) "ch_th",5) && 1)))
         {
            appendarray(&buf_1,const_1_54,48);
            consume(6);
            goto l1_7;
         }
         consume(1);
         goto l1_1;
      }
      goto fail1;
l1_7: if (!readnext(1, 2))
      {
         goto fail1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= '0')) || ((('2' <= next[0]) && (next[0] <= 'h')) || (('j' <= next[0]) && (next[0] <= 255))))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_34,304);
         consume(1);
         goto l1_8;
      }
      if (((avail >= 1) && ((next[0] == '1') && 1)))
      {
         if (((avail >= 2) && ((next[1] == 's') && 1)))
         {
            appendarray(&buf_1,const_1_2,24);
            consume(2);
            goto l1_2;
         }
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 'i') && 1)))
      {
         if (((avail >= 2) && ((next[1] == 's') && 1)))
         {
            appendarray(&buf_1,const_1_52,24);
            consume(2);
            goto l1_2;
         }
         consume(1);
         goto l1_1;
      }
      goto fail1;
l1_8: if (!readnext(1, 72))
      {
         goto accept1;
      }
      if (((avail >= 1) && ((((0 <= next[0]) && (next[0] <= 9)) || (((11 <= next[0]) && (next[0] <= 'G')) || ((('I' <= next[0]) && (next[0] <= 'V')) || (('X' <= next[0]) && (next[0] <= 255))))) && 1)))
      {
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 10) && 1)))
      {
         outputarray(const_1_34,304);
         consume(1);
         goto l1_8;
      }
      if (((avail >= 1) && ((next[0] == 'H') && 1)))
      {
         if (((avail >= '*') && (cmp(&next[1],(unsigned char *) "ow""\x20""do""\x20""crazy""\x20""people""\x20""go""\x20""through""\x20""the""\x20""forest?",41) && 1)))
         {
            reset(&buf_1);
            appendarray(&buf_1,const_1_42,208);
            consume(42);
            goto l1_2;
         }
         consume(1);
         goto l1_1;
      }
      if (((avail >= 1) && ((next[0] == 'W') && 1)))
      {
         if (((avail >= 2) && ((next[1] == 'h') && 1)))
         {
            if (((avail >= 4) && (cmp(&next[2],(unsigned char *) "at",2) && 1)))
            {
               if (((avail >= 5) && ((next[4] == ' ') && 1)))
               {
                  if (((avail >= 6) && ((next[5] == 'd') && 1)))
                  {
                     if (((avail >= 9) && (cmp(&next[6],(unsigned char *) "id""\x20""",3) && 1)))
                     {
                        if (((avail >= 13) && (cmp(&next[9],(unsigned char *) "one""\x20""",4) && 1)))
                        {
                           if (((avail >= ' ') && (cmp(&next[13],(unsigned char *) "hat""\x20""say""\x20""to""\x20""another?",19) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_46,256);
                              consume(32);
                              goto l1_2;
                           }
                           if (((avail >= ',') && (cmp(&next[13],(unsigned char *) "toilet""\x20""say""\x20""to""\x20""the""\x20""other""\x20""toilet?",31) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_45,128);
                              consume(44);
                              goto l1_2;
                           }
                        }
                        if (((avail >= 13) && (cmp(&next[9],(unsigned char *) "the""\x20""",4) && 1)))
                        {
                           if (((avail >= '>') && (cmp(&next[13],(unsigned char *) "cat""\x20""say""\x20""after""\x20""eating""\x20""two""\x20""robins""\x20""lying""\x20""in""\x20""the""\x20""sun?",49) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_28,216);
                              consume(62);
                              goto l1_2;
                           }
                           if (((avail >= '8') && (cmp(&next[13],(unsigned char *) "digital""\x20""clock""\x20""say""\x20""to""\x20""the""\x20""grandfather""\x20""clock?",43) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_32,184);
                              consume(56);
                              goto l1_2;
                           }
                           if (((avail >= '6') && (cmp(&next[13],(unsigned char *) "elder""\x20""chimney""\x20""say""\x20""to""\x20""the""\x20""younger""\x20""chimney?",41) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_47,208);
                              consume(54);
                              goto l1_2;
                           }
                           if (((avail >= '&') && (cmp(&next[13],(unsigned char *) "lawyer""\x20""name""\x20""his""\x20""daughter?",25) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_38,24);
                              consume(38);
                              goto l1_2;
                           }
                           if (((avail >= 'H') && (cmp(&next[13],(unsigned char *) "worker""\x20""at""\x20""the""\x20""rubber""\x20""band""\x20""factory""\x20""say""\x20""when""\x20""he""\x20""lost""\x20""his""\x20""job?",59) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_35,64);
                              consume(72);
                              goto l1_2;
                           }
                        }
                     }
                     if (((avail >= 7) && ((next[6] == 'o') && 1)))
                     {
                        if (((avail >= 8) && ((next[7] == ' ') && 1)))
                        {
                           if (((avail >= 30) && (cmp(&next[8],(unsigned char *) "lawyers""\x20""wear""\x20""to""\x20""court?",22) && 1)))
                           {
                              reset(&buf_1);
                              appendarray(&buf_1,const_1_31,72);
                              consume(30);
                              goto l1_2;
                           }
                           if (((avail >= 12) && (cmp(&next[8],(unsigned char *) "you""\x20""",4) && 1)))
                           {
                              if (((avail >= 17) && (cmp(&next[12],(unsigned char *) "call""\x20""",5) && 1)))
                              {
                                 if (((avail >= 18) && ((next[17] == 'a') && 1)))
                                 {
                                    if (((avail >= 31) && (cmp(&next[18],(unsigned char *) """\x20""fake""\x20""noodle?",13) && 1)))
                                    {
                                       reset(&buf_1);
                                       appendarray(&buf_1,const_1_11,80);
                                       consume(31);
                                       goto l1_2;
                                    }
                                    if (((avail >= 21) && (cmp(&next[18],(unsigned char *) "n""\x20""a",3) && 1)))
                                    {
                                       if (((avail >= '(') && (cmp(&next[21],(unsigned char *) "lligator""\x20""in""\x20""a""\x20""vest?",19) && 1)))
                                       {
                                          reset(&buf_1);
                                          appendarray(&buf_1,const_1_10,120);
                                          consume(40);
                                          goto l1_2;
                                       }
                                       if (((avail >= '7') && (cmp(&next[21],(unsigned char *) "pology""\x20""written""\x20""in""\x20""dots""\x20""and""\x20""dashes?",34) && 1)))
                                       {
                                          reset(&buf_1);
                                          appendarray(&buf_1,const_1_37,104);
                                          consume(55);
                                          goto l1_2;
                                       }
                                    }
                                 }
                                 if (((avail >= ')') && (cmp(&next[17],(unsigned char *) "cheese""\x20""that""\x20""isn't""\x20""yours?",24) && 1)))
                                 {
                                    reset(&buf_1);
                                    appendarray(&buf_1,const_1_33,96);
                                    consume(41);
                                    goto l1_2;
                                 }
                                 if (((avail >= '9') && (cmp(&next[17],(unsigned char *) "four""\x20""bullfighters""\x20""standing""\x20""in""\x20""quicksand?",40) && 1)))
                                 {
                                    reset(&buf_1);
                                    appendarray(&buf_1,const_1_36,104);
                                    consume(57);
                                    goto l1_2;
                                 }
                                 if (((avail >= '.') && (cmp(&next[17],(unsigned char *) "two""\x20""fat""\x20""people""\x20""having""\x20""a""\x20""chat?",29) && 1)))
                                 {
                                    reset(&buf_1);
                                    appendarray(&buf_1,const_1_4,144);
                                    consume(46);
                                    goto l1_2;
                                 }
                              }
                              if (((avail >= '8') && (cmp(&next[12],(unsigned char *) "get""\x20""when""\x20""you""\x20""cross""\x20""a""\x20""snowman""\x20""with""\x20""a""\x20""vampire?",44) && 1)))
                              {
                                 reset(&buf_1);
                                 appendarray(&buf_1,const_1_25,72);
                                 consume(56);
                                 goto l1_2;
                              }
                           }
                        }
                        if (((avail >= '*') && (cmp(&next[7],(unsigned char *) "es""\x20""it""\x20""take""\x20""to""\x20""solve""\x20""this""\x20""challenge?",35) && 1)))
                        {
                           consume(42);
                           goto l1_3;
                        }
                        if (((avail >= 29) && (cmp(&next[7],(unsigned char *) "g""\x20""keeps""\x20""the""\x20""best""\x20""time?",22) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_9,88);
                           consume(29);
                           goto l1_2;
                        }
                     }
                  }
                  if (((avail >= '4') && (cmp(&next[5],(unsigned char *) "is""\x20""an""\x20""astronaut's""\x20""favorite""\x20""place""\x20""on""\x20""a""\x20""computer?",47) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_39,112);
                     consume(52);
                     goto l1_2;
                  }
                  if (((avail >= 13) && (cmp(&next[5],(unsigned char *) "kind""\x20""of""\x20""",8) && 1)))
                  {
                     if (((avail >= '%') && (cmp(&next[13],(unsigned char *) "bird""\x20""sticks""\x20""to""\x20""sweaters?",24) && 1)))
                     {
                        reset(&buf_1);
                        appendarray(&buf_1,const_1_48,80);
                        consume(37);
                        goto l1_2;
                     }
                     if (((avail >= '4') && (cmp(&next[13],(unsigned char *) "crackers""\x20""do""\x20""firemen""\x20""like""\x20""in""\x20""their""\x20""soup?",39) && 1)))
                     {
                        reset(&buf_1);
                        appendarray(&buf_1,const_1_24,104);
                        consume(52);
                        goto l1_2;
                     }
                  }
                  if (((avail >= 7) && (cmp(&next[5],(unsigned char *) "li",2) && 1)))
                  {
                     if (((avail >= '2') && (cmp(&next[7],(unsigned char *) "es""\x20""at""\x20""the""\x20""bottom""\x20""of""\x20""the""\x20""ocean""\x20""and""\x20""twitches?",43) && 1)))
                     {
                        reset(&buf_1);
                        appendarray(&buf_1,const_1_5,120);
                        consume(50);
                        goto l1_2;
                     }
                     if (((avail >= ' ') && (cmp(&next[7],(unsigned char *) "ghts""\x20""up""\x20""a""\x20""soccer""\x20""stadium?",25) && 1)))
                     {
                        reset(&buf_1);
                        appendarray(&buf_1,const_1_7,112);
                        consume(32);
                        goto l1_2;
                     }
                  }
                  if (((avail >= '!') && (cmp(&next[5],(unsigned char *) "pet""\x20""makes""\x20""the""\x20""loudest""\x20""noise?",28) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_8,88);
                     consume(33);
                     goto l1_2;
                  }
                  if (((avail >= '#') && (cmp(&next[5],(unsigned char *) "runs""\x20""but""\x20""doesn't""\x20""get""\x20""anywhere?",30) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_6,112);
                     consume(35);
                     goto l1_2;
                  }
               }
               if (((avail >= '/') && (cmp(&next[4],(unsigned char *) "'s""\x20""easy""\x20""to""\x20""get""\x20""into""\x20""but""\x20""hard""\x20""to""\x20""get""\x20""out""\x20""of?",43) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_44,56);
                  consume(47);
                  goto l1_2;
               }
            }
            if (((avail >= 3) && ((next[2] == 'e') && 1)))
            {
               if (((avail >= '&') && (cmp(&next[3],(unsigned char *) "n""\x20""does""\x20""Friday""\x20""come""\x20""before""\x20""Thursday?",35) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_29,136);
                  consume(38);
                  goto l1_2;
               }
               if (((avail >= '%') && (cmp(&next[3],(unsigned char *) "re""\x20""do""\x20""boats""\x20""go""\x20""when""\x20""they""\x20""get""\x20""sick?",34) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_40,64);
                  consume(37);
                  goto l1_2;
               }
            }
            if (((avail >= 6) && (cmp(&next[2],(unsigned char *) "ich""\x20""",4) && 1)))
            {
               if (((avail >= ',') && (cmp(&next[6],(unsigned char *) "is""\x20""the""\x20""longest""\x20""word""\x20""in""\x20""the""\x20""dictionary?",38) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_1,400);
                  consume(44);
                  goto l1_2;
               }
               if (((avail >= '"') && (cmp(&next[6],(unsigned char *) "month""\x20""do""\x20""soldiers""\x20""hate""\x20""most?",28) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_41,152);
                  consume(34);
                  goto l1_2;
               }
            }
            if (((avail >= 4) && (cmp(&next[2],(unsigned char *) "y""\x20""",2) && 1)))
            {
               if (((avail >= 13) && (cmp(&next[4],(unsigned char *) "couldn't""\x20""",9) && 1)))
               {
                  if (((avail >= ')') && (cmp(&next[13],(unsigned char *) "dracula's""\x20""wife""\x20""get""\x20""to""\x20""sleep?",28) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_21,176);
                     consume(41);
                     goto l1_2;
                  }
                  if (((avail >= ',') && (cmp(&next[13],(unsigned char *) "the""\x20""bicycle""\x20""stand""\x20""up""\x20""by""\x20""itself?",31) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_30,136);
                     consume(44);
                     goto l1_2;
                  }
               }
               if (((avail >= 5) && ((next[4] == 'd') && 1)))
               {
                  if (((avail >= 8) && (cmp(&next[5],(unsigned char *) "id""\x20""",3) && 1)))
                  {
                     if (((avail >= '1') && (cmp(&next[8],(unsigned char *) "Johnny""\x20""throw""\x20""the""\x20""clock""\x20""out""\x20""of""\x20""the""\x20""window?",41) && 1)))
                     {
                        reset(&buf_1);
                        appendarray(&buf_1,const_1_14,272);
                        consume(49);
                        goto l1_2;
                     }
                     if (((avail >= 12) && (cmp(&next[8],(unsigned char *) "the""\x20""",4) && 1)))
                     {
                        if (((avail >= ' ') && (cmp(&next[12],(unsigned char *) "barber""\x20""win""\x20""the""\x20""race?",20) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_13,224);
                           consume(32);
                           goto l1_2;
                        }
                        if (((avail >= '&') && (cmp(&next[12],(unsigned char *) "cookie""\x20""go""\x20""to""\x20""the""\x20""hospital?",26) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_12,176);
                           consume(38);
                           goto l1_2;
                        }
                        if (((avail >= '$') && (cmp(&next[12],(unsigned char *) "dinosaur""\x20""cross""\x20""the""\x20""road?",24) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_23,360);
                           consume(36);
                           goto l1_2;
                        }
                        if (((avail >= '-') && (cmp(&next[12],(unsigned char *) "man""\x20""put""\x20""his""\x20""money""\x20""in""\x20""the""\x20""freezer?",33) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_27,200);
                           consume(45);
                           goto l1_2;
                        }
                        if (((avail >= 31) && (cmp(&next[12],(unsigned char *) "picture""\x20""go""\x20""to""\x20""jail?",19) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_18,176);
                           consume(31);
                           goto l1_2;
                        }
                        if (((avail >= '#') && (cmp(&next[12],(unsigned char *) "scarecrow""\x20""win""\x20""an""\x20""award?",23) && 1)))
                        {
                           reset(&buf_1);
                           appendarray(&buf_1,const_1_16,328);
                           consume(35);
                           goto l1_2;
                        }
                     }
                  }
                  if (((avail >= '5') && (cmp(&next[5],(unsigned char *) "oes""\x20""a""\x20""Moon-rock""\x20""taste""\x20""better""\x20""than""\x20""an""\x20""Earth-rock?",48) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_19,224);
                     consume(53);
                     goto l1_2;
                  }
               }
               if (((avail >= 7) && (cmp(&next[4],(unsigned char *) "is""\x20""",3) && 1)))
               {
                  if (((avail >= 31) && (cmp(&next[7],(unsigned char *) "Peter""\x20""Pan""\x20""always""\x20""flying?",24) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_26,112);
                     consume(31);
                     goto l1_2;
                  }
                  if (((avail >= '&') && (cmp(&next[7],(unsigned char *) "there""\x20""a""\x20""gate""\x20""around""\x20""cemetaries?",31) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_22,280);
                     consume(38);
                     goto l1_2;
                  }
               }
               if (((avail >= '-') && (cmp(&next[4],(unsigned char *) "shouldn't""\x20""you""\x20""write""\x20""with""\x20""a""\x20""broken""\x20""pencil?",41) && 1)))
               {
                  reset(&buf_1);
                  appendarray(&buf_1,const_1_20,184);
                  consume(45);
                  goto l1_2;
               }
               if (((avail >= 5) && ((next[4] == 'w') && 1)))
               {
                  if (((avail >= '#') && (cmp(&next[5],(unsigned char *) "as""\x20""the""\x20""baby""\x20""strawberry""\x20""crying?",30) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_17,304);
                     consume(35);
                     goto l1_2;
                  }
                  if (((avail >= '+') && (cmp(&next[5],(unsigned char *) "ouldn't""\x20""the""\x20""shrimp""\x20""share""\x20""his""\x20""treasure?",38) && 1)))
                  {
                     reset(&buf_1);
                     appendarray(&buf_1,const_1_15,264);
                     consume(43);
                     goto l1_2;
                  }
               }
            }
         }
         consume(1);
         goto l1_1;
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
