#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define INT_MIN (1 << (sizeof(int) * 8 - 1))
#define INT_MAX (int)((unsigned)INT_MIN - 1)

#define LOG(fmt, args...)                       \
  do {                                          \
    fprintf(stderr, fmt "\n", ## args);         \
  } while (0)

typedef struct {
  char *lhs, *rhs;
  size_t lhslen, rhslen;
} rule_t;

typedef uint32_t color_t;
#define WHITE ((color_t)~0)
#define BLACK ((color_t)0)
#define MARK BLACK

typedef struct {
  int x, y;
  color_t c;
} pixel_t;

char *step(char *s, rule_t *rules) {
  char *t = NULL;
  size_t size = 0;
  rule_t *rule;
  unsigned i, j;

#define GROW(n)                                 \
  do {                                          \
    if (j + (n) > size) {                       \
      size = (size ? size : strlen(s)) << 1;    \
      t = realloc(t, size);                     \
    }                                           \
  } while (0)

  for (i = 0, j = 0; s[i];) {
    for (rule = rules; rule->lhs; rule++) {
      if (0 == strncasecmp(&s[i], rule->lhs, rule->lhslen)) {
        GROW(rule->rhslen);
        memcpy(&t[j], rule->rhs, rule->rhslen);
        j += rule->rhslen;
        i += rule->lhslen;
        break;
      }
    }
    if (!rule->lhs) {
      GROW(1);
      t[j++] = s[i++];
    }
  }

  GROW(1);
  t[j++] = 0;

#undef GROW
  return t;
}

color_t palette[] = {
  0xff4fe9fc,
  0xff3eaffc,
  0xff6eb9e9,
  0xff34e28a,
  0xffcf9f72,
  0xffa87fad,
  0xff2929ef,
};
#define NCOLORS (sizeof(palette) / sizeof(palette[0]))

int check(char *s, int w, int h, color_t *drawing) {
  pixel_t *pixels = NULL, *px;
  size_t size = 0;
  int i, j = 0, stop, idx;

  bool pen = false;
  int x = 0, y = 0, dx = 0, dy = 1, color = 0, tmp,
    minx = INT_MAX, maxx = INT_MIN,
    miny = INT_MAX, maxy = INT_MIN;

  typedef struct {
    int x, y, dx, dy, color;
    bool pen;
  } state_t;
  state_t stack[0x1000];
  unsigned top = 0;

#define W (maxx - minx + 1)
#define H (maxy - miny + 1)

#define RET(r)                                  \
  do {                                          \
    free(pixels);                               \
    return (r);                                 \
  } while (0)

#define PUSH()                                          \
  do {                                                  \
    if (sizeof(stack) / sizeof(stack[0]) == top) {      \
      RET(0);                                           \
    }                                                   \
    stack[top++] = (state_t){x, y, dx, dy, color, pen}; \
  } while (0)

#define POP()                                             \
  do {                                                    \
    if (0 == top) {                                       \
      RET(0);                                             \
    }                                                     \
    top--;                                                \
    x = stack[top].x;                                     \
    y = stack[top].y;                                     \
    dx = stack[top].dx;                                   \
    dy = stack[top].dy;                                   \
    color = stack[top].color;                             \
    pen = stack[top].pen;                                 \
  } while (0)

#define TL()                                    \
  do {                                          \
    tmp = dx;                                   \
    dx = -dy;                                   \
    dy = tmp;                                   \
  } while (0)

#define TR()                                    \
  do {                                          \
    tmp = dx;                                   \
    dx = dy;                                    \
    dy = -tmp;                                  \
  } while (0)

#define FWD()                                   \
  do {                                          \
    x += dx;                                    \
    y += dy;                                    \
  } while (0)

#define NC()                                                        \
  do {                                                              \
    color = (color + 1) % NCOLORS;                                  \
  } while (0)

#define PC()                                                        \
  do {                                                              \
    color = (color + NCOLORS - 1) % NCOLORS;                        \
  } while (0)

#define PT()                                    \
  do {                                          \
    pen = !pen;                                 \
  } while (0)

#define PD()                                    \
  do {                                          \
    pen = true;                                 \
  } while (0)

#define PU()                                    \
  do {                                          \
    pen = false;                                \
  } while (0)

#define GROW(n)                                         \
  do {                                                  \
  } while (0)

#define PAINT()                                         \
  do {                                                  \
    if (j == size) {                                    \
      size = size ? (size << 1) : 0x1000;               \
      pixels = realloc(pixels, size * sizeof(pixel_t)); \
    }                                                   \
    /* LOG("(%d, %d) %d", x, y, color); */                    \
    pixels[j++] = (pixel_t){x, y, palette[color]};      \
    if (x < minx) minx = x;                             \
    if (x > maxx) maxx = x;                             \
    if (y < miny) miny = y;                             \
    if (y > maxy) maxy = y;                             \
    if (W > w || H > h) {                               \
      RET(0);                                           \
    }                                                   \
  } while(0)

  for (i = 0; s[i]; i++) {
    if (pen) {
      PAINT();
    }

    switch (s[i]) {

    case '(':
      PUSH();
      break;

    case ')':
      POP();
      break;

    case '[':
      PUSH();
      TL();
      break;

    case ']':
      POP();
      TR();
      break;

    case '<':
      TL();
      break;

    case '>':
      TR();
      break;

    case '+':
      PD();
      break;

    case '-':
      PU();
      break;

    case '!':
      PT();
      break;

    case '/':
      NC();
      break;

    case '\\':
      PC();
      break;

    case '.':
      PAINT();
      break;

    case 'A' ... 'Z':
    case '^':
      FWD();
      break;

    }
  }

  /* LOG("%d %d %d", minx, maxx, W); */
  /* LOG("%d %d %d", miny, maxy, H); */
  if (W != w || H != h) {
    RET(0);
  }

  /* Go through pixels from most recent first */
  for (i = j - 1; i >= 0; i--) {
    px = &pixels[i];
    px->x -= minx;
    px->y -= miny;
    idx = w * px->y + px->x;

    /* LOG("%3d %3d %06x", px->x, px->y, px->c & 0xffffff); */

    /* Pixel already checked */
    if (MARK == drawing[idx]) {
      continue;
    }

    /* Pixel is bad */
    if (drawing[idx] != px->c) {
      break;
    }

    /* Mark pixel as visited */
    /* LOG("MARK(%d, %d) %08x", px->x, px->y, drawing[idx]); */
    drawing[idx] = MARK;
  }
  stop = i; /* Stop just before bad pixel */

  /* Final check: every pixel must be white or have been marked */
  if (-1 == stop) {
    for (i = 0; i < h * w; i++) {
      if (MARK != drawing[i] && WHITE != drawing[i]) {
        break;
      }
    }
    if (h * w == i) {
      RET(1);
    }
  }

  /* Restore pixels in drawing */
  for (i = j - 1; i > stop; i--) {
    px = &pixels[i];
    idx = w * px->y + px->x;

    if (!drawing[idx]) {
      drawing[idx] = px->c;
      /* LOG("RESTORE(%d, %d) %08x", px->x, px->y, drawing[idx]); */
    }
  }

  RET(0);

#undef W
#undef H
#undef RET
#undef PUSH
#undef POP
#undef TL
#undef TR
#undef FWD
#undef NC
#undef PC
#undef PT
#undef PD
#undef PU
#undef GROW
#undef PAINT
}

#define RULE(l, r)                              \
  { .lhs = (l), .lhslen = (l) ? strlen(l) : 0,  \
    .rhs = (r), .rhslen = (r) ? strlen(r) : 0 }

int main(int argc, char *argv[]) {
  int i, j, numb, ngens, nrules, nvars, w, h, ret, axiomi[100];
  pixel_t *pixels, px;
  rule_t rules[100] = {{0, 0, 0, 0}};
  char axiom[100], *s, *t, vars[26 * 2 + 12 + 2] = {0};
  color_t *drawing;

  if (argc < 5) {
    fprintf(stderr,
            "usage: %s <gen> <width> <height> [<lhs> <rhs> [ ... ]] < <image data>\n",
            argv[0]);
    return 1;
  }

  i = 1;
  ngens = atoi(argv[i++]);
  w = atoi(argv[i++]);
  h = atoi(argv[i++]);
  for (j = 0; i < argc; j++) {
    rules[j].lhs = argv[i++];
    rules[j].lhslen = strlen(rules[j].lhs);
    rules[j].rhs = argv[i++];
    rules[j].rhslen = strlen(rules[j].rhs);
  }
  nrules = j;

  numb = sizeof(color_t) * w * h;
  drawing = malloc(numb);

#define ADDVAR(v)                                \
  do {                                           \
    if ((v) >= 'a' && (v) <= 'z' &&              \
        !strchr(vars, (v))) {                    \
      vars[strlen(vars)] = (v);                  \
    }                                            \
  } while (0)

#define ADDVARS(vs)                             \
  do {                                          \
    for (j = 0; (vs)[j]; j++) {                 \
      ADDVAR((vs)[j] | 0x20);                   \
    }                                           \
  } while (0)

  for (i = 0; i < nrules; i++) {
    ADDVARS(rules[i].lhs);
    ADDVARS(rules[i].rhs);
  }
  nvars = strlen(vars);

#ifdef AXIOM_ANY
  LOG("AXIOM_ANY");
  /* Add uppercase vars */
  for (i = 0; i < nvars; i++) {
    vars[i + nvars] = vars[i] & ~0x20;
  }
  /* Add constants */
  strcpy(&vars[nvars * 2], "()[]^<>!+-/\\.");
  nvars = strlen(vars);
#endif

  LOG("vars = %s", vars, nvars);

  for (i = 0; i < numb;) {
    ret = read(0, (void*)drawing + i, numb - i);
    if (ret <= 0) {
      return 1;
    }
    i += ret;
  }

  /* Initialize `axiomi` */
  for (i = 0; i < sizeof(axiomi) / sizeof(axiomi[0]); i++) {
    axiomi[i] = -1;
  }

  for (;;) {
    for (i = 0; 0 == vars[++axiomi[i]]; i++) {
      axiomi[i] = 0;
      axiom[i] = vars[0];
    }
    axiom[i] = vars[axiomi[i]];

    fprintf(stderr, "\x1b[G%s", axiom);
    /* LOG("axiom = %s", axiom); */
    s = strdup(axiom);
    for (i = 1; i <= ngens; i++) {
      /* LOG("  gen = %d", i); */
      t = step(s, rules);
      free(s);
      s = t;
    }

    if (check(s, w, h, drawing)) {
      LOG("");
      printf("%s\n", axiom);
      return 0;
    }
    free(s);

  }

  return 0;
}
