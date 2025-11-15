/**
 * @file mcrypt.c
 * @author Shane
 *
 * @brief Main driver program for the KStream stream cipher.
 *
 * Usage:
 *      mcrypt key-file input-file [output-file | - ]
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <assert.h>
#include "KStream.h"

/* ---------------------------------------------------------
 * Print usage message to stderr
 * --------------------------------------------------------- */
static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s key-file in-file [ out-file | - ]\n",
            prog);
}

/* ---------------------------------------------------------
 * Read 8-byte key from key file as uint64_t
 * --------------------------------------------------------- */
static uint64_t read_key(const char *keyfile)
{
    FILE *kf = fopen(keyfile, "rb");
    if (!kf)
    {
        perror("key-file");
        exit(EXIT_FAILURE);
    }

    uint64_t key = 0;
    size_t n = fread(&key, 1, 8, kf);
    fclose(kf);

    if (n != 8)
    {
        fprintf(stderr, "error: key file must contain 8 bytes\n");
        exit(EXIT_FAILURE);
    }

    return key;
}

/* ---------------------------------------------------------
 * Read entire input file into a buffer
 * --------------------------------------------------------- */
static uint8_t *read_input(const char *filename, size_t *len_out)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        perror("input-file");
        exit(EXIT_FAILURE);
    }

    /* determine file size */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    if (size < 0)
    {
        fprintf(stderr, "error: cannot read file size\n");
        exit(EXIT_FAILURE);
    }

    uint8_t *buf = malloc(size);
    assert(buf != NULL);

    size_t n = fread(buf, 1, size, f);
    fclose(f);

    if (n != (size_t)size)
    {
        fprintf(stderr, "error: could not read entire input file\n");
        exit(EXIT_FAILURE);
    }

    *len_out = (size_t)size;
    return buf;
}

/* ---------------------------------------------------------
 * Write binary output to file
 * --------------------------------------------------------- */
static void write_output_file(const char *filename,
                              const uint8_t *data,
                              size_t len)
{
    FILE *f = fopen(filename, "wb");
    if (!f)
    {
        perror("output-file");
        exit(EXIT_FAILURE);
    }

    size_t n = fwrite(data, 1, len, f);
    fclose(f);

    if (n != len)
    {
        fprintf(stderr, "error: failed to write output file\n");
        exit(EXIT_FAILURE);
    }
}

/* ---------------------------------------------------------
 * Write to stdout using ASCII or hex rules (assignment spec)
 * --------------------------------------------------------- */
static void write_stdout(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (data[i] < 128 && isprint(data[i]))
        {
            /* printable ASCII */
            putchar(data[i]);
        }
        else
        {
            /* print non-ASCII as hex */
            printf("%02x", data[i]);
        }
    }
}

/* ---------------------------------------------------------
 * MAIN
 * --------------------------------------------------------- */
int main(int argc, char **argv)
{
    if (argc != 4)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *keyfile = argv[1];
    const char *infile = argv[2];
    const char *outfile = argv[3];

    /* -----------------------------------------------------
     * Step 1: Read key
     * ----------------------------------------------------- */
    uint64_t key64 = read_key(keyfile);

    /* -----------------------------------------------------
     * Step 2: Read input file
     * ----------------------------------------------------- */
    size_t in_len = 0;
    uint8_t *inbuf = read_input(infile, &in_len);

    /* Allocate output buffer (same size) */
    uint8_t *outbuf = malloc(in_len);
    assert(outbuf != NULL);

    /* -----------------------------------------------------
     * Step 3: Create keystream
     * ----------------------------------------------------- */
    KStream *ks = ks_create(key64);

    /* -----------------------------------------------------
     * Step 4: Translate
     * ----------------------------------------------------- */
    ks_translate(ks, inbuf, outbuf, in_len);

    /* -----------------------------------------------------
     * Step 5: Deliver output
     * ----------------------------------------------------- */
    if (outfile[0] == '-' && outfile[1] == '\0')
    {
        /* stdout mode */
        write_stdout(outbuf, in_len);
    }
    else
    {
        /* binary file mode */
        write_output_file(outfile, outbuf, in_len);
    }

    /* -----------------------------------------------------
     * Step 6: Cleanup
     * ----------------------------------------------------- */
    ks_destroy(ks);
    free(inbuf);
    free(outbuf);

    return EXIT_SUCCESS;
}