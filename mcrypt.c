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

/**
 * @brief Print usage message to stderr.
 */
static void usage(void)
{
    fprintf(stderr, "usage: mcrypt key-file in-file [ out-file | - ]\n");
}

/**
 * @brief Read an 8-byte key from the provided key file.
 *
 * @param keyfile   Path to the binary key file.
 * @param keybytes  Output buffer that receives the 8-byte key.
 */
static void read_key(const char *keyfile, uint8_t keybytes[8])
{
    FILE *kf = fopen(keyfile, "rb");
    if (!kf)
    {
        perror("key-file");
        exit(EXIT_FAILURE);
    }

    size_t n = fread(keybytes, 1, 8, kf);
    fclose(kf);

    if (n != 8)
    {
        fprintf(stderr, "error: key file must contain 8 bytes\n");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Read an entire file into a heap-allocated buffer.
 *
 * @param filename  Path to the file to read.
 * @param len_out   Output parameter that receives the file length.
 *
 * @return Pointer to a buffer containing the file contents.
 */
static uint8_t *read_input(const char *filename, size_t *len_out)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        perror("input-file");
        exit(EXIT_FAILURE);
    }

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

/**
 * @brief Write binary output to a file.
 *
 * @param filename  Output file path.
 * @param data      Buffer containing the data to write.
 * @param len       Number of bytes to write.
 */
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
    if (len == 0)
    {
        fclose(f);
        return;
    }

    size_t written = fwrite(data, 1, len, f);
    fclose(f);

    if (written != len)
    {
        fprintf(stderr, "error: failed to write output file\n");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Write translated bytes to stdout using ASCII/hex rules.
 *
 * @param data  Buffer containing the bytes to print.
 * @param len   Number of bytes in the buffer.
 */
static void write_stdout(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        unsigned char c = data[i];

        if (c < 128)
        {
            putchar(c);
        }
        else
        {
            printf("%02x", c);
        }
    }
}

/**
 * @brief Program entry point for the mcrypt driver.
 *
 * @param argc  Argument count.
 * @param argv  Argument vector describing key/input/output paths.
 *
 * @return EXIT_SUCCESS on success; EXIT_FAILURE on invalid usage.
 */
int main(int argc, char **argv)
{
    if (argc != 4)
    {
        usage();
        return EXIT_FAILURE;
    }

    const char *keyfile = argv[1];
    const char *infile = argv[2];
    const char *outfile = argv[3];

    uint8_t keybytes[8];
    read_key(keyfile, keybytes);

    size_t in_len = 0;
    uint8_t *inbuf = read_input(infile, &in_len);

    uint8_t *outbuf = malloc(in_len);
    assert(outbuf != NULL);

    KStream *ks = ks_create(keybytes);

    ks_translate(ks, inbuf, outbuf, in_len);

    if (outfile[0] == '-' && outfile[1] == '\0')
    {
        write_stdout(outbuf, in_len);
    }
    else
    {
        write_output_file(outfile, outbuf, in_len);
    }

    ks_destroy(ks);
    free(inbuf);
    free(outbuf);

    return EXIT_SUCCESS;
}
