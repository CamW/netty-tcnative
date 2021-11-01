/*
 * Copyright 2021 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include "tcn.h"
#include "ssl_private.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "cert_compress.h"
#include <dlfcn.h>

static void* libBrotliCommonHandle = NULL;
static void* libBrotliDecHandle = NULL;
static void* libBrotliEncHandle = NULL;

bool zlib_load_libs() {
    return 0;
}

int zlib_compress(SSL* ssl, CBB* out, const uint8_t* in, size_t in_len)
{
    fprintf(stderr, "TLS Cert Compression: zlib_compress not implemented!\n");
    return 0;
}

int zlib_decompress(SSL* ssl, CRYPTO_BUFFER** out, size_t uncompressed_len, const uint8_t* in, size_t in_len)
{
    fprintf(stderr, "TLS Cert Compression: zlib_decompress not implemented!\n");
    return 0;
}

bool brotli_load_libs() {
    if (libBrotliCommonHandle == NULL) {
       libBrotliCommonHandle = dlopen ("libbrotlicommon.1.dylib", RTLD_LAZY);
       if (libBrotliCommonHandle == NULL) return 0;
    }
    if (libBrotliDecHandle == NULL) {
       libBrotliDecHandle = dlopen ("libbrotlidec.1.dylib", RTLD_LAZY);
       if (libBrotliDecHandle == NULL) return 0;
    }
    if (libBrotliEncHandle == NULL) {
       libBrotliEncHandle = dlopen ("libbrotlienc.1.dylib", RTLD_LAZY);
       if (libBrotliEncHandle == NULL) return 0;
    }
    return 1;
}

int brotli_decompress(SSL* ssl, CRYPTO_BUFFER** out, size_t uncompressed_len, const uint8_t* in, size_t in_len)
{
    fprintf(stderr, "Decompressing cert\n");

    uint8_t* data;
    if (!((*out) = CRYPTO_BUFFER_alloc(&data, uncompressed_len))) {
        fprintf(stderr, "Unable to allocate decompression buffer [%zu].", uncompressed_len);
        return 0;
    }

    size_t output_size = uncompressed_len;
    if (BrotliDecoderDecompress(in_len, in, &output_size, data) !=
        1 || output_size != uncompressed_len) {
        fprintf(stderr, "Unexpected length of decompressed data or failure to decompress. [%zu/%zu]" , output_size, uncompressed_len);
        return 0;
    }

    fprintf(stderr, "Certificate decompressed successfully. [%zu->%zu] %f%%\n", in_len, uncompressed_len, (100.0 * in_len) / uncompressed_len);

    return 1;
}

int brotli_compress(SSL* ssl, CBB* out, const uint8_t* in, size_t in_len)
{
    fprintf(stderr, "TLS Cert Compression: brotli_compress not implemented!\n");
    return 0;
}

bool zstd_load_libs() {
    return 0;
}

int zstd_compress(SSL* ssl, CBB* out, const uint8_t* in, size_t in_len)
{
    fprintf(stderr, "TLS Cert Compression: zstd_compress not implemented!\n");
    return 0;
}

int zstd_decompress(SSL* ssl, CRYPTO_BUFFER** out, size_t uncompressed_len, const uint8_t* in, size_t in_len)
{
    fprintf(stderr, "TLS Cert Compression: zstd_decompress not implemented!\n");
    return 0;
}

#endif // OPENSSL_IS_BORINGSSL