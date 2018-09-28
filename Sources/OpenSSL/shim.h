/**
 * Copyright IBM Corporation 2017
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#ifndef OpenSSLHelper_h
#define OpenSSLHelper_h

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

// This is a wrapper function to wrap the call to SSL_CTX_set_alpn_select_cb() which is
// only available from OpenSSL v1.0.2. Calling this function with older version will do
// nothing.
static inline SSL_CTX_set_alpn_select_cb_wrapper(SSL_CTX *ctx,
					  int (*cb) (SSL *ssl,
								 const unsigned char **out,
								 unsigned char *outlen,
								 const unsigned char *in,
								 unsigned int inlen,
								 void *arg), void *arg) {
	#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		SSL_CTX_set_alpn_select_cb(ctx, cb, arg);
	#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
}

// This is a wrapper function to wrap the call to SSL_get0_alpn_selected() which is
// only available from OpenSSL v1.0.2. Calling this function with older version will do
// nothing.
static inline SSL_get0_alpn_selected_wrapper(const SSL *ssl, const unsigned char **data,
											 unsigned int *len) {
	#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		SSL_get0_alpn_selected(ssl, data, len);
	#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
}

// This is a wrapper function that allows the setting of AUTO ECDH mode when running
// on OpenSSL v1.0.2. Calling this function on an older version will have no effect.
static inline SSL_CTX_setAutoECDH(SSL_CTX *ctx) {

	#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL && OPENSSL_VERSION_NUMBER < 0x10100000L)
		SSL_CTX_ctrl(ctx, SSL_CTRL_SET_ECDH_AUTO, 1, NULL);
	#endif
}

// This is a wrapper function that allows older versions of OpenSSL, that use mutable
// pointers to work alongside newer versions of it that use an immutable pointer.
static inline int SSL_EVP_digestVerifyFinal_wrapper(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen) {

	//If version higher than 1.0.2 then it needs to use immutable version of sig
	#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL)
		return EVP_DigestVerifyFinal(ctx, sig, siglen);
	#else
		// Need to make sig immutable for under 1.0.2
		return EVP_DigestVerifyFinal(ctx, sig, siglen);
	#endif

}

#endif
