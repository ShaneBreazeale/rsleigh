//! OpenSSL / common crypto library signatures.
//!
//! Top-hit OpenSSL APIs (libcrypto + libssl) plus a handful of POSIX
//! crypto helpers. Bodies are already covered by the bundled openssl
//! FID database; these signatures give the type info the FID match
//! lacks so the decompiler can render `EVP_DigestUpdate(ctx, "abc", 3)`
//! with named typed parameters.

use crate::signatures::*;

pub static CRYPTO_SIGNATURES: &[FuncSig] = crate::define_signatures! {
    // --- libcrypto: EVP digest ---
    fn EVP_MD_CTX_new() -> VoidPtr;
    fn EVP_MD_CTX_free(ctx: VoidPtr);
    fn EVP_MD_CTX_reset(ctx: VoidPtr) -> Int;
    fn EVP_DigestInit_ex(ctx: VoidPtr, type_: VoidPtr, impl_: VoidPtr) -> Int;
    fn EVP_DigestUpdate(ctx: VoidPtr, d: ConstVoidPtr, cnt: SizeT) -> Int;
    fn EVP_DigestFinal_ex(ctx: VoidPtr, md: VoidPtr, s: VoidPtr) -> Int;
    fn EVP_Digest(data: ConstVoidPtr, count: SizeT, md: VoidPtr, size: VoidPtr, type_: VoidPtr, impl_: VoidPtr) -> Int;
    fn EVP_md5() -> VoidPtr;
    fn EVP_sha1() -> VoidPtr;
    fn EVP_sha256() -> VoidPtr;
    fn EVP_sha512() -> VoidPtr;
    fn EVP_get_digestbyname(name: ConstCharPtr) -> VoidPtr;

    // --- libcrypto: EVP cipher ---
    fn EVP_CIPHER_CTX_new() -> VoidPtr;
    fn EVP_CIPHER_CTX_free(ctx: VoidPtr);
    fn EVP_CIPHER_CTX_reset(ctx: VoidPtr) -> Int;
    fn EVP_EncryptInit_ex(ctx: VoidPtr, cipher: VoidPtr, impl_: VoidPtr, key: ConstVoidPtr, iv: ConstVoidPtr) -> Int;
    fn EVP_EncryptUpdate(ctx: VoidPtr, out: VoidPtr, outl: VoidPtr, in_: ConstVoidPtr, inl: Int) -> Int;
    fn EVP_EncryptFinal_ex(ctx: VoidPtr, out: VoidPtr, outl: VoidPtr) -> Int;
    fn EVP_DecryptInit_ex(ctx: VoidPtr, cipher: VoidPtr, impl_: VoidPtr, key: ConstVoidPtr, iv: ConstVoidPtr) -> Int;
    fn EVP_DecryptUpdate(ctx: VoidPtr, out: VoidPtr, outl: VoidPtr, in_: ConstVoidPtr, inl: Int) -> Int;
    fn EVP_DecryptFinal_ex(ctx: VoidPtr, out: VoidPtr, outl: VoidPtr) -> Int;
    fn EVP_aes_128_cbc() -> VoidPtr;
    fn EVP_aes_192_cbc() -> VoidPtr;
    fn EVP_aes_256_cbc() -> VoidPtr;
    fn EVP_aes_128_gcm() -> VoidPtr;
    fn EVP_aes_256_gcm() -> VoidPtr;
    fn EVP_chacha20_poly1305() -> VoidPtr;

    // --- libcrypto: legacy hash one-shot ---
    fn MD5(d: ConstVoidPtr, n: SizeT, md: VoidPtr) -> VoidPtr;
    fn SHA1(d: ConstVoidPtr, n: SizeT, md: VoidPtr) -> VoidPtr;
    fn SHA256(d: ConstVoidPtr, n: SizeT, md: VoidPtr) -> VoidPtr;
    fn SHA512(d: ConstVoidPtr, n: SizeT, md: VoidPtr) -> VoidPtr;
    fn HMAC(evp_md: VoidPtr, key: ConstVoidPtr, key_len: Int, d: ConstVoidPtr, n: SizeT, md: VoidPtr, md_len: VoidPtr) -> VoidPtr;

    // --- libcrypto: random ---
    fn RAND_bytes(buf: VoidPtr, num: Int) -> Int;
    fn RAND_priv_bytes(buf: VoidPtr, num: Int) -> Int;
    fn RAND_seed(buf: ConstVoidPtr, num: Int);
    fn RAND_status() -> Int;

    // --- libcrypto: BN ---
    fn BN_new() -> VoidPtr;
    fn BN_free(a: VoidPtr);
    fn BN_clear_free(a: VoidPtr);
    fn BN_num_bytes(a: VoidPtr) -> Int;
    fn BN_num_bits(a: VoidPtr) -> Int;
    fn BN_bn2bin(a: VoidPtr, to: VoidPtr) -> Int;
    fn BN_bin2bn(s: ConstVoidPtr, len: Int, ret: VoidPtr) -> VoidPtr;
    fn BN_set_word(a: VoidPtr, w: ULong) -> Int;
    fn BN_mod_exp(r: VoidPtr, a: VoidPtr, p: VoidPtr, m: VoidPtr, ctx: VoidPtr) -> Int;

    // --- libcrypto: PKEY / RSA ---
    fn EVP_PKEY_new() -> VoidPtr;
    fn EVP_PKEY_free(pkey: VoidPtr);
    fn EVP_PKEY_size(pkey: VoidPtr) -> Int;
    fn EVP_PKEY_id(pkey: VoidPtr) -> Int;
    fn EVP_PKEY_CTX_new(pkey: VoidPtr, e: VoidPtr) -> VoidPtr;
    fn EVP_PKEY_CTX_free(ctx: VoidPtr);
    fn RSA_new() -> VoidPtr;
    fn RSA_free(rsa: VoidPtr);
    fn RSA_size(rsa: VoidPtr) -> Int;
    fn RSA_public_encrypt(flen: Int, from: ConstVoidPtr, to: VoidPtr, rsa: VoidPtr, padding: Int) -> Int;
    fn RSA_private_decrypt(flen: Int, from: ConstVoidPtr, to: VoidPtr, rsa: VoidPtr, padding: Int) -> Int;
    fn RSA_sign(type_: Int, m: ConstVoidPtr, m_length: UInt, sigret: VoidPtr, siglen: VoidPtr, rsa: VoidPtr) -> Int;
    fn RSA_verify(type_: Int, m: ConstVoidPtr, m_length: UInt, sigbuf: ConstVoidPtr, siglen: UInt, rsa: VoidPtr) -> Int;

    // --- libcrypto: error/init ---
    fn ERR_get_error() -> ULong;
    fn ERR_peek_error() -> ULong;
    fn ERR_clear_error();
    fn ERR_error_string_n(e: ULong, buf: CharPtr, len: SizeT);
    fn OPENSSL_init_crypto(opts: ULong, settings: VoidPtr) -> Int;
    fn OPENSSL_cleanup();

    // --- libssl ---
    fn SSL_CTX_new(method: VoidPtr) -> VoidPtr;
    fn SSL_CTX_free(ctx: VoidPtr);
    fn SSL_CTX_use_certificate_file(ctx: VoidPtr, file: ConstCharPtr, type_: Int) -> Int;
    fn SSL_CTX_use_PrivateKey_file(ctx: VoidPtr, file: ConstCharPtr, type_: Int) -> Int;
    fn SSL_new(ctx: VoidPtr) -> VoidPtr;
    fn SSL_free(ssl: VoidPtr);
    fn SSL_set_fd(ssl: VoidPtr, fd: Int) -> Int;
    fn SSL_connect(ssl: VoidPtr) -> Int;
    fn SSL_accept(ssl: VoidPtr) -> Int;
    fn SSL_read(ssl: VoidPtr, buf: VoidPtr, num: Int) -> Int;
    fn SSL_write(ssl: VoidPtr, buf: ConstVoidPtr, num: Int) -> Int;
    fn SSL_shutdown(ssl: VoidPtr) -> Int;
    fn SSL_get_error(ssl: VoidPtr, ret: Int) -> Int;
    fn TLS_client_method() -> VoidPtr;
    fn TLS_server_method() -> VoidPtr;
    fn TLS_method() -> VoidPtr;

    // --- POSIX crypt / glibc helpers ---
    fn crypt(key: ConstCharPtr, salt: ConstCharPtr) -> CharPtr;
    fn crypt_r(key: ConstCharPtr, salt: ConstCharPtr, data: VoidPtr) -> CharPtr;
    fn arc4random() -> UInt;
    fn arc4random_buf(buf: VoidPtr, nbytes: SizeT);
    fn arc4random_uniform(upper_bound: UInt) -> UInt;
    fn getrandom(buf: VoidPtr, buflen: SizeT, flags: UInt) -> Long;
};
