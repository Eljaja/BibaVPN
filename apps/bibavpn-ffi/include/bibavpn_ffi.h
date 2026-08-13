#ifndef BIBAVPN_FFI_H
#define BIBAVPN_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Start embedded SOCKS5 → BibaVPN client (same JSON as Android JNI `nativeStart`).
 * @return 0 on success; non-zero on failure — then `*err_out` is a NUL-terminated
 *         UTF-8 message allocated by Rust; free with `bibavpn_ffi_string_free`.
 */
int32_t bibavpn_ffi_start(const char *config_json_utf8, char **err_out);

/**
 * Stop client if running; idempotent.
 * Returns within ~5s even if the client thread is stuck (shutdown is signalled,
 * then the join is bounded — same as Android JNI `nativeStop`).
 */
void bibavpn_ffi_stop(void);

/**
 * Decode `biba://` invite (same semantics as Android `nativeDecodeInvite`).
 * @return JSON UTF-8 string (always non-null on valid inputs); free with `bibavpn_ffi_string_free`.
 */
char *bibavpn_ffi_decode_invite(const char *uri_utf8, const char *passphrase_utf8);

/** Free strings returned by this library; safe with NULL (no-op). */
void bibavpn_ffi_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* BIBAVPN_FFI_H */
