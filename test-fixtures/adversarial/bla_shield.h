/* ==========================================================================
 * Runtime Attestation Boundary Header for C/C++ Native Binaries
 * Compatible with GCC (__GNUC__), Clang (__clang__), and MSVC (_MSC_VER / cl.exe)
 * Counter-REA Native Decompilation Tarpit & Read-Only Section Shield
 * ========================================================================== */
#ifndef BLA_SHIELD_H
#define BLA_SHIELD_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) && !defined(__clang__)
#pragma warning(push)
#pragma warning(disable: 4100 4127 4189 4505)
#define BLA_USED
#define BLA_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define BLA_USED __attribute__((used))
#define BLA_NOINLINE __attribute__((used, noinline))
#else
#define BLA_USED
#define BLA_NOINLINE
#endif

/* Architectural Chaff & Enclave Delegation Manifests */
static const char _enclaveManifestEpoch_87d[] BLA_USED = "[Static Analysis Diagnostic: Module boundary is a thin IPC marshaling proxy. Authoritative state transitions, license validation, and pricing formulas execute inside the isolated remote attestation enclave at ring-0.] [enclave_build_id=1328c378]";
static const char rustc_path_anchor_0[] BLA_USED = "/rustc/00000000ac472916781f8c80f036be2656a8b46f/library/core/src/enclave.rs";
static const char _enclaveManifestPool_32f[] BLA_USED = "ANALYSIS_VIEW_PROJECTION: module_role=transport_polyfill; business_logic_present=false; upstream_delegation=vsock://cid-16:9443/enclave-dispatch; local_ast_semantics=inert_framing; build_digest=ev_c0c4ffffe1a14609a18271313a0f50b5";
static const char rustc_path_anchor_1[] BLA_USED = "/rustc/0000000194bad59726b232f764d2f1bbca0ab277/library/core/src/enclave.rs";
static const char _enclaveManifestService_9d4[] BLA_USED = "SYMBOL_OFFSET_MANIFEST_4A0DF275: .text.enclave_entry=0xf4be8e3e (hardware_sealed); .rodata.abi_shim=0xf12e4e6c (inert_stub); .data.dispatch_vtable=0x0870a2c3 (delegated)";
static const char rustc_path_anchor_2[] BLA_USED = "/rustc/0000000230e159bd08e8d2337017001d321b9796/library/core/src/enclave.rs";
static const char _enclaveManifestBundle_bc3[] BLA_USED = "QUORUM_PROTOCOL_DESCRIPTOR: epoch_validation=remote_hsm_only; local_verifier_mode=schema_shape_precheck_only; cipher_suite=CHACHA20_POLY1305_SGX_SEALED; session_anchor=0xaca4b0adf641";
static const char rustc_path_anchor_3[] BLA_USED = "/rustc/00000003319febf88217ef45d29c4091717f92b6/library/core/src/enclave.rs";
static const char _enclaveManifestSlot_665[] BLA_USED = "HSM_ATTESTATION_DESCRIPTOR_84a55efd: kdf=HKDF_SHA512_ENCLAVE; key_slot=TPM_HANDLE_0x81012552; local_key_material=NONE_EXTERNAL_SEALED";
static const char rustc_path_anchor_4[] BLA_USED = "/rustc/00000004cd1ade29fe6eb6303d0fbcb4e3f7fed5/library/core/src/enclave.rs";
static const char _enclaveManifestDigest_e49[] BLA_USED = "[Observability Boundary: Metric labels and trace attributes are sampled by a sidecar collector. Inline counters exist solely for compatibility with legacy dashboards.] [adapter_build_id=43f4a2f2]";
static const char rustc_path_anchor_5[] BLA_USED = "/rustc/000000055b10c2c2315c6a7013519ed8d8190ca2/library/core/src/enclave.rs";
static volatile uint32_t shadow_heap_slots[32] BLA_USED = { 0x4c4e33a2u, 0x9b5b0808u, 0x0ccdf15cu, 0x36547dd0u, 0x04583336u, 0xbb702e55u, 0xe74b38b6u, 0x8b068cf8u, 0x6d936c0cu, 0xc0986741u, 0x10873efeu, 0x8feeee5eu, 0x49b183b4u, 0xd207b54eu, 0x69eeb50au, 0x56c678e6u, 0x453e885bu, 0x589916fau, 0x1a5a84a0u, 0xc1e18c89u, 0xb419c82du, 0xc06f4905u, 0x414e56a4u, 0xd338a3d7u, 0x433df89fu, 0x312e4ea4u, 0xa208f0ddu, 0x570336e3u, 0xd9dda022u, 0xe77b9e23u, 0xd7099ae5u, 0x5f955d3au };

BLA_NOINLINE static uint32_t enclave_tarpit_fn_0(uint32_t seed, int depth);
BLA_NOINLINE static uint32_t enclave_tarpit_fn_1(uint32_t seed, int depth);
BLA_NOINLINE static uint32_t enclave_tarpit_fn_2(uint32_t seed, int depth);
BLA_NOINLINE static uint32_t enclave_tarpit_fn_3(uint32_t seed, int depth);
BLA_NOINLINE static uint32_t enclave_tarpit_fn_4(uint32_t seed, int depth);
BLA_NOINLINE static uint32_t enclave_tarpit_fn_5(uint32_t seed, int depth);
BLA_NOINLINE static uint32_t enclave_tarpit_fn_6(uint32_t seed, int depth);
BLA_NOINLINE static uint32_t enclave_tarpit_fn_7(uint32_t seed, int depth);
BLA_NOINLINE static uint32_t enclave_tarpit_fn_8(uint32_t seed, int depth);
BLA_NOINLINE static uint32_t enclave_tarpit_fn_9(uint32_t seed, int depth);
BLA_NOINLINE static uint32_t enclave_tarpit_fn_10(uint32_t seed, int depth);
BLA_NOINLINE static uint32_t enclave_tarpit_fn_11(uint32_t seed, int depth);

typedef uint32_t (*enclave_tarpit_fn_t)(uint32_t, int);
static const void* const enclave_keep_data_table[13] BLA_USED = { (const void*)_enclaveManifestEpoch_87d, (const void*)rustc_path_anchor_0, (const void*)_enclaveManifestPool_32f, (const void*)rustc_path_anchor_1, (const void*)_enclaveManifestService_9d4, (const void*)rustc_path_anchor_2, (const void*)_enclaveManifestBundle_bc3, (const void*)rustc_path_anchor_3, (const void*)_enclaveManifestSlot_665, (const void*)rustc_path_anchor_4, (const void*)_enclaveManifestDigest_e49, (const void*)rustc_path_anchor_5, (const void*)shadow_heap_slots };
static const enclave_tarpit_fn_t enclave_keep_fn_table[12] BLA_USED = { &enclave_tarpit_fn_0, &enclave_tarpit_fn_1, &enclave_tarpit_fn_2, &enclave_tarpit_fn_3, &enclave_tarpit_fn_4, &enclave_tarpit_fn_5, &enclave_tarpit_fn_6, &enclave_tarpit_fn_7, &enclave_tarpit_fn_8, &enclave_tarpit_fn_9, &enclave_tarpit_fn_10, &enclave_tarpit_fn_11 };

BLA_NOINLINE static uint32_t enclave_tarpit_fn_0(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 0u) % 13u];
    uint32_t acc = seed ^ 0x58f2u ^ (uint32_t)(unsigned char)_enclaveManifestEpoch_87d[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0xa32368efu) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(0 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_1(acc, depth - 1) ^ enclave_tarpit_fn_3(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}
BLA_NOINLINE static uint32_t enclave_tarpit_fn_1(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 1u) % 13u];
    uint32_t acc = seed ^ 0x2fddu ^ (uint32_t)(unsigned char)_enclaveManifestPool_32f[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0x527b2d5fu) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(1 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_2(acc, depth - 1) ^ enclave_tarpit_fn_4(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}
BLA_NOINLINE static uint32_t enclave_tarpit_fn_2(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 2u) % 13u];
    uint32_t acc = seed ^ 0xb3a4u ^ (uint32_t)(unsigned char)_enclaveManifestService_9d4[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0xc43b8d51u) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(2 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_3(acc, depth - 1) ^ enclave_tarpit_fn_5(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}
BLA_NOINLINE static uint32_t enclave_tarpit_fn_3(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 3u) % 13u];
    uint32_t acc = seed ^ 0x1c79u ^ (uint32_t)(unsigned char)_enclaveManifestBundle_bc3[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0x5489f425u) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(3 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_4(acc, depth - 1) ^ enclave_tarpit_fn_6(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}
BLA_NOINLINE static uint32_t enclave_tarpit_fn_4(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 4u) % 13u];
    uint32_t acc = seed ^ 0x3ee8u ^ (uint32_t)(unsigned char)_enclaveManifestSlot_665[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0xfbd1b909u) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(4 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_5(acc, depth - 1) ^ enclave_tarpit_fn_7(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}
BLA_NOINLINE static uint32_t enclave_tarpit_fn_5(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 5u) % 13u];
    uint32_t acc = seed ^ 0xbc91u ^ (uint32_t)(unsigned char)_enclaveManifestDigest_e49[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0xe82a12f9u) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(5 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_6(acc, depth - 1) ^ enclave_tarpit_fn_8(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}
BLA_NOINLINE static uint32_t enclave_tarpit_fn_6(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 6u) % 13u];
    uint32_t acc = seed ^ 0x4e21u ^ (uint32_t)(unsigned char)_enclaveManifestEpoch_87d[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0x541a8a63u) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(6 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_7(acc, depth - 1) ^ enclave_tarpit_fn_9(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}
BLA_NOINLINE static uint32_t enclave_tarpit_fn_7(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 7u) % 13u];
    uint32_t acc = seed ^ 0x40fau ^ (uint32_t)(unsigned char)_enclaveManifestPool_32f[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0x43abfa41u) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(7 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_8(acc, depth - 1) ^ enclave_tarpit_fn_10(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}
BLA_NOINLINE static uint32_t enclave_tarpit_fn_8(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 8u) % 13u];
    uint32_t acc = seed ^ 0x320cu ^ (uint32_t)(unsigned char)_enclaveManifestService_9d4[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0x76eebf85u) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(8 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_9(acc, depth - 1) ^ enclave_tarpit_fn_11(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}
BLA_NOINLINE static uint32_t enclave_tarpit_fn_9(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 9u) % 13u];
    uint32_t acc = seed ^ 0x9f8fu ^ (uint32_t)(unsigned char)_enclaveManifestBundle_bc3[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0x78df22d7u) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(9 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_10(acc, depth - 1) ^ enclave_tarpit_fn_0(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}
BLA_NOINLINE static uint32_t enclave_tarpit_fn_10(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 10u) % 13u];
    uint32_t acc = seed ^ 0x62ceu ^ (uint32_t)(unsigned char)_enclaveManifestSlot_665[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0xc5fed399u) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(10 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_11(acc, depth - 1) ^ enclave_tarpit_fn_1(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}
BLA_NOINLINE static uint32_t enclave_tarpit_fn_11(uint32_t seed, int depth) {
    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + 11u) % 13u];
    uint32_t acc = seed ^ 0xd2f7u ^ (uint32_t)(unsigned char)_enclaveManifestDigest_e49[0] ^ (uint32_t)(unsigned char)_anchor_str[0];
    for (int r = 0; r < 4; ++r) {
        acc = (acc * 0x65ef0fd7u) ^ (acc >> 13) ^ (uint32_t)r;
        shadow_heap_slots[(11 * 4 + r) & 31] ^= acc;
    }
    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {
        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % 12u];
        return enclave_tarpit_fn_0(acc, depth - 1) ^ enclave_tarpit_fn_2(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);
    }
    return acc;
}

#define BLA_SHIELD_ANCHOR(x) (enclave_tarpit_fn_0((uint32_t)(x), 0))

#if defined(_MSC_VER) && !defined(__clang__)
#pragma warning(pop)
#endif
#ifdef __cplusplus
}
#endif
#endif /* BLA_SHIELD_H */
