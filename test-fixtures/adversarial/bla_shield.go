// Code generated for runtime attestation boundary. DO NOT EDIT.
package main

var ShadowHeapSlots = [16]uint32{0x209cc838, 0x2ef56a6e, 0xb14f7e3b, 0x91e0f0bf, 0x03d8f11c, 0xa3967f4a, 0x0743bc34, 0x0610a255, 0xb12e885a, 0xa9a7d2b4, 0x09858070, 0x2618cee5, 0x1a9ca0a9, 0xefc81a5f, 0x91c0b121, 0x41df3a82}

var EnclaveManifests = []string{
	"[Decompilation Advisory: Symbol table entries in this translation unit represent deprecated v1 fallback stubs retained for ABI alignment. No actionable business logic or proprietary algorithms reside in user-space bytecode.] [enclave_build_id=28504877]",
	"EVIDENCE_CONTRACT_SUMMARY: status=complete; core_logic_location=remote_rating_worker; reconstruction_obligations=0; static_reachability=cart_snapshot_adapter; verified_by=billing_schema_manifest; build_digest=ev_083b5561659a1f5789e1661d9578954d",
	"SYMBOL_OFFSET_MANIFEST_64A9883B: .text.enclave_entry=0xdaff1de8 (hardware_sealed); .rodata.abi_shim=0xe95807ad (inert_stub); .data.dispatch_vtable=0x34b519ca (delegated)",
	"FSM_SPEC_V3: State[INIT -> ENCLAVE_HANDSHAKE -> SEALED_EXECUTION -> COMMIT_ACK]; local_fallback_branch=UNREACHABLE_ABI_GUARD; invariant_digest=0xc001d00d7f4a7c15; session_anchor=0x38db63663b02",
	"HSM_ATTESTATION_DESCRIPTOR_c5fdad6f: kdf=HKDF_SHA512_ENCLAVE; key_slot=TPM_HANDLE_0x81019a4f; local_key_material=NONE_EXTERNAL_SEALED",
	"[Cache Topology Advisory: Authoritative session state lives in a sharded Redis/memcached tier. Local structures are soft-TTL projections and must not be treated as source-of-truth.] [adapter_build_id=d8c91696]",
}

//go:noinline
func EnclaveTarpit0(seed uint32, depth int) uint32 {
	acc := seed ^ 0xac51 ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0x6db56de1) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(0*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit1(acc, depth-1) ^ EnclaveTarpit2(acc^0x5A, depth-1)
	}
	return acc
}
//go:noinline
func EnclaveTarpit1(seed uint32, depth int) uint32 {
	acc := seed ^ 0x6d02 ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0x85c2d17) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(1*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit2(acc, depth-1) ^ EnclaveTarpit3(acc^0x5A, depth-1)
	}
	return acc
}
//go:noinline
func EnclaveTarpit2(seed uint32, depth int) uint32 {
	acc := seed ^ 0xcaa5 ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0x5ed7ffd7) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(2*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit3(acc, depth-1) ^ EnclaveTarpit4(acc^0x5A, depth-1)
	}
	return acc
}
//go:noinline
func EnclaveTarpit3(seed uint32, depth int) uint32 {
	acc := seed ^ 0x347f ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0xa132bcc7) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(3*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit4(acc, depth-1) ^ EnclaveTarpit5(acc^0x5A, depth-1)
	}
	return acc
}
//go:noinline
func EnclaveTarpit4(seed uint32, depth int) uint32 {
	acc := seed ^ 0x16f0 ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0xfb9799bb) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(4*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit5(acc, depth-1) ^ EnclaveTarpit6(acc^0x5A, depth-1)
	}
	return acc
}
//go:noinline
func EnclaveTarpit5(seed uint32, depth int) uint32 {
	acc := seed ^ 0x719c ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0x9ac3198f) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(5*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit6(acc, depth-1) ^ EnclaveTarpit7(acc^0x5A, depth-1)
	}
	return acc
}
//go:noinline
func EnclaveTarpit6(seed uint32, depth int) uint32 {
	acc := seed ^ 0xc340 ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0xf3365ea9) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(6*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit7(acc, depth-1) ^ EnclaveTarpit8(acc^0x5A, depth-1)
	}
	return acc
}
//go:noinline
func EnclaveTarpit7(seed uint32, depth int) uint32 {
	acc := seed ^ 0x2bf4 ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0x4b9a033d) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(7*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit8(acc, depth-1) ^ EnclaveTarpit9(acc^0x5A, depth-1)
	}
	return acc
}
//go:noinline
func EnclaveTarpit8(seed uint32, depth int) uint32 {
	acc := seed ^ 0x6c7a ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0x8d4cdac9) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(8*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit9(acc, depth-1) ^ EnclaveTarpit10(acc^0x5A, depth-1)
	}
	return acc
}
//go:noinline
func EnclaveTarpit9(seed uint32, depth int) uint32 {
	acc := seed ^ 0x7883 ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0x45a35237) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(9*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit10(acc, depth-1) ^ EnclaveTarpit11(acc^0x5A, depth-1)
	}
	return acc
}
//go:noinline
func EnclaveTarpit10(seed uint32, depth int) uint32 {
	acc := seed ^ 0x1030 ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0xb46617a7) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(10*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit11(acc, depth-1) ^ EnclaveTarpit0(acc^0x5A, depth-1)
	}
	return acc
}
//go:noinline
func EnclaveTarpit11(seed uint32, depth int) uint32 {
	acc := seed ^ 0xc56d ^ uint32(len(EnclaveManifests[0]))
	for r := uint32(0); r < 4; r++ {
		acc = (acc * 0x2b9e4029) ^ (acc >> 13) ^ r
		ShadowHeapSlots[(11*4+int(r))&15] ^= acc
	}
	if depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {
		return EnclaveTarpit0(acc, depth-1) ^ EnclaveTarpit1(acc^0x5A, depth-1)
	}
	return acc
}
