import { x25519 } from "@noble/curves/ed25519"
import { KEM } from "./kem"
import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha256"
export type X25519HkdfSha256KEM = KEM<Uint8Array, Uint8Array, Uint8Array, Uint8Array>

function id<A>(a: A) {
  return a
}

export const x25519HkdfSha256KEM: X25519HkdfSha256KEM = {
  keygen: keygen,
  encapsulate: encapWithEph,
  decapsulate: decapWithEph,
  encodeSS: id,
  encodeCT: id,
  encodePK: id,
  encodeSK: id,
}

function keygen() {
  const sk = x25519.utils.randomPrivateKey()

  return { sk: sk, pk: x25519.getPublicKey(sk) }
}

function encapWithEph(pk: Uint8Array) {
  const esk = x25519.utils.randomPrivateKey()
  const kex_res_eph = x25519.getSharedSecret(esk, pk)

  const encapped_key = x25519.getPublicKey(esk)

  const kem_context = new Uint8Array([...encapped_key, ...pk])

  return {
    ss: hkdf(sha256, kex_res_eph, undefined, kem_context, 32),
    ct: encapped_key,
  }
}

function decapWithEph(ct: Uint8Array, sk: Uint8Array) {
  const kex_res_eph = x25519.getSharedSecret(sk, ct)
  const pk_recip = x25519.getPublicKey(sk)

  const kem_context = new Uint8Array([...ct, ...pk_recip])

  return hkdf(sha256, kex_res_eph, undefined, kem_context, 32)
}

export function encapsulateWithSenderKey(
  publicKeyRecipient: Uint8Array,
  publicKeySender: Uint8Array,
  secretKeySender: Uint8Array,
) {
  const sk_eph = x25519.utils.randomPrivateKey()

  const kex_res_eph = x25519.getSharedSecret(sk_eph, publicKeyRecipient)

  const encapped_key = x25519.getPublicKey(sk_eph)

  const kem_context = new Uint8Array([...encapped_key, ...publicKeyRecipient, ...publicKeySender])

  const kex_res_identity = x25519.getSharedSecret(secretKeySender, publicKeyRecipient)

  const concatted_secrets = new Uint8Array([...kex_res_eph, ...kex_res_identity])

  return {
    sharedSecret: hkdf(sha256, concatted_secrets, undefined, kem_context, 32),
    ct: encapped_key,
  }
}

export function decapsulateWithSenderKey(
  secretKeyRecipient: Uint8Array,
  publicKeySender: Uint8Array,
  encapsulatedKey: Uint8Array,
) {
  const kex_res_eph = x25519.getSharedSecret(secretKeyRecipient, encapsulatedKey)
  const pk_recip = x25519.getPublicKey(secretKeyRecipient)

  const kem_context = new Uint8Array([...encapsulatedKey, ...pk_recip, ...publicKeySender])

  const kex_res_identity = x25519.getSharedSecret(secretKeyRecipient, publicKeySender)

  const concatted_secrets = new Uint8Array([...kex_res_eph, ...kex_res_identity])

  return hkdf(sha256, concatted_secrets, undefined, kem_context, 32)
}
