import { KEM } from "./kem"
import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha256"
import { p256 } from "@noble/curves/p256"

export type P256HkdfSha256KEM = KEM<Uint8Array, Uint8Array, Uint8Array, Uint8Array>

function id<A>(a: A) {
  return a
}

export const p256HkdfSha256KEM: P256HkdfSha256KEM = {
  keygen: keygen,
  encapsulate: encapWithEph,
  decapsulate: decapWithEph,
  encodeSS: id,
  encodeCT: id,
  encodePK: id,
  encodeSK: id,
}

function keygen() {
  const sk = p256.utils.randomPrivateKey()

  return { sk: sk, pk: p256.getPublicKey(sk) }
}

function encapWithEph(pk: Uint8Array) {
  const esk = p256.utils.randomPrivateKey()
  const kex_res_eph = p256.getSharedSecret(esk, pk)

  const encapped_key = p256.getPublicKey(esk)

  const kem_context = new Uint8Array([...encapped_key, ...pk])

  return {
    ss: hkdf(sha256, kex_res_eph, undefined, kem_context, 32),
    ct: encapped_key,
  }
}

function decapWithEph(ct: Uint8Array, sk: Uint8Array) {
  const kex_res_eph = p256.getSharedSecret(sk, ct)
  const pk_recip = p256.getPublicKey(sk)

  const kem_context = new Uint8Array([...ct, ...pk_recip])

  return hkdf(sha256, kex_res_eph, undefined, kem_context, 32)
}

export function encapsulateWithSenderKey(
  publicKeyRecipient: Uint8Array,
  publicKeySender: Uint8Array,
  secretKeySender: Uint8Array,
) {
  const sk_eph = p256.utils.randomPrivateKey()

  const kex_res_eph = p256.getSharedSecret(sk_eph, publicKeyRecipient)

  const encapped_key = p256.getPublicKey(sk_eph)

  const kem_context = new Uint8Array([...encapped_key, ...publicKeyRecipient, ...publicKeySender])

  const kex_res_identity = p256.getSharedSecret(secretKeySender, publicKeyRecipient)

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
  const kex_res_eph = p256.getSharedSecret(secretKeyRecipient, encapsulatedKey)
  const pk_recip = p256.getPublicKey(secretKeyRecipient)

  const kem_context = new Uint8Array([...encapsulatedKey, ...pk_recip, ...publicKeySender])

  const kex_res_identity = p256.getSharedSecret(secretKeyRecipient, publicKeySender)

  const concatted_secrets = new Uint8Array([...kex_res_eph, ...kex_res_identity])

  return hkdf(sha256, concatted_secrets, undefined, kem_context, 32)
}
