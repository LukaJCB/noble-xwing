import { ml_kem768 } from "@noble/post-quantum/ml-kem"
import { randomBytes } from "@noble/post-quantum/utils"
import { sha3_256 } from "@noble/hashes/sha3"

import { x25519 } from "@noble/curves/ed25519"
import { KEM } from "./kem"

export type XwingKem = KEM<XwingSharedSecret, XwingCipherText, XwingPublicKey, XwingPrivateKey>

export const xwingKem: XwingKem = {
  keygen: keygen,
  encapsulate: encapsulate,
  decapsulate: decapsulate,
  encodeSS: encodeSharedSecret,
  encodeCT: encodeCipherText,
  encodePK: encodePublicKey,
  encodeSK: encodePrivateKey,
}

export type XwingPublicKey = {
  ecdhPublicKey: Uint8Array
  mlKemPublicKey: Uint8Array
}
export type XwingPrivateKey = {
  ecdhPublicKey: Uint8Array
  ecdhPrivateKey: Uint8Array
  mlKemPrivateKey: Uint8Array
}

export type XwingCipherText = {
  mlKemCipherText: Uint8Array
  ecdhCipherText: Uint8Array
}
export type XwingSharedSecret = {
  mlKemSharedSecret: Uint8Array
  ecdhSharedSecret: Uint8Array
  ecdhCipherText: Uint8Array
  ecdhPublicKey: Uint8Array
}

function encodeSharedSecret(sharedSecret: XwingSharedSecret): Uint8Array {
  return sha3_256(
    new Uint8Array([
      ...[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c],
      ...sharedSecret.mlKemSharedSecret,
      ...sharedSecret.ecdhSharedSecret,
      ...sharedSecret.ecdhCipherText,
      ...sharedSecret.ecdhPublicKey,
    ]),
  )
}

function encodePrivateKey(privateKey: XwingPrivateKey): Uint8Array {
  return new Uint8Array([...privateKey.mlKemPrivateKey, ...privateKey.ecdhPrivateKey, ...privateKey.ecdhPublicKey])
}

function encodePublicKey(publicKey: XwingPublicKey): Uint8Array {
  return new Uint8Array([...publicKey.mlKemPublicKey, ...publicKey.ecdhPublicKey])
}

function encodeCipherText(cipherText: XwingCipherText): Uint8Array {
  return new Uint8Array([...cipherText.mlKemCipherText, ...cipherText.ecdhCipherText])
}

function encapsulate(publicKey: XwingPublicKey): {
  ct: XwingCipherText
  ss: XwingSharedSecret
} {
  const { cipherText: ct_m, sharedSecret: ss_m } = ml_kem768.encapsulate(publicKey.mlKemPublicKey)
  const ek_x = x25519.utils.randomPrivateKey()
  const ct_x = x25519.getPublicKey(ek_x)
  const ss_x = x25519.getSharedSecret(ek_x, publicKey.ecdhPublicKey)

  const ct = { mlKemCipherText: ct_m, ecdhCipherText: ct_x }

  const ss = {
    mlKemSharedSecret: ss_m,
    ecdhSharedSecret: ss_x,
    ecdhCipherText: ct_x,
    ecdhPublicKey: publicKey.ecdhPublicKey,
  }

  return { ct, ss }
}

function decapsulate(cipherText: XwingCipherText, privateKey: XwingPrivateKey): XwingSharedSecret {
  const [sk_m, sk_x, pk_x] = [privateKey.mlKemPrivateKey, privateKey.ecdhPrivateKey, privateKey.ecdhPublicKey]
  const ss_m = ml_kem768.decapsulate(cipherText.mlKemCipherText, sk_m)

  const ss_x = x25519.getSharedSecret(sk_x, cipherText.ecdhCipherText)

  return {
    mlKemSharedSecret: ss_m,
    ecdhSharedSecret: ss_x,
    ecdhCipherText: cipherText.ecdhCipherText,
    ecdhPublicKey: pk_x,
  }
}

function keygen(): { pk: XwingPublicKey; sk: XwingPrivateKey } {
  const seed = randomBytes(96)
  const mlKemKeyPair = ml_kem768.keygen(seed.slice(0, 64))
  const ecdhPrivateKey = seed.slice(64, 96)
  const ecdhPublicKey = x25519.getPublicKey(ecdhPrivateKey)

  return {
    pk: { ecdhPublicKey, mlKemPublicKey: mlKemKeyPair.publicKey },
    sk: {
      ecdhPublicKey,
      ecdhPrivateKey,
      mlKemPrivateKey: mlKemKeyPair.secretKey,
    },
  }
}
