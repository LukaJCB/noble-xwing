import { ml_kem768 } from "@noble/post-quantum/ml-kem"
import { randomBytes } from "@noble/post-quantum/utils"
import { sha3_256, shake256 } from "@noble/hashes/sha3"

import { x25519 } from "@noble/curves/ed25519"
import { KEM } from "./kem"

// function id<A>(a: A) {
//   return a
// }

export type XwingKem = KEM<Uint8Array, Uint8Array, Uint8Array, Uint8Array>

// export const xwingSparseKem: XwingKem = {
//   keygen: keygen,
//   encapsulate: encapsulate,
//   decapsulate: decapsulate,
//   encodeSS: id,
//   encodeCT: id,
//   encodePK: id,
//   encodeSK: id,
// }

// const mlKemPublicKeyLength = 1184
// const mlKemPrivateKeyLength = 2400
// const x25519PrivateKeyLength = 32
// const x25519PublicKeyLength = 32

function expandDecapsulationKey(seed: Uint8Array): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] {
  const expanded = shake256(seed, { dkLen: 96 })
  const { publicKey: pkM, secretKey: skM } = ml_kem768.keygen(expanded.subarray(0, 64))
  const skX = expanded.subarray(64, 96)
  const pkX = x25519.getPublicKey(skX)
  return [skM, skX, pkM, pkX]
}

export function generateKeyPair(seed: Uint8Array = randomBytes(32)): [Uint8Array, Uint8Array] {
  const [, , pkM, pkX] = expandDecapsulationKey(seed)
  return [seed, new Uint8Array([...pkM, ...pkX])]
}

const xWingLabel = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]

function combiner(ssM: Uint8Array, ssX: Uint8Array, ctX: Uint8Array, pkX: Uint8Array) {
  return sha3_256(new Uint8Array([...ssM, ...ssX, ...ctX, ...pkX, ...xWingLabel]))
}

// function decodePublicKey(publicKey: Uint8Array): [Uint8Array, Uint8Array] {

//   return [publicKey.subarray(0, mlKemPublicKeyLength), publicKey.subarray(mlKemPublicKeyLength, mlKemPublicKeyLength + x25519PublicKeyLength)]
// }

// function decodePrivateKey(privateKey: Uint8Array): [Uint8Array, Uint8Array] {
//   return [privateKey.subarray(0, mlKemPrivateKeyLength), privateKey.subarray(mlKemPrivateKeyLength, mlKemPrivateKeyLength + x25519PrivateKeyLength)]
// }

export function encapsulate(publicKey: Uint8Array, eseed: Uint8Array = randomBytes(64)): [Uint8Array, Uint8Array] {
  const pkM = publicKey.subarray(0, 1184)
  const pkX = publicKey.subarray(1184, 1216)
  const ekX = eseed.subarray(32, 64)
  const ctX = x25519.getPublicKey(ekX)
  const ssX = x25519.getSharedSecret(ekX, pkX)

  const { cipherText: ctM, sharedSecret: ssM } = ml_kem768.encapsulate(pkM, eseed.subarray(0, 32))

  const ss = combiner(ssM, ssX, ctX, pkX)

  return [ss, new Uint8Array([...ctM, ...ctX])]
}

export function decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const [skM, skX, , pkX] = expandDecapsulationKey(secretKey)
  const ctM = cipherText.subarray(0, 1088)
  const ctX = cipherText.subarray(1088, 1120)
  const ssM = ml_kem768.decapsulate(ctM, skM)

  const ssX = x25519.getSharedSecret(skX, ctX)

  return combiner(ssM, ssX, ctX, pkX)
}

// function keygen(): { pk: XwingPublicKey; sk: XwingPrivateKey } {
//   const seed = randomBytes(96)
//   const mlKemKeyPair = ml_kem768.keygen(seed.subarray(0, 64))
//   const ecdhPrivateKey = seed.subarray(64, 96)
//   const ecdhPublicKey = x25519.getPublicKey(ecdhPrivateKey)

//   return {
//     pk: { ecdhPublicKey, mlKemPublicKey: mlKemKeyPair.publicKey },
//     sk: {
//       ecdhPublicKey,
//       ecdhPrivateKey,
//       mlKemPrivateKey: mlKemKeyPair.secretKey,
//     },
//   }
// }
