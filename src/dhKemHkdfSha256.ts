import { DH } from "./dh"
import { KEM } from "./kem"
import { hkdf } from "@noble/hashes/hkdf"
import { sha256 } from "@noble/hashes/sha256"

function id<A>(a: A) {
  return a
}

export function hkdfSha256KemForDH(dh: DH): KEM<Uint8Array, Uint8Array, Uint8Array, Uint8Array> {
  return {
    keygen: () => {
      const sk = dh.genSecretKey()
      return { sk, pk: dh.publicKey(sk) }
    },
    encapsulate: (pk: Uint8Array) => {
      const esk = dh.genSecretKey()

      const encappedKey = dh.publicKey(esk)

      const ssEph = dh.exchange(esk, pk)

      const kemContext = new Uint8Array([...encappedKey, ...pk])

      return {
        ss: hkdf(sha256, ssEph, undefined, kemContext, 32),
        ct: encappedKey,
      }
    },
    decapsulate: (ct: Uint8Array, sk: Uint8Array) => {
      const ssEph = dh.exchange(sk, ct)
      const pkRecip = dh.publicKey(sk)

      const kemContext = new Uint8Array([...ct, ...pkRecip])

      return hkdf(sha256, ssEph, undefined, kemContext, 32)
    },
    encodeSS: id,
    encodeCT: id,
    encodePK: id,
    encodeSK: id,
  }
}
