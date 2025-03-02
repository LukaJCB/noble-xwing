import { KEM } from "./kem"
import { p256 } from "@noble/curves/p256"
import { hkdfSha256KemForDH } from "./dhKemHkdfSha256"
import { DH } from "./dh"

const p256DH: DH = {
  genSecretKey: () => p256.utils.randomPrivateKey(),
  publicKey: p256.getPublicKey,
  exchange: p256.getSharedSecret,
}

export const p256HkdfSha256KEM: KEM<Uint8Array, Uint8Array, Uint8Array, Uint8Array> = hkdfSha256KemForDH(p256DH)
