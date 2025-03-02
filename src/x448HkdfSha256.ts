import { x448 } from "@noble/curves/ed448"
import { KEM } from "./kem"
import { hkdfSha256KemForDH } from "./dhKemHkdfSha256"
import { DH } from "./dh"

const x448DH: DH = {
  genSecretKey: () => x448.utils.randomPrivateKey(),
  publicKey: x448.getPublicKey,
  exchange: x448.getSharedSecret,
}

export const x448HkdfSha256KEM: KEM<Uint8Array, Uint8Array, Uint8Array, Uint8Array> = hkdfSha256KemForDH(x448DH)
