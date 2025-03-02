import { x25519 } from "@noble/curves/ed25519"
import { KEM } from "./kem"
import { hkdfSha256KemForDH } from "./dhKemHkdfSha256"
import { DH } from "./dh"

const x25519DH: DH = {
  genSecretKey: () => x25519.utils.randomPrivateKey(),
  publicKey: x25519.getPublicKey,
  exchange: x25519.getSharedSecret,
}

export const x25519HkdfSha256KEM: KEM<Uint8Array, Uint8Array, Uint8Array, Uint8Array> = hkdfSha256KemForDH(x25519DH)
