import { KEM } from "../src/kem"
import { gcm } from "@noble/ciphers/aes"
import { bytesToUtf8, utf8ToBytes } from "@noble/ciphers/utils"
import { randomBytes } from "@noble/post-quantum/utils"

export function selfTest<SS, CT, PK, SK>(kem: KEM<SS, CT, PK, SK>): void {
  const { pk, sk } = kem.keygen()

  const { ss, ct } = kem.encapsulate(pk)
  const rss = kem.decapsulate(ct, sk)

  expect(bytesToUtf8(kem.encodeSS(ss))).toBe(bytesToUtf8(kem.encodeSS(rss)))
}

export function aesGcmTest<SS, CT, PK, SK>(kem: KEM<SS, CT, PK, SK>, plainText: string): void {
  const { pk: pkBob, sk: skBob } = kem.keygen()

  const { ss: ssAlice, ct: encapsulatedKey } = kem.encapsulate(pkBob)

  const nonce = randomBytes(12)
  const ciphertext = gcm(kem.encodeSS(ssAlice), nonce).encrypt(utf8ToBytes(plainText))

  const ssBob = kem.decapsulate(encapsulatedKey, skBob)
  const aesAlice = gcm(kem.encodeSS(ssBob), nonce)
  const decrypted = bytesToUtf8(aesAlice.decrypt(ciphertext))

  expect(plainText).toBe(decrypted)
}
