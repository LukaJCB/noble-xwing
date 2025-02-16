import { x25519HkdfSha256KEM } from "../src/x25519HkdfSha256"
import { aesGcmTest, selfTest } from "./kem"

test("self test", () => {
  selfTest(x25519HkdfSha256KEM)
})

test("xwing_aes-gcm test", () => {
  aesGcmTest(x25519HkdfSha256KEM, "hello, Bob")
})
