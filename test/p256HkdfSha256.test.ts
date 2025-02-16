import { p256HkdfSha256KEM } from "../src/p256HkdfSha256"
import { aesGcmTest, selfTest } from "./kem"

test("self test", () => {
  selfTest(p256HkdfSha256KEM)
})

test("xwing_aes-gcm test", () => {
  aesGcmTest(p256HkdfSha256KEM, "hello, Bob")
})
