import { x448HkdfSha256KEM } from "../src/x448HkdfSha256"
import { aesGcmTest, selfTest } from "./kem"

test("self test", () => {
  selfTest(x448HkdfSha256KEM)
})

test("xwing_aes-gcm test", () => {
  aesGcmTest(x448HkdfSha256KEM, "hello, Bob")
})
