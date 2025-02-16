import { xwingKem } from "../src/xwing"
import { aesGcmTest, selfTest } from "./kem"

test("self test", () => {
  selfTest(xwingKem)
})

test("xwing_aes-gcm test", () => {
  aesGcmTest(xwingKem, "hello, Bob")
})
