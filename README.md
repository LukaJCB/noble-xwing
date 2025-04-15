# noble-xwing

Typescript implementation of the X-Wing hybrid Post Quantum KEM using the noble library, as outlined in https://eprint.iacr.org/2024/039.

TL;DR: This library allows the use of a KEM combining the ML-KEM-768 Post Quantum KEM with X25519 ECDH.


# Installation
```bash
# npm
npm install noble-xwing

# yarn
yarn add noble-xwing

# pnpm
pnpm add noble-xwing
```

## Example usage

```typescript
import { generateKeyPair, encapsulate, decapsulate } from "noble-xwing"

const { sk, pk } = generateKeyPair()
const { ss, ct } = encapsulate(pk)

decapsulate(ct, sk)
```
