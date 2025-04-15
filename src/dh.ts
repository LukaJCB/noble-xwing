export type DH = {
  genSecretKey: () => Uint8Array
  publicKey: (sk: Uint8Array) => Uint8Array
  exchange: (sk: Uint8Array, pk: Uint8Array) => Uint8Array
}
