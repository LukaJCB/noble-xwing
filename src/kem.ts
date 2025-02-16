export type Encoder<T> = (t: T) => Uint8Array

export type KEM<SS, CT, PK, SK> = {
  keygen: () => { pk: PK; sk: SK }
  encapsulate: (pk: PK) => { ss: SS; ct: CT }
  decapsulate: (ct: CT, sk: SK) => SS

  encodeSS: Encoder<SS>
  encodeCT: Encoder<CT>
  encodePK: Encoder<PK>
  encodeSK: Encoder<SK>
}
