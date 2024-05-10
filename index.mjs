export const {
  contextRandomize,
  privateKeyVerify,
  privateKeyNegate,
  privateKeyTweakAdd,
  privateKeyTweakMul,
  publicKeyVerify,
  publicKeyConvert,
  publicKeyNegate,
  publicKeyCombine,
  publicKeyCreate,
  publicKeyTweakAdd,
  publicKeyTweakMul,
  signatureNormalize,
  signatureExport,
  signatureImport,
  ecdsaSign,
  ecdsaRecover,
  ecdsaVerify,
  ecdh,
} = (await import("./lib/index.js")).default(await import("./lib/noble.mjs"));
