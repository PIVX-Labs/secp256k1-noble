import wrapper from './lib/index.js'
import * as noble from './lib/noble.mjs'

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
} = (wrapper(noble));
