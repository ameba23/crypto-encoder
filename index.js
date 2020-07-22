const sodium = require('sodium-native')
const assert = require('assert')
const codecs = require('codecs')

module.exports = encoder
module.exports.encryptionKey = encryptionKey
module.exports.KEYBYTES = sodium.crypto_stream_KEYBYTES
module.exports.generateNonce = function () {
  const nonce = Buffer.alloc(sodium.crypto_stream_NONCEBYTES)
  sodium.randombytes_buf(nonce)
  return nonce
}

function encoder (encryptionKey, opts = {}) {
  assert(Buffer.isBuffer(encryptionKey), 'encryption key must be a buffer')
  assert(encryptionKey.length === sodium.crypto_stream_KEYBYTES, `Key must be a buffer of length ${sodium.crypto_stream_KEYBYTES}`)

  const encoder = codecs(opts.valueEncoding)

  const nonce = opts.nonce
  assert(nonce, 'Nonce must be provided')

  const encryptOrDecrypt = function (data) {
    sodium.crypto_stream_xor(data, data, nonce, encryptionKey)
    return data
  }

  return {
    encode (message, buffer, offset) {
      return encryptOrDecrypt(encoder.encode(message, buffer, offset))
    },
    decode (message, start, end) {
      return encoder.decode(encryptOrDecrypt(message), start, end)
    }
  }
}

function encryptionKey () {
  const key = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)
  return key
}
