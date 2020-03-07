const sodium = require('sodium-native')
const assert = require('assert')
const zero = sodium.sodium_memzero

module.exports = encoder
module.exports.encryptionKey = encryptionKey
module.exports.KEYBYTES = sodium.crypto_secretbox_KEYBYTES

function encoder (encryptionKey, opts = {}) {
  assert(Buffer.isBuffer(encryptionKey), 'encryption key must be a buffer')
  // assert(encryptionKey.length === sodium.crypto_secretbox_KEYBYTES, `cobox-crypto: key must be a buffer of length ${sodium.crypto_secretbox_KEYBYTES}`)

  opts.valueEncoding = _resolveStringEncoder(opts.valueEncoding)

  const nonce = opts.nonce || generateNonce()

  return {
    encode (message, buffer, offset) {
      // Run originally provided encoder if any
      if (opts.valueEncoding && typeof opts.valueEncoding.encode === 'function') {
        message = opts.valueEncoding.encode(message, buffer, offset)
      }
      const ciphertext = sodium.sodium_malloc(message.length)
      sodium.crypto_stream_chacha20_xor(ciphertext, message, nonce, encryptionKey)
      return ciphertext
    },

    decode (ciphertext, start, end) {
      const message = sodium.sodium_malloc(ciphertext.length)
      sodium.crypto_stream_chacha20_xor(message, ciphertext, nonce, encryptionKey)
      // Run originally provided encoder if any
      if (opts.valueEncoding && typeof opts.valueEncoding.decode === 'function') {
        return opts.valueEncoding.decode(message, start, end)
      } else {
        return message
      }
    },
    nonce
  }
}

function encryptionKey () {
  const key = sodium.sodium_malloc(sodium.crypto_stream_KEYBYTES)
  sodium.randombytes_buf(key)
  return key
}

function _resolveStringEncoder (encoder) {
  if (encoder === 'json') {
    return {
      encode: (msg) => Buffer.from(JSON.stringify(msg)),
      decode: (msg) => JSON.parse(msg.toString())
    }
  }

  if ((encoder === 'utf-8') || (encoder === 'utf8')) {
    return {
      encode: (msg) => Buffer.from(msg),
      decode: (msg) => msg.toString()
    }
  }
  return encoder
}

function generateNonce () {
  const nonce = Buffer.alloc(sodium.crypto_stream_NONCEBYTES)
  sodium.randombytes_buf(nonce)
  return nonce
}
