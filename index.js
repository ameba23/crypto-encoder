const sodium = require('sodium-native')
const assert = require('assert')
const codecs = require('codecs')
const zero = sodium.sodium_memzero

module.exports = encoder
module.exports.encryptionKey = encryptionKey
module.exports.KEYBYTES = sodium.crypto_secretbox_KEYBYTES

function encoder (encryptionKey, opts = {}) {
  assert(Buffer.isBuffer(encryptionKey), 'encryption key must be a buffer')
  assert(encryptionKey.length === sodium.crypto_secretbox_KEYBYTES, `cobox-crypto: key must be a buffer of length ${sodium.crypto_secretbox_KEYBYTES}`)

  const encoder = codecs(opts.valueEncoding)

  return {
    encode (message, buffer, offset) {
      // Run originally provided encoder if any
      if (opts.valueEncoding) message = encoder.encode(message, buffer, offset)
      if (!Buffer.isBuffer(message)) message = Buffer.from(message, 'utf-8')
      const ciphertext = Buffer.alloc(message.length + sodium.crypto_secretbox_MACBYTES)
      const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
      sodium.randombytes_buf(nonce)
      sodium.crypto_secretbox_easy(ciphertext, message, nonce, encryptionKey)
      zero(message)
      return Buffer.concat([nonce, ciphertext])
    },

    decode (buffer, start, end) {
      const nonce = buffer.slice(0, sodium.crypto_secretbox_NONCEBYTES)
      const messageWithMAC = buffer.slice(sodium.crypto_secretbox_NONCEBYTES)
      const message = Buffer.alloc(messageWithMAC.length - sodium.crypto_secretbox_MACBYTES)
      assert(
        sodium.crypto_secretbox_open_easy(message, messageWithMAC, nonce, encryptionKey),
        'Decryption failed!'
      )
      // Run originally provided encoder if any
      if (opts.valueEncoding) return encoder.decode(message, start, end)
      return message
    }
  }
}

function encryptionKey () {
  const key = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)
  return key
}
