const sodium = require('sodium-native')

const pushState = sodium.crypto_secretstream_xchacha20poly1305_state_new()

const header = generateHeader()
const key = encryptionKey()
const message = Buffer.from('its nice to be important but its more important to be nice')
const ad = null

const ciphertext = sodium.sodium_malloc(message.length + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
const tag = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE

// encrypt:
sodium.crypto_secretstream_xchacha20poly1305_init_push(pushState, header, key)
var mlen = sodium.crypto_secretstream_xchacha20poly1305_push(pushState, ciphertext, message, ad, tag)

const pullState = sodium.crypto_secretstream_xchacha20poly1305_state_new()
const clearMessage = sodium.sodium_malloc(ciphertext.length - sodium.crypto_secretstream_xchacha20poly1305_ABYTES)

// decrypt:
sodium.crypto_secretstream_xchacha20poly1305_init_pull(pullState, header, key)
var clen = sodium.crypto_secretstream_xchacha20poly1305_pull(pullState, clearMessage, tag, ciphertext, ad)
console.log(clearMessage.toString())
  // sodium.crypto_secretstream_xchacha20poly1305_rekey(pullState)

function generateHeader () {
  const header = sodium.sodium_malloc(sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES)
  sodium.randombytes_buf(header)
  return header
}

function encryptionKey () {
  const key = sodium.sodium_malloc(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)
  sodium.crypto_secretstream_xchacha20poly1305_keygen(key)
  return key
}
