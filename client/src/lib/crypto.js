// Crypto matching Go backend: ed25519 -> X25519 sealed box + signatures.
// Backend: EncryptMessage uses ephemeral X25519 keypair, ZERO nonce, box.Seal.
// Account ID = "05" + hex(ed25519 pubkey).
import nacl from 'tweetnacl'
import ed2curve from 'ed2curve'

const te = new TextEncoder()
const td = new TextDecoder()

export function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function fromHex(hex) {
  if (hex.length % 2 !== 0) throw new Error('bad hex length')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export function toB64(bytes) {
  let s = ''
  const CH = 0x8000
  for (let i = 0; i < bytes.length; i += CH) {
    s += String.fromCharCode(...bytes.subarray(i, i + CH))
  }
  return btoa(s)
}

export function fromB64(b64) {
  const s = atob(b64)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

export function generateKeys() {
  const kp = nacl.sign.keyPair()
  const publicKeyHex = toHex(kp.publicKey)
  const secretKeyHex = toHex(kp.secretKey)
  const accountId = '05' + publicKeyHex
  return { publicKeyHex, secretKeyHex, accountId }
}

/** accountId ("05"+hex) or raw hex pubkey -> 32-byte ed25519 pubkey */
export function accountIdToEdPub(accountId) {
  const h = accountId.trim()
  if ((h.length === 66 && h.startsWith('05')) || h.startsWith('05')) {
    const raw = fromHex(h)
    if (raw.length === 33 && raw[0] === 0x05) return raw.slice(1)
  }
  const pub = fromHex(h)
  if (pub.length !== 32) throw new Error('recipient must be 32-byte pubkey hex or 05-prefixed account ID')
  return pub
}

export function pad160(data) {
  const r = data.length % 160
  if (r === 0) return data
  const out = new Uint8Array(data.length + (160 - r))
  out.set(data)
  return out // zero-filled rest
}

export function unpad(data) {
  let end = data.length
  while (end > 0 && data[end - 1] === 0) end--
  return data.slice(0, end)
}

export function buildPackedEmail({ from, to, subject, body }) {
  const json = JSON.stringify({ from, to, timestamp: Math.floor(Date.now() / 1000), subject, body })
  return pad160(te.encode(json))
}

export function parseEmail(padded) {
  return JSON.parse(td.decode(unpad(padded)))
}

/** packed = padded + senderEdPub(32) + sig(64) */
export function packSigned(padded, senderEdPub, sig) {
  const out = new Uint8Array(padded.length + 32 + 64)
  out.set(padded, 0)
  out.set(senderEdPub, padded.length)
  out.set(sig, padded.length + 32)
  return out
}

export function unpackSigned(opened) {
  if (opened.length < 96) throw new Error('packed too short')
  return {
    padded: opened.slice(0, opened.length - 96),
    senderPub: opened.slice(opened.length - 96, opened.length - 64),
    sig: opened.slice(opened.length - 64),
  }
}

/** sealed payload = ephPub(32) + zeroNonce(24) + box(packed) — mirrors Go box.Seal */
export function encryptFor(packed, recipientEdPub) {
  const recipX = ed2curve.convertPublicKey(recipientEdPub)
  if (!recipX) throw new Error('bad recipient key (ed->x25519 failed)')
  const eph = nacl.box.keyPair()
  const nonce = new Uint8Array(24) // zeros, like Go's `var nonce [24]byte`
  const sealed = nacl.box(packed, nonce, recipX, eph.secretKey)
  const out = new Uint8Array(32 + 24 + sealed.length)
  out.set(eph.publicKey, 0)
  out.set(nonce, 32)
  out.set(sealed, 56)
  return out
}

export function decryptWith(payload, mySecretKey64) {
  if (payload.length < 72) throw new Error('payload too short')
  const ephPub = payload.slice(0, 32)
  const nonce = payload.slice(32, 56)
  const ct = payload.slice(56)
  const myX = ed2curve.convertSecretKey(mySecretKey64)
  if (!myX) throw new Error('bad secret key (ed->x25519 failed)')
  const opened = nacl.box.open(ct, nonce, ephPub, myX)
  if (!opened) throw new Error('decrypt failed (wrong key or tampered)')
  return opened
}

/** X-Signature over "recipient:timestamp" */
export function signChallenge(recipient, timestamp, secretKey64) {
  return toHex(nacl.sign.detached(te.encode(`${recipient}:${timestamp}`), secretKey64))
}
