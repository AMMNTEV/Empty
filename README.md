# Empty

**Temporary web messenger with no registration.**

No emails, phone numbers, or passwords on the server. Just you, the person you're talking to, and ciphertext.

**Try it →** [Empty](https://ammntev.github.io/Empty)

<img width="1919" height="991" alt="image" src="https://github.com/user-attachments/assets/9973f5c7-ed47-4302-98ac-f894c99c9731" />


---

## What It Is

Empty is a decentralized E2EE messenger that runs right in your browser. All keys are generated locally, all history is stored on the device. The server is used only as a "mailbox" for delivering encrypted messages — it sees neither the text nor who is talking to whom.

## Features

-  **E2EE** — AES-GCM via a shared X25519 key, Ed25519 signatures
-  **QR contacts** — exchange cards via QR code, no searching by nickname
-  **Auto-delete** — a chat lives for 24 hours from the last message
-  **Multi-account** — several identities on one device
-  **Import/export** — transfer an account to another device via QR + temporary password
-  **Local storage** — OPFS, encrypted with a password

## Security

### Algorithms

| Component | Algorithm |
|---|---|
| Key exchange | X25519 |
| Signatures | Ed25519 |
| Message encryption | AES-GCM 256 |
| Identity file encryption | AES-GCM 256 + PBKDF2 (100,000 iterations) |
| Shared key derivation | X25519 + HKDF-SHA-256 |

### What Is Guaranteed

- **Messages are encrypted on the client** before being sent. The server sees only ciphertext.
- **Forging a message on behalf of a contact is impossible** — the Ed25519 signature is verified on the recipient's client.
- **Reading someone else's conversation is impossible** — the recipient's private X25519 key is required.
- **Brute-forcing the key is impossible** — the key space is 2²⁵⁶. Brute-forcing at 10⁹ keys/sec would take ~10⁶⁰ years. Even with a quantum computer (√N = 2¹²⁸) — astronomically long.

## Stack

- **Vanilla JS** + ES modules, no build step
- **@noble/curves** — X25519 + Ed25519
- **WebCrypto** — AES-GCM, PBKDF2, HKDF, SHA-256
- **Firebase Firestore** — relay for messages (ciphertext only)
- **OPFS** — local data storage
- **qrcode-generator** + **jsQR** — QR generation and reading

## How to Use

### Creating an Account

1. Open [Empty](https://ammntev.github.io/Empty).
2. Enter a nickname and password (at least 6 characters).
3. The password is used only to encrypt the local identity file. It is never sent to the server.
4. You land in the messenger right away.

### Adding a Contact

1. One participant opens **"My QR"**.
2. The other opens **"Add Contact"** and points the camera.
3. The contact appears in the list on the left.

### Chatting

1. Click on a contact — the chat opens.
2. Type a message → **"send"** or Enter (on desktop).
3. The chat lives for 24 hours from the last message.
4. **"End Chat"** — deletes the chat for both sides at once.

### Transferring to Another Device

1. Old device: **"My Accounts" → "Transfer Account"**.
2. Create a temporary password → **"Generate QR"**.
3. New device: **"Import" → scan the QR** → enter the temporary password and a new permanent one.
4. The account is transferred.

## Threat Model

**Empty protects against:**

- ✅ Traffic interception (E2EE)
- ✅ The server reading messages
- ✅ Message forgery
- ✅ Password compromise in case of an identity-file leak (PBKDF2 + AES-GCM)
- ✅ Mass spam (PoW + TTL)

**Empty does not protect against:**

- ❌ Device compromise (malware, physical access)
- ❌ Weak passwords (PBKDF2 only gives temporary protection)
- ❌ Metadata
- ❌ Lack of forward secrecy (key compromise reveals the entire conversation)
- ❌ Data loss when clearing the browser

## License

MIT

## Disclaimer

This is a learning/experimental project. Do not use it to transmit truly important data without a prior code audit. The cryptography is built on standard primitives but has not undergone a professional security audit.
