export function simulateKyberAesDecrypt(ciphertext) {
  try {
    const match = ciphertext.match(/^\ud83d\udd12\[[a-fA-F0-9]{32}\](.+)$/);
    if (!match) return null;
    const base64 = match[1];
    return decodeURIComponent(escape(Buffer.from(base64, 'base64').toString()));
  } catch (err) {
    console.error("Decryption error:", err);
    return null;
  }
}
