/**
 * Client-side cryptography - all sensitive ops happen in the browser
 * Uses Web Crypto API. Master key never leaves the client.
 */

export const PBKDF2_ITERATIONS_LEGACY = 120000; // for existing users
export const PBKDF2_ITERATIONS = 600000; // OWASP recommendation for new users
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 256;

/**
 * Derive encryption key from master phrase using PBKDF2
 */
async function deriveKey(masterPhrase, saltBase64, iterations = PBKDF2_ITERATIONS) {
  const salt = typeof saltBase64 === 'string' ? b64decode(saltBase64) : saltBase64;
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(masterPhrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
  return key;
}

/**
 * Generate a strong random password (16 chars: upper, lower, digits, symbols)
 */
export function generatePassword(length = 16) {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghjkmnpqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#$%&*';
  const all = upper + lower + digits + symbols;

  const bytes = new Uint8Array(length * 2);
  crypto.getRandomValues(bytes);

  const chars = [];
  chars.push(upper[bytes[0] % upper.length]);
  chars.push(lower[bytes[1] % lower.length]);
  chars.push(digits[bytes[2] % digits.length]);
  chars.push(symbols[bytes[3] % symbols.length]);

  for (let i = 4; i < length; i++) {
    chars.push(all[bytes[i * 2] % all.length]);
  }

  for (let i = chars.length - 1; i > 0; i--) {
    const j = bytes[i * 2 + 1] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

/**
 * Generate 12 random words from BIP39 wordlist
 */
export function generateMasterKey(wordlist) {
  const words = [];
  const rng = new Uint32Array(12);
  crypto.getRandomValues(rng);
  for (let i = 0; i < 12; i++) {
    words.push(wordlist[rng[i] % wordlist.length]);
  }
  return words.join(' ');
}

export function generateSalt() {
  const salt = new Uint8Array(SALT_LENGTH);
  crypto.getRandomValues(salt);
  return b64encode(salt);
}

/**
 * Login hash - SHA-256(masterPhrase) - used to find user, no salt needed
 */
export async function computeLoginHash(masterPhrase) {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(masterPhrase));
  return b64encode(new Uint8Array(hash));
}

/**
 * Auth hash - SHA-256(masterPhrase + salt) - used for vault authentication
 */
export async function computeAuthHash(masterPhrase, salt) {
  const enc = new TextEncoder();
  const data = enc.encode(masterPhrase + salt);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return b64encode(new Uint8Array(hash));
}

export async function encryptVault(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: AUTH_TAG_LENGTH * 8 },
    key,
    enc.encode(plaintext)
  );
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return b64encode(combined);
}

export async function decryptVault(ciphertextB64, key) {
  const combined = b64decode(ciphertextB64);
  const iv = combined.slice(0, IV_LENGTH);
  const data = combined.slice(IV_LENGTH);
  const dec = new TextDecoder();
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: AUTH_TAG_LENGTH * 8 },
    key,
    data
  );
  return dec.decode(plaintext);
}

/**
 * Setup for a new user: returns { salt, loginHash, authHash }
 */
export async function setupNewUser(masterPhrase) {
  const salt = generateSalt();
  const loginHash = await computeLoginHash(masterPhrase);
  const authHash = await computeAuthHash(masterPhrase, salt);
  return { salt, loginHash, authHash };
}

/**
 * Get derived key and auth hash for existing user (login)
 */
export async function deriveFromMaster(masterPhrase, salt, iterations) {
  const iter = iterations ?? PBKDF2_ITERATIONS;
  const key = await deriveKey(masterPhrase, salt, iter);
  const authHash = await computeAuthHash(masterPhrase, salt);
  return { key, authHash };
}

/**
 * Setup for email+password user: returns { salt, loginHash, authHash }
 * loginHash = SHA256(email) for lookup, authHash = SHA256(password + salt)
 */
export async function setupNewUserEmail(email, password) {
  const salt = generateSalt();
  const loginHash = await computeLoginHash(email.trim().toLowerCase());
  const authHash = await computeAuthHash(password, salt);
  return { salt, loginHash, authHash };
}

/**
 * Derive key and auth hash for email+password login
 */
export async function deriveFromPassword(password, salt, iterations) {
  const iter = iterations ?? PBKDF2_ITERATIONS;
  const key = await deriveKey(password, salt, iter);
  const authHash = await computeAuthHash(password, salt);
  return { key, authHash };
}

/**
 * Password strength: 0-100 based on length, variety, patterns
 */
export function passwordStrength(pwd) {
  if (!pwd || pwd.length === 0) return 0;
  let score = 0;
  const len = pwd.length;
  score += Math.min(len * 4, 40); // length: up to 40 pts for 10+ chars
  if (/[a-z]/.test(pwd)) score += 10;
  if (/[A-Z]/.test(pwd)) score += 10;
  if (/[0-9]/.test(pwd)) score += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) score += 15;
  if (len >= 12) score += 5;
  if (len >= 16) score += 5;
  // Penalize common patterns
  if (/(.)\1{2,}/.test(pwd)) score -= 15; // repeated chars
  if (/^(123|abc|qwerty|password)/i.test(pwd)) score -= 20;
  if (/^\d+$/.test(pwd)) score -= 25; // all digits
  return Math.max(0, Math.min(100, score));
}

/**
 * Check if password appears in known breaches (HIBP k-anonymity API)
 * Password never leaves the device - only first 5 chars of SHA-1 hash are sent
 */
export async function checkPasswordBreach(password) {
  if (!password || password.length < 4) return { breached: false };
  const enc = new TextEncoder();
  const data = enc.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashHex = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);
  try {
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' },
    });
    if (!res.ok) return { breached: false };
    const text = await res.text();
    const lines = text.split('\r\n');
    for (const line of lines) {
      const [part, countStr] = line.split(':');
      if (part === suffix) {
        return { breached: true, count: parseInt(countStr || '0', 10) };
      }
    }
    return { breached: false };
  } catch {
    return { breached: false, error: true };
  }
}

function b64encode(buf) {
  const arr = new Uint8Array(buf);
  let binary = '';
  const chunk = 8192;
  for (let i = 0; i < arr.length; i += chunk) {
    binary += String.fromCharCode.apply(null, arr.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function b64decode(str) {
  const binary = atob(str);
  const arr = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) arr[i] = binary.charCodeAt(i);
  return arr;
}
