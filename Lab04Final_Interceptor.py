"""
Lab04Final_Interceptor
Diffie-Hellman key exchange + a stateful hash-ratchet PRNG stream cipher,
with an active man-in-the-middle (Mallory).

NOTE: This is a self-contained, runnable REFERENCE. If you are filling in a
starter template, drop each piece of logic below into the spot the template's
comments point to. Keep the class/method names the template gives you; if they
differ from these, move the logic inside them. Do not change code the template
says to leave alone (like get_public_hex()).
"""

import hashlib
import secrets

# ---------------------------------------------------------------------------
# Public Diffie-Hellman parameters (RFC 3526, 2048-bit MODP Group 14).
# These are PUBLIC and shared by everyone. Your template may already define
# p and g -- if so, use the template's values instead of these.
# ---------------------------------------------------------------------------
p = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
g = 2


class SecurePRNG:
    """A hash-ratchet pseudorandom generator (the 'keystream machine')."""

    def init(self, shared_secret_int):
        # Turn the shared number into bytes, then hash to a fixed 32-byte state.
        secret_bytes = str(shared_secret_int).encode()
        self.state = hashlib.sha256(secret_bytes).digest()  # 32 bytes

    def generate(self, n):
        output = b""
        while len(output) < n:
            # The keystream block and the NEXT state come from different inputs,
            # so seeing the keystream never reveals the internal state.
            block = hashlib.sha256(self.state + b"\x00").digest()   # 32 bytes out
            output += block
            self.state = hashlib.sha256(self.state + b"\x01").digest()  # ratchet forward
        return output[:n]


def stream_cipher(data, prng):
    """XOR the data with a keystream from the PRNG.

    Because XOR undoes itself, this SAME function both encrypts and decrypts,
    as long as the PRNG is seeded the same and started fresh.
    """
    keystream = prng.generate(len(data))
    return bytes(b ^ k for b, k in zip(data, keystream))


class Entity:
    """Alice or Bob."""

    def __init__(self, name):
        self.name = name
        self.private = secrets.randbelow(p - 3) + 2     # secret exponent
        self.public = pow(g, self.private, p)           # g^private mod p
        self.prng = None

    def get_public_hex(self):
        # Already provided in your template -- do not change it there.
        return hex(self.public)

    def establish_session(self, other_public_int):
        # shared = (other's public) ^ (my private) mod p
        self.shared_secret = pow(other_public_int, self.private, p)
        self.prng = SecurePRNG()
        self.prng.init(self.shared_secret)


class Mallory:
    """Active man-in-the-middle."""

    def __init__(self):
        self.name = "Mallory"
        self.private = secrets.randbelow(p - 3) + 2
        self.public = pow(g, self.private, p)
        self.secret_with_alice = None
        self.secret_with_bob = None

    def get_public_hex(self):
        return hex(self.public)

    def intercept(self, data, kind, sender=None):
        if kind == "key":
            # Store a shared secret with the REAL sender, then hand back
            # Mallory's OWN public key instead of passing the real one through.
            shared = pow(data, self.private, p)
            if sender == "Alice":
                self.secret_with_alice = shared
            elif sender == "Bob":
                self.secret_with_bob = shared
            return self.public

        elif kind == "message":
            # 1) Decrypt using the Alice-side secret.
            prng_in = SecurePRNG(); prng_in.init(self.secret_with_alice)
            plaintext = stream_cipher(data, prng_in)

            # 2) Tamper: change one word.
            modified = plaintext.replace(b"north", b"south")

            # 3) Re-encrypt with the Bob-side secret so Bob decrypts cleanly.
            prng_out = SecurePRNG(); prng_out.init(self.secret_with_bob)
            new_ciphertext = stream_cipher(modified, prng_out)

            return plaintext, modified, new_ciphertext


def short(h, n=28):
    return h[:n] + "..." if len(h) > n else h


def scenario_a():
    print("=" * 70)
    print("SCENARIO A: Secure session (no attacker)")
    print("=" * 70)

    alice = Entity("Alice")
    bob = Entity("Bob")

    print(f"Alice public key: {short(alice.get_public_hex())}")
    print(f"Bob   public key: {short(bob.get_public_hex())}")

    # They swap public keys and each computes the shared secret.
    alice.establish_session(bob.public)
    bob.establish_session(alice.public)

    print(f"Shared secrets match? {alice.shared_secret == bob.shared_secret}")

    message = b"Meet me at the north gate at midnight."
    print(f"\nAlice's original message: {message.decode()}")

    ciphertext = stream_cipher(message, alice.prng)
    print(f"Encrypted (hex): {ciphertext.hex()}")

    decrypted = stream_cipher(ciphertext, bob.prng)
    print(f"Bob decrypted:   {decrypted.decode()}")
    print(f"Message intact?  {decrypted == message}")
    print()


def scenario_b():
    print("=" * 70)
    print("SCENARIO B: Mallory as man-in-the-middle")
    print("=" * 70)

    alice = Entity("Alice")
    bob = Entity("Bob")
    mallory = Mallory()

    # Key exchange, but Mallory sits in the middle and swaps in her own key.
    key_bob_receives   = mallory.intercept(alice.public, "key", sender="Alice")
    key_alice_receives = mallory.intercept(bob.public,   "key", sender="Bob")

    # Alice and Bob unknowingly share a secret with Mallory, not each other.
    alice.establish_session(key_alice_receives)  # really Mallory's key
    bob.establish_session(key_bob_receives)      # really Mallory's key

    print(f"Do Alice & Bob share the same secret? "
          f"{alice.shared_secret == bob.shared_secret}  (should be False!)")

    message = b"Meet me at the north gate at midnight."
    print(f"\nAlice's ORIGINAL message: {message.decode()}")

    ciphertext = stream_cipher(message, alice.prng)
    print(f"Ciphertext Alice sends (hex): {ciphertext.hex()}")

    # Mallory intercepts, reads, tampers, re-encrypts.
    seen, modified, new_ct = mallory.intercept(ciphertext, "message")
    print(f"\n[Mallory] I can read it:      {seen.decode()}")
    print(f"[Mallory] MODIFIED version:   {modified.decode()}")
    print(f"[Mallory] Re-encrypted (hex): {new_ct.hex()}")

    bob_reads = stream_cipher(new_ct, bob.prng)
    print(f"\nBob decrypted (no error):     {bob_reads.decode()}")
    print(f"Bob got the TAMPERED message? {bob_reads == modified}")
    print()


if __name__ == "__main__":
    scenario_a()
    scenario_b()
