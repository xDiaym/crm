from binascii import unhexlify
from Crypto.Util.number import getPrime, inverse, bytes_to_long

def test_simple():
    N = 128
    p1, p2 = getPrime(N), getPrime(N)
    m1, m2 = int.from_bytes(b"hello", "little"), int.from_bytes(b"world", "little")

    assert N.bit_length() < m1.bit_length()
    assert N.bit_length() < m2.bit_length()

    P = p1 * p2
    c = ((m1*p2) % P)*inverse(p2, p1)%P + ((m2*p1)%P)*inverse(p1, p2)%P

    assert c % p1 == m1

"""
c = m1 (mod p1)
c = m2 (mod p2)

c = a1m1 + a2m2
c = p2*b1*m1 + p1*b2*m2
c = p1*b2*m2 = m2 (mod p1) => b2 = p1^-1

c = p2*p1^-1*m1 + p1*p2^-1*m2
"""