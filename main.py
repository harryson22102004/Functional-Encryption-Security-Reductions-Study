import hashlib, os, hmac
 
# Inner-Product Functional Encryption (simplified simulation)
class IPFE:
    """Simplified Inner-Product FE: Dec(sk_y, ct_x) = <x,y>"""
    def __init__(self, n, p=2**31-1):
        self.n=n; self.p=p
    def setup(self):
        self.msk=[int.from_bytes(os.urandom(8),'big')%self.p for _ in range(self.n)]
        return self.msk
    def keygen(self, y):
        """sk_y = sum(msk_i * y_i) mod p"""
        return sum(m*yi for m,yi in zip(self.msk,y)) % self.p
    def encrypt(self, x):
        """ct = (r, c_i = r*msk_i + x_i) for random r"""
        r=int.from_bytes(os.urandom(8),'big')%self.p
        return r, [(r*m+xi)%self.p for m,xi in zip(self.msk,x)]
    def decrypt(self, ct, sk_y, y):
        r,cs=ct
        val=(sum(c*yi for c,yi in zip(cs,y)) - r*sk_y) % self.p
        return val  # = <x,y> mod p
 
fe=IPFE(4)
fe.setup()
x=[3,1,4,1]; y=[1,5,9,2]
expected=sum(xi*yi for xi,yi in zip(x,y))
sk=fe.keygen(y); ct=fe.encrypt(x)
result=fe.decrypt(ct,sk,y)
print(f"<x,y> = {expected}")
print(f"FE decryption: {result}")
print(f"Correct: {result%fe.p == expected%fe.p}")
