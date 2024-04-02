import hashlib

filename = "vericat.py"
f = open(filename, "rb")
data = f.read()

md5 = hashlib.md5(data)
sha1 = hashlib.sha1(data)
sha256 = hashlib.sha256(data)
sha384 = hashlib.sha384(data)
sha512 = hashlib.sha512(data)

print("md5: ",    md5.hexdigest())
print("sha1: ",   sha1.hexdigest())
print("sha256: ", sha256.hexdigest())
print("sha384: ", sha384.hexdigest())
print("sha512: ", sha512.hexdigest())