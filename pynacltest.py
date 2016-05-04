import nacl.utils
from nacl.public import PrivateKey, Box

# generate the private key which must be kept secret
skbob = PrivateKey.generate()

# the public key can be given to anyone wishing to send
# Bob an encrypted message
pkbob = skbob.public_key

# Alice does the same and then
#     sends her public key to Bob and Bob his public key to Alice
skalice = PrivateKey.generate()
pkalice = skalice.public_key

# Bob wishes to send Alice an encrypted message
# So Bob must make a Box with his private key and Alice's public key
bob_box = Box(skbob, pkalice)

# This is our message to send, it must be a bytestring as Box will
#   treat is as just a binary blob of data.
message = b"Kill all humans"

# This is a nonce, it *MUST* only be used once, but it is not considered
#   secret and can be transmitted or stored alongside the ciphertext. A
#   good source of nonce is just 24 random bytes.
nonce = nacl.utils.random(Box.NONCE_SIZE)

# Encrypt our message, it will be exactly 40 bytes longer than the original
#   message as it stores authentication information and nonce alongside it.
encrypted = bob_box.encrypt(message, nonce)

# Alice creates a second box with her private key to decrypt the message
alice_box = Box(skalice, pkbob)

# Decrypt our message, an exception will be raised if the encryption was
#   tampered with or there was otherwise an error.
plaintext = alice_box.decrypt(encrypted)

