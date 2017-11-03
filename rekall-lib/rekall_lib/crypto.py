"""Various cryptography helpers.


AppEngine can only use PyCrypto so here we implement the same SerializedObject
as the agent using that library.
"""

from rekall_lib import serializer
from rekall_lib import utils
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

# Needed to make PyInstaller include these modules.
from Crypto.Cipher import ARC2
from Crypto.Cipher import DES

rng = Random.new().read


class CipherError(TypeError):
    """Denotes a crypto error."""


class RSAPublicKey(serializer.SerializedObject):
    _value = None

    def to_primitive(self, with_type=True):
        if not self._value:
            raise RuntimeError("Key not initialized yet.")

        return utils.SmartUnicode(self._value.exportKey("PEM"))

    @classmethod
    def from_primitive(cls, pem_string, session=None):
        result = cls(session)
        try:
            result._value = RSA.importKey(utils.SmartStr(pem_string))
        except (TypeError, ValueError) as e:
            raise CipherError("Public Key invalid: %s" % e)
        return result

    def from_raw_key(self, value):
        self._value = value
        return self

    def verify(self, message, signature):
        hash = SHA256.new(message)
        signer = PKCS1_v1_5.new(self._value)
        return signer.verify(hash, signature)

    def client_id(self):
        return "C.%s" % (SHA256.new(self._value.publickey().exportKey(
            "PEM")).hexdigest()[:16])

    def __str__(self):
        return self.to_json()

    def __repr__(self):
        digest = SHA256.new(self.to_primitive()).hexdigest()
        return "<%s (%s)>" % (self.__class__.__name__, digest)

    def __bool__(self):
        return bool(self._value)


class RSAPrivateKey(serializer.SerializedObject):
    """A type representing an private key."""

    _value = ""

    def generate_key(self):
        self._value = RSA.generate(2048)
        self._signal_modified()
        return self

    def to_primitive(self, with_type=True):
        if not self._value:
            raise RuntimeError("Key not initialized yet.")

        return utils.SmartUnicode(self._value.exportKey("PEM"))

    @classmethod
    def from_primitive(cls, pem_string, session=None):
        result = cls(session=session)
        try:
            result._value = RSA.importKey(utils.SmartUnicode(pem_string))
        except (TypeError, ValueError) as e:
            raise CipherError("Private Key invalid: %s" % e)

        return result

    def public_key(self):
        return RSAPublicKey(session=self._session).from_raw_key(
            self._value.publickey())

    def sign(self, message):
        hash = SHA256.new(message)
        signer = PKCS1_v1_5.new(self._value)
        return signer.sign(hash)

    def __bool__(self):
        return bool(self._value)


class HTTPAssertion(serializer.SerializedObject):
    """An assertion that will be signed with the HTTPSignature."""
    schema = [
        dict(name="timestamp", type="epoch"),
        dict(name="url"),
    ]


class HTTPSignature(serializer.SerializedObject):
    """A message used to sign the data delivered in HTTPLocation.write_file().

    The message is delivered in the x-rekall-signature header. Note that due to
    limitations with the AppEngine environment we must use PyCrypto and this
    does not support all the cryptography primitives.
    """
    schema = [
        dict(name="client_id",
             doc="The client id this message came from."),
        dict(name="public_key", type=RSAPublicKey,
             doc="The public key in PEM format."),
        dict(name="signature", type="bytes"),
        dict(name="assertion"),
    ]
