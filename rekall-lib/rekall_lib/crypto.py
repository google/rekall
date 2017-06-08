import datetime
import hashlib
import time
import struct
from cryptography.x509 import oid

from rekall_lib import serializer
from rekall_lib import utils
from cryptography import x509
from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


class CipherError(ValueError):
    """Raised when decryption failed."""

class VerificationError(CipherError):
    pass

class RSAPublicKey(serializer.SerializedObject):
    """A type representing an encryption key."""

    _value = ""

    def to_primitive(self):
        if not self._value:
            raise RuntimeError("Key not initialized yet.")

        return self._value.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    @classmethod
    def from_primitive(cls, pem_string, session=None):
        result = cls(session=session)
        try:
            result.from_raw_key(serialization.load_pem_public_key(
                utils.SmartStr(pem_string), backend=openssl.backend))
        except (TypeError, ValueError, exceptions.UnsupportedAlgorithm) as e:
            raise CipherError("Public Key invalid: %s" % e)
        return result

    def from_raw_key(self, raw_key):
        self._value = raw_key
        self._signal_modified()
        return self

    def get_raw_key(self):
        return self._value

    def encrypt(self, message):
        if self._value is None:
            raise ValueError("Can't Encrypt with empty key.")

        try:
            return self._value.encrypt(
                    message,
                    padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA1()),
                            algorithm=hashes.SHA1(),
                            label=None))
        except ValueError as e:
            raise CipherError(e)

    def get_verifier(self, signature):
        """Gets an incremental verifier.

        Must call .update() on the verifier and then .verify() to check.
        """
        hash_algorithm = hashes.SHA256()
        padding_algorithm = padding.PKCS1v15()

        return self._value.verifier(signature, padding_algorithm,
                                    hash_algorithm)

    def verify(self, message, signature, hash_algorithm=None):
        if hash_algorithm is None:
            hash_algorithm = hashes.SHA256()

        padding_algorithm = padding.PKCS1v15()
        try:
            verifyer = self._value.verifier(signature, padding_algorithm,
                                            hash_algorithm)
            verifyer.update(message)
            verifyer.verify()
            return True
        except exceptions.InvalidSignature as e:
            pass

        raise VerificationError(e)

    def client_id(self):
        n = self._value.public_numbers().n
        raw_n = ("%x" % n).decode("hex")
        mpi_format = struct.pack(">i", len(raw_n) + 1) + "\x00" + raw_n

        return "C.%s" % (
            hashlib.sha256(mpi_format).digest()[:8].encode("hex"))

    def __str__(self):
        return self.to_json()

    def __repr__(self):
        digest = hashlib.sha256(self.to_primitive()).hexdigest()
        return "<%s (%s)>" % (self.__class__.__name__, digest)

    def __nonzero__(self):
        return bool(self._value)


class X509Ceritifcate(serializer.SerializedObject):
    """An X509 certificate."""

    def from_raw_key(self, raw_key):
        self._value = raw_key
        self._signal_modified()
        return self

    @classmethod
    def from_primitive(cls, pem_string, session=None):
        result = cls(session=session)
        try:
            return result.from_raw_key(x509.load_pem_x509_certificate(
                utils.SmartStr(pem_string), backend=openssl.backend))
        except (TypeError, ValueError, exceptions.UnsupportedAlgorithm) as e:
            raise CipherError("X509 Certificate invalid: %s" % e)
        return result

    def to_primitive(self):
        return self._value.public_bytes(serialization.Encoding.PEM)

    def get_issuer(self):
        return self._value.issuer

    def get_public_key(self):
        return RSAPublicKey(session=self._session).from_raw_key(
            self._value.public_key())

    def get_serial_number(self):
        return self._value.serial

    def verify(self, public_key):
        """Verifies the certificate using the given key.

        Args:
          public_key: The public key to use.

        Returns:
          True: Everything went well.

        Raises:
          VerificationError: The certificate did not verify.
        """
        # TODO: We have to do this manually for now since cryptography does
        # not yet support cert verification. There is PR 2460:
        # https://github.com/pyca/cryptography/pull/2460/files
        # that will add it, once it's in we should switch to using this.

        # Note that all times here are in UTC.
        #now = rdfvalue.RDFDatetime.Now().AsDatetime()
        #if now > self._value.not_valid_after:
        #    raise VerificationError("Certificate expired!")
        #    if now < self._value.not_valid_before:
        #        raise VerificationError("Certificate not yet valid!")

        public_key.verify(
            self._value.tbs_certificate_bytes,
            self._value.signature,
            hash_algorithm=self._value.signature_hash_algorithm)

        return True


def MakeCASignedCert(common_name,
                     private_key,
                     ca_cert,
                     ca_private_key,
                     serial_number=2,
                     session=None):
    """Make a cert and sign it with the CA's private key."""
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()

    builder = builder.issuer_name(ca_cert.get_issuer())

    subject = x509.Name([
            x509.NameAttribute(oid.NameOID.COMMON_NAME, common_name)
    ])
    builder = builder.subject_name(subject)

    valid_from = time.time() - 60 * 60 * 24
    valid_until = time.time() + 60 * 60 * 24 * 365 * 10
    builder = builder.not_valid_before(datetime.datetime.fromtimestamp(
        valid_from))
    builder = builder.not_valid_after(datetime.datetime.fromtimestamp(
        valid_until))

    builder = builder.serial_number(serial_number)
    builder = builder.public_key(public_key.get_raw_key())

    builder = builder.add_extension(
            x509.BasicConstraints(
                    ca=False, path_length=None), critical=True)
    certificate = builder.sign(
            private_key=ca_private_key.get_raw_key(),
            algorithm=hashes.SHA256(),
            backend=openssl.backend)

    return X509Ceritifcate(session=session).from_raw_key(certificate)


def MakeCACert(private_key,
               common_name=u"rekall-agent-ca",
               issuer_cn=u"rekall-agent-ca",
               issuer_c=u"US",
               session=None):
    """Generate a CA certificate.

    Args:
        private_key: The private key to use.
        common_name: Name for cert.
        issuer_cn: Name for issuer.
        issuer_c: Country for issuer.

    Returns:
        The certificate.
    """
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()

    issuer = x509.Name([
            x509.NameAttribute(oid.NameOID.COMMON_NAME, issuer_cn),
            x509.NameAttribute(oid.NameOID.COUNTRY_NAME, issuer_c)
    ])
    subject = x509.Name([
            x509.NameAttribute(oid.NameOID.COMMON_NAME, common_name)
    ])
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)

    valid_from = time.time() - 60 * 60 * 24
    valid_until = time.time() + 60 * 60 * 24 * 365 * 10
    builder = builder.not_valid_before(datetime.datetime.fromtimestamp(
        valid_from))
    builder = builder.not_valid_after(datetime.datetime.fromtimestamp(
        valid_until))

    builder = builder.serial_number(1)
    builder = builder.public_key(public_key.get_raw_key())

    builder = builder.add_extension(
            x509.BasicConstraints(
                    ca=True, path_length=None), critical=True)
    builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                public_key.get_raw_key()),
            critical=False)

    certificate = builder.sign(
            private_key=private_key.get_raw_key(),
            algorithm=hashes.SHA256(),
            backend=openssl.backend)

    return X509Ceritifcate(session=session).from_raw_key(certificate)


class AES128CBCCipher(object):
    """A Cipher using AES128 in CBC mode and PKCS7 for padding."""

    algorithm = None

    def __init__(self, key, iv):
        """Init.

        Args:
            key: The key, a EncryptionKey instance.
            iv: The iv, a EncryptionKey instance.
        """
        self.key = key.RawBytes()
        self.iv = iv.RawBytes()

    def Pad(self, data):
        padder = sym_padding.PKCS7(128).padder()
        return padder.update(data) + padder.finalize()

    def UnPad(self, padded_data):
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def GetEncryptor(self):
        return ciphers.Cipher(
                algorithms.AES(self.key), modes.CBC(self.iv),
                backend=openssl.backend).encryptor()

    def Encrypt(self, data):
        """A convenience method which pads and encrypts at once."""
        encryptor = self.GetEncryptor()
        padded_data = self.Pad(data)

        try:
            return encryptor.update(padded_data) + encryptor.finalize()
        except ValueError as e:
            raise CipherError(e)

    def GetDecryptor(self):
        return ciphers.Cipher(
                algorithms.AES(self.key), modes.CBC(self.iv),
                backend=openssl.backend).decryptor()

    def Decrypt(self, data):
        """A convenience method which pads and decrypts at once."""
        decryptor = self.GetDecryptor()

        try:
            padded_data = decryptor.update(data) + decryptor.finalize()
            return self.UnPad(padded_data)
        except ValueError as e:
            raise CipherError(e)


class CipherProperties(serializer.SerializedObject):
    """Describes the cipher that is encrypting this file."""

    schema = [
        dict(name="name",
             help="The name of this cipher (e.g. AES128CBC)"),
        dict(name="key", type="EncryptionKey",
             help="The encryption key"),
        dict(name="iv", type="EncryptionKey",
             help="IV used for symmetric encryption"),
        dict(name="hmac_key", type="EncryptionKey",
             help="The hmac key used."),
    ]

    # This is a cipher object we use to encrypt, decrypt.
    _cipher = None

    def generate_keys(self):
        self.name = "AES128CBC"
        self.key = EncryptionKey(session=self._session).GenerateKey()
        self.iv = EncryptionKey(session=self._session).GenerateKey()
        self.hmac_key = EncryptionKey(session=self._session).GenerateKey()
        self._cipher = AES128CBCCipher(self.key, self.iv)
        return self

    @classmethod
    def from_primitive(cls, primitive, session=None):
        result = super(CipherProperties, cls).from_primitive(primitive,
                                                             session=session)
        if not result.key or not result.iv or not result.hmac_key:
            raise RuntimeError("Invalid CipherProperties.")

        result._cipher = AES128CBCCipher(result.key, result.iv)
        return result

    def encrypt(self, data):
        return self._cipher.Encrypt(data)

    def decrypt(self, data):
        return self._cipher.Decrypt(data)


class Signature(serializer.SerializedObject):
    """A signature block also contains the HMAC."""

    schema = [
        dict(name="signature", type="str",
             help="The signature covers the plain text of the encrypted "
             "cipher field."),
        dict(name="encrypted_cipher", type="str",
             help="The encrypted CipherProperties object."),
    ]
