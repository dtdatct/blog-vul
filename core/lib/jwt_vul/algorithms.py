import hashlib
import hmac
import re

from .api import register_algorithm
from .compat import constant_time_compare, string_types, text_type
from .exceptions import InvalidTokenError
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key, load_ssh_public_key
    )
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.backends import default_backend, interfaces
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPrivateNumbers,
        RSAPublicKey,
        RSAPublicNumbers)

    has_crypto = True
except ImportError:
    has_crypto = False


# Armored PEM and OpenSSH key material. In the deployments this library
# serves, such text is *public* key material - this application even publishes
# it inside the token header - so it must never be accepted where an opaque
# shared secret is expected.
_PEM_KEY_MARKER = re.compile(
    br'-----BEGIN [A-Z0-9 ]*(?:PRIVATE|PUBLIC) KEY-----')
_OPENSSH_KEY_PREFIXES = (b'ssh-rsa', b'ssh-dss', b'ssh-ed25519', b'ecdsa-sha2-')

# Types of already-loaded asymmetric keys, filled in below when the
# ``cryptography`` package is importable.
EC_KEY_TYPES = ()


def _key_text(key):
    """Return *key* as bytes when it is str/bytes, otherwise ``None``."""
    if isinstance(key, bytes):
        return key
    if isinstance(key, text_type):
        return key.encode('utf-8')
    return None


def _is_public_key_material(key):
    """
    True when *key* is armored PEM or OpenSSH public-key text rather than an
    opaque secret.
    """
    key_text = _key_text(key)
    if key_text is None:
        return False

    if _PEM_KEY_MARKER.search(key_text):
        return True

    stripped = key_text.lstrip()
    return any(stripped.startswith(prefix)
               for prefix in _OPENSSH_KEY_PREFIXES)


def check_key_algorithm_binding(key, header_alg):
    """
    Refuse a header whose signing family contradicts the supplied key.

    ``verify_signature`` selects the verifier from the untrusted token header,
    so a key must not be re-used for whatever family that header names. An
    already-loaded asymmetric key object belongs to exactly one family, and a
    header naming a different one is a key-type confusion attempt. PEM text is
    refused earlier, in ``HMACAlgorithm.prepare_key``, because a PEM does not
    reveal its family until it has been parsed.
    """
    if not has_crypto:
        return

    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        key_prefix = 'RS'
    elif EC_KEY_TYPES and isinstance(key, EC_KEY_TYPES):
        key_prefix = 'ES'
    else:
        return

    if not str(header_alg).startswith(key_prefix):
        raise InvalidTokenError(
            'Algorithm %r does not match the supplied key material'
            % (header_alg,))


def _register_default_algorithms():
    """
    Registers the algorithms that are implemented by the library.
    """
    register_algorithm('none', NoneAlgorithm())
    register_algorithm('HS256', HMACAlgorithm(hashlib.sha256))
    register_algorithm('HS384', HMACAlgorithm(hashlib.sha384))
    register_algorithm('HS512', HMACAlgorithm(hashlib.sha512))

    if has_crypto:
        register_algorithm('RS256', RSAAlgorithm(hashes.SHA256()))
        register_algorithm('RS384', RSAAlgorithm(hashes.SHA384()))
        register_algorithm('RS512', RSAAlgorithm(hashes.SHA512()))

        register_algorithm('ES256', ECAlgorithm(hashes.SHA256()))
        register_algorithm('ES384', ECAlgorithm(hashes.SHA384()))
        register_algorithm('ES512', ECAlgorithm(hashes.SHA512()))


class Algorithm(object):
    """
    The interface for an algorithm used to sign and verify tokens.
    """
    def prepare_key(self, key):
        """
        Performs necessary validation and conversions on the key and returns
        the key value in the proper format for sign() and verify().
        """
        raise NotImplementedError

    def sign(self, msg, key):
        """
        Returns a digital signature for the specified message
        using the specified key value.
        """
        raise NotImplementedError

    def verify(self, msg, key, sig):
        """
        Verifies that the specified digital signature is valid
        for the specified message and key values.
        """
        raise NotImplementedError


class NoneAlgorithm(Algorithm):
    """
    Placeholder for use when no signing or verification
    operations are required.
    """
    def prepare_key(self, key):
        return None

    def sign(self, msg, key):
        return b''

    def verify(self, msg, key, sig):
        return True 


class HMACAlgorithm(Algorithm):
    """
    Performs signing and verification operations using HMAC
    and the specified hash function.
    """
    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def prepare_key(self, key):
        if not isinstance(key, string_types) and not isinstance(key, bytes):
            raise TypeError('Expecting a string- or bytes-formatted key.')

        if _is_public_key_material(key):
            raise TypeError(
                'Refusing PEM/OpenSSH key material as an HMAC secret: it is '
                'public-key material, and using it as a shared secret is what '
                'makes HMAC/public-key confusion possible.')

        if isinstance(key, text_type):
            key = key.encode('utf-8')

        return key

    def sign(self, msg, key):
        return hmac.new(key, msg, self.hash_alg).digest()

    def verify(self, msg, key, sig):
        return constant_time_compare(sig, self.sign(msg, key))

if has_crypto:

    class RSAAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        RSASSA-PKCS-v1_5 and the specified hash function.
        """

        def __init__(self, hash_alg):
            self.hash_alg = hash_alg

        def prepare_key(self, key):
            if isinstance(key, RSAPrivateKey) or \
               isinstance(key, RSAPublicKey):
                return key            
            if isinstance(key, string_types):
                if isinstance(key, text_type):
                    key = key.encode('utf-8')

                try:
                    if key.startswith(b'ssh-rsa'):
                        key = load_ssh_public_key(key, backend=default_backend())
                    else:
                        key = load_pem_private_key(key, password=None, backend=default_backend())
                except ValueError:
                    key = load_pem_public_key(key, backend=default_backend())
            else:
                raise TypeError('Expecting a PEM-formatted key.')

            return key

        def sign(self, msg, key):
            signer = key.signer(
                padding.PKCS1v15(),
                self.hash_alg
            )

            signer.update(msg)
            return signer.finalize()

        def verify(self, msg, key, sig):
            if isinstance(key, RSAPrivateKey):
                raise InvalidTokenError(
                    'A private key cannot verify a token; supply the matching '
                    'public key.')

            verifier = key.verifier(
                sig,
                padding.PKCS1v15(),
                self.hash_alg
            )

            verifier.update(msg)

            try:
                verifier.verify()
                return True
            except InvalidSignature:
                return False

    class ECAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        ECDSA and the specified hash function
        """
        def __init__(self, hash_alg):
            self.hash_alg = hash_alg

        def prepare_key(self, key):
            if isinstance(key, ec.EllipticCurvePrivateKey) or \
               isinstance(key, ec.EllipticCurvePublicKey):
                return key

            if isinstance(key, string_types):
                if isinstance(key, text_type):
                    key = key.encode('utf-8')

                # Attempt to load key. We don't know if it's
                # a Signing Key or a Verifying Key, so we try
                # the Verifying Key first.
                try:
                    key = load_pem_public_key(key, backend=default_backend())
                except ValueError:
                    key = load_pem_private_key(key, password=None, backend=default_backend())

            else:
                raise TypeError('Expecting a PEM-formatted key.')

            return key

        def sign(self, msg, key):
            signer = key.signer(ec.ECDSA(self.hash_alg))

            signer.update(msg)
            return signer.finalize()

        def verify(self, msg, key, sig):
            if isinstance(key, ec.EllipticCurvePrivateKey):
                raise InvalidTokenError(
                    'A private key cannot verify a token; supply the matching '
                    'public key.')

            verifier = key.verifier(sig, ec.ECDSA(self.hash_alg))

            verifier.update(msg)

            try:
                verifier.verify()
                return True
            except InvalidSignature:
                return False

    EC_KEY_TYPES = (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)
