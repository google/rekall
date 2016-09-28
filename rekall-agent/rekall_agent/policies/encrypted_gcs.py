
## To be done!

from rekall_agent import crypto


class EncryptedGCSServerPolicy(agent.ServerPolicy):
    """A server deployment policy which stored files in Google Cloud Storage."""

    schema = [
        dict(name="server_private_key", type=crypto.RSAPrivateKey,
             doc="The client's private key"),

        dict(name="server_public_key", type=crypto.RSAPublicKey,
             doc="The client's public key"),

        dict(name="server_certificate", type=crypto.X509Ceritifcate,
             doc="The server's certificate signed by the CA."),

        dict(name="ca_private_key", type=crypto.RSAPrivateKey,
             doc="The private key for the trusted CA."),

        dict(name="service_account", type=cloud.ServiceAccount,
             doc="Service account credentials for cloud deployments."),
    ]


class EncryptingAgentPolicy(GCSAgentPolicy):
    """An agent which encrypts all messages."""
    # TODO
    schema = [
        dict(name="ca_certificate", type=crypto.X509Ceritifcate,
             doc="The public key for the trusted CA."),
    ]
