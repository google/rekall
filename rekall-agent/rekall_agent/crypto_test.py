import StringIO
from rekall import testlib
from rekall_agent import crypto


class TestWritableAgentFile(testlib.RekallBaseUnitTestCase):

    def testAgentFile(self):
        readers_private_key = crypto.RSAPrivateKey(
            session=self.session).generate_key()
        writers_private_key = crypto.RSAPrivateKey(
            session=self.session).generate_key()

        filename = "/tmp/foo.tmp"
        fd = crypto.WritableAgentFile(
            filename, session=self.session,
            readers_public_key=readers_private_key.public_key(),
            writers_private_key=writers_private_key,
            )
        fd.write_encrypted_data("hello world")
        fd.write_encrypted_data("goodbye world")
        fd.close()

        out_fd = StringIO.StringIO()
        fd2 = crypto.ReadableAgentFile(
            filename, session=self.session,
            readers_private_key=readers_private_key,
            writers_public_key=writers_private_key.public_key())
        fd2.extract_to_fd(out_fd)

        self.assertEqual(out_fd.getvalue(),
                         "hello world" + "goodbye world")
        self.assertEqual(fd2.hmac_verified, True)


if __name__ == "__main__":
    testlib.main()
