import unittest
import binascii
import struct
import yubi_goog

class TestYubiGoog(unittest.TestCase):
    def setUp(self):
        self.google_secret = "n xu7 v4s qp6 njs gj5"
        self.test_secret = binascii.hexlify('12345678901234567890'.encode('ascii'))
        self.test_vectors = [{ 'time': 1111111111, 'otp': '050471' },
                             { 'time': 1234567890, 'otp': '005924' },
                             { 'time': 2000000000, 'otp': '279037' } ]

    def test_decode_secret(self):
        decoded = yubi_goog.decode_secret(self.google_secret).upper()
        self.assertEqual(decoded, "6DE9FAF2507F9A99193D".encode('ascii'))

    def test_totp(self):
        for pair in self.test_vectors:
            time = pair['time']
            real_otp = pair['otp']

            tm = int(int(time)/30)
            tm = struct.pack('>q', tm)
            otp = yubi_goog.totp(self.test_secret, tm)
            self.assertEqual(otp, real_otp)

if __name__ == '__main__':
    unittest.main()
