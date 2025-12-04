#!/usr/bin/python3
import socket
import argparse
import unittest
import struct
import os
import re


def parse_proc_crypto():
    """Parse /proc/crypto and return available algorithms by type"""
    algorithms = {}
    current = {}
    
    try:
        with open('/proc/crypto', 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    if current and current.get('name') and current.get('type'):
                        name = current['name']
                        algo_type = current['type']
                        internal = current.get('internal', 'no')
                        
                        # Skip internal algorithms and algorithms starting with __
                        if internal == 'no' and not name.startswith('__'):
                            if algo_type not in algorithms:
                                algorithms[algo_type] = []
                            if name not in algorithms[algo_type]:
                                algorithms[algo_type].append(name)
                    current = {}
                else:
                    match = re.match(r'(\w+)\s*:\s*(.+)', line)
                    if match:
                        key, value = match.groups()
                        current[key] = value.strip()
    except FileNotFoundError:
        print("Warning: /proc/crypto not found")
        return {}
    
    return algorithms


# This socket unit test is from python package /Lib/test/test_socket.py
class LinuxKernelCryptoAPI(unittest.TestCase):
    # tests for AF_ALG
    def create_alg(self, crypto_type, name):
        sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        try:
            sock.bind((crypto_type, name))
        except FileNotFoundError as e:
            # type / algorithm is not available
            sock.close()
            print("Error: {}".format(e))
            raise Exception(
                "Error: Not able to use algorithm\n"
                "Please check kernel config!"
            )
        else:
            return sock

    def test_hash_crc64(self):
        # Try crc64-rocksoft first (modern kernels), fall back to crc64
        data = b"abcdefghijklmnopqrstuvwxyz" * 1024 * 1024
        algo_name = "crc64-rocksoft"
        try:
            with self.create_alg("hash", algo_name) as algo:
                op, _ = algo.accept()
                with op:
                    op.send(data, socket.MSG_MORE)
                    return_data = op.recv(64).hex()
                    self.assertEqual(len(return_data), 16)
                    print("hash crc64: {}".format(return_data))
        except Exception as e:
            # Try the generic crc64 name
            if "Not able to use algorithm" in str(e):
                with self.create_alg("hash", "crc64") as algo:
                    op, _ = algo.accept()
                    with op:
                        op.send(data, socket.MSG_MORE)
                        return_data = op.recv(64).hex()
                        self.assertEqual(len(return_data), 16)
                        print("hash crc64: {}".format(return_data))
            else:
                raise

    def test_hash_sha256(self):
        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396"
            "177a9cb410ff61f20015ad"
        )
        with self.create_alg("hash", "sha256") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(b"abc")
                self.assertEqual(op.recv(512), expected)

            op, _ = algo.accept()
            with op:
                op.send(b"a", socket.MSG_MORE)
                op.send(b"b", socket.MSG_MORE)
                op.send(b"c", socket.MSG_MORE)
                op.send(b"")
                self.assertEqual(op.recv(512), expected)
                print("hash: {}".format(op.recv(512).hex()))

    def test_hash_md5(self):
        # MD5 hash of "abc"
        expected = bytes.fromhex("900150983cd24fb0d6963f7d28e17f72")
        with self.create_alg("hash", "md5") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(b"abc")
                result = op.recv(512)
                self.assertEqual(result, expected)
                print("hash md5: {}".format(result.hex()))

    def test_hash_sha1(self):
        # SHA1 hash of "abc"
        expected = bytes.fromhex("a9993e364706816aba3e25717850c26c9cd0d89d")
        with self.create_alg("hash", "sha1") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(b"abc")
                result = op.recv(512)
                self.assertEqual(result, expected)
                print("hash sha1: {}".format(result.hex()))

    def test_hash_sha224(self):
        # SHA224 hash of "abc"
        expected = bytes.fromhex(
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        )
        with self.create_alg("hash", "sha224") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(b"abc")
                result = op.recv(512)
                self.assertEqual(result, expected)
                print("hash sha224: {}".format(result.hex()))

    def test_hash_sha384(self):
        # SHA384 hash of "abc"
        expected = bytes.fromhex(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7"
        )
        with self.create_alg("hash", "sha384") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(b"abc")
                result = op.recv(512)
                self.assertEqual(result, expected)
                print("hash sha384: {}".format(result.hex()))

    def test_hash_sha512(self):
        # SHA512 hash of "abc"
        expected = bytes.fromhex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        with self.create_alg("hash", "sha512") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(b"abc")
                result = op.recv(512)
                self.assertEqual(result, expected)
                print("hash sha512: {}".format(result.hex()))

    def test_hash_sha3_224(self):
        # SHA3-224 hash of "abc"
        expected = bytes.fromhex(
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        )
        with self.create_alg("hash", "sha3-224") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(b"abc")
                result = op.recv(512)
                self.assertEqual(result, expected)
                print("hash sha3-224: {}".format(result.hex()))

    def test_hash_sha3_256(self):
        # SHA3-256 hash of "abc"
        expected = bytes.fromhex(
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        )
        with self.create_alg("hash", "sha3-256") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(b"abc")
                result = op.recv(512)
                self.assertEqual(result, expected)
                print("hash sha3-256: {}".format(result.hex()))

    def test_hash_sha3_384(self):
        # SHA3-384 hash of "abc"
        expected = bytes.fromhex(
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
            "98d88cea927ac7f539f1edf228376d25"
        )
        with self.create_alg("hash", "sha3-384") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(b"abc")
                result = op.recv(512)
                self.assertEqual(result, expected)
                print("hash sha3-384: {}".format(result.hex()))

    def test_hash_sha3_512(self):
        # SHA3-512 hash of "abc"
        expected = bytes.fromhex(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        )
        with self.create_alg("hash", "sha3-512") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(b"abc")
                result = op.recv(512)
                self.assertEqual(result, expected)
                print("hash sha3-512: {}".format(result.hex()))

    def test_hash_crc32(self):
        data = b"abcdefghijklmnopqrstuvwxyz"
        with self.create_alg("hash", "crc32") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(data)
                result = op.recv(64)
                self.assertEqual(len(result), 4)
                print("hash crc32: {}".format(result.hex()))

    def test_hash_crc32c(self):
        data = b"abcdefghijklmnopqrstuvwxyz"
        with self.create_alg("hash", "crc32c") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(data)
                result = op.recv(64)
                self.assertEqual(len(result), 4)
                print("hash crc32c: {}".format(result.hex()))

    def test_hash_crc64_rocksoft(self):
        data = b"abcdefghijklmnopqrstuvwxyz"
        with self.create_alg("hash", "crc64-rocksoft") as algo:
            op, _ = algo.accept()
            with op:
                op.sendall(data)
                result = op.recv(64)
                self.assertEqual(len(result), 8)
                print("hash crc64-rocksoft: {}".format(result.hex()))

    def test_skcipher_cbc_aes(self):
        key = bytes.fromhex("06a9214036b8a15b512e03d534120006")
        iv = bytes.fromhex("3dafba429d9eb430b422da802c9fac41")
        msg = b"Single block msg"
        ciphertext = bytes.fromhex("e353779c1079aeb82708942dbe77181a")
        msglen = len(msg)
        with self.create_alg("skcipher", "cbc(aes)") as algo:
            algo.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, key)
            op, _ = algo.accept()
            with op:
                op.sendmsg_afalg(
                    op=socket.ALG_OP_ENCRYPT, iv=iv, flags=socket.MSG_MORE
                )
                op.sendall(msg)
                self.assertEqual(op.recv(msglen), ciphertext)

            op, _ = algo.accept()
            with op:
                op.sendmsg_afalg([ciphertext], op=socket.ALG_OP_DECRYPT, iv=iv)
                self.assertEqual(op.recv(msglen), msg)

            # long message
            multiplier = 8
            longmsg = [msg] * multiplier
            op, _ = algo.accept()
            with op:
                op.sendmsg_afalg(longmsg, op=socket.ALG_OP_ENCRYPT, iv=iv)
                enc = op.recv(msglen * multiplier)
            self.assertEqual(len(enc), msglen * multiplier)
            self.assertEqual(enc[:msglen], ciphertext)

            op, _ = algo.accept()
            with op:
                op.sendmsg_afalg([enc], op=socket.ALG_OP_DECRYPT, iv=iv)
                dec = op.recv(msglen * multiplier)
            self.assertEqual(len(dec), msglen * multiplier)
            self.assertEqual(dec, msg * multiplier)
            print("skcipher cbc(aes): {}".format(dec.hex()))

    def test_skcipher_ecb_aes(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        msg = b"Single block msg"
        msglen = len(msg)
        with self.create_alg("skcipher", "ecb(aes)") as algo:
            algo.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, key)
            op, _ = algo.accept()
            with op:
                op.sendmsg_afalg(op=socket.ALG_OP_ENCRYPT, flags=socket.MSG_MORE)
                op.sendall(msg)
                enc = op.recv(msglen)
                self.assertEqual(len(enc), msglen)

            op, _ = algo.accept()
            with op:
                op.sendmsg_afalg([enc], op=socket.ALG_OP_DECRYPT)
                dec = op.recv(msglen)
                self.assertEqual(dec, msg)
                print("skcipher ecb(aes): {}".format(dec.hex()))

    def test_skcipher_ctr_aes(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        msg = b"Single block msg"
        msglen = len(msg)
        with self.create_alg("skcipher", "ctr(aes)") as algo:
            algo.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, key)
            op, _ = algo.accept()
            with op:
                op.sendmsg_afalg(
                    op=socket.ALG_OP_ENCRYPT, iv=iv, flags=socket.MSG_MORE
                )
                op.sendall(msg)
                enc = op.recv(msglen)
                self.assertEqual(len(enc), msglen)

            op, _ = algo.accept()
            with op:
                op.sendmsg_afalg([enc], op=socket.ALG_OP_DECRYPT, iv=iv)
                dec = op.recv(msglen)
                self.assertEqual(dec, msg)
                print("skcipher ctr(aes): {}".format(dec.hex()))

    def test_skcipher_xts_aes(self):
        # XTS-AES requires a 256-bit (32 byte) key for 128-bit AES
        key = bytes.fromhex(
            "2b7e151628aed2a6abf7158809cf4f3c"
            "2b7e151628aed2a6abf7158809cf4f3c"
        )
        # XTS IV is typically 16 bytes (sector number)
        iv = bytes.fromhex("00000000000000000000000000000000")
        msg = b"Single block msg"
        msglen = len(msg)
        with self.create_alg("skcipher", "xts(aes)") as algo:
            algo.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, key)
            op, _ = algo.accept()
            with op:
                op.sendmsg_afalg(
                    op=socket.ALG_OP_ENCRYPT, iv=iv, flags=socket.MSG_MORE
                )
                op.sendall(msg)
                enc = op.recv(msglen)
                self.assertEqual(len(enc), msglen)

            op, _ = algo.accept()
            with op:
                op.sendmsg_afalg([enc], op=socket.ALG_OP_DECRYPT, iv=iv)
                dec = op.recv(msglen)
                self.assertEqual(dec, msg)
                print("skcipher xts(aes): {}".format(dec.hex()))

    def test_aead_gcm_aes(self):
        key = bytes.fromhex("c939cc13397c1d37de6ae0e1cb7c423c")
        iv = bytes.fromhex("b3d8cc017cbb89b39e0f67e2")
        plain = bytes.fromhex("c3b3c41f113a31b73d9a5cd432103069")
        assoc = bytes.fromhex("24825602bd12a984e0092d3e448eda5f")
        expected_ct = bytes.fromhex("93fe7d9e9bfd10348a5606e5cafa7354")
        expected_tag = bytes.fromhex("0032a1dc85f1c9786925a2e71d8272dd")

        taglen = len(expected_tag)
        assoclen = len(assoc)
        with self.create_alg("aead", "gcm(aes)") as algo:
            algo.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, key)
            algo.setsockopt(
                socket.SOL_ALG, socket.ALG_SET_AEAD_AUTHSIZE, None, taglen
            )

            # send assoc, plain and tag buffer in separate steps
            op, _ = algo.accept()
            with op:
                op.sendmsg_afalg(
                    op=socket.ALG_OP_ENCRYPT,
                    iv=iv,
                    assoclen=assoclen,
                    flags=socket.MSG_MORE,
                )
                op.sendall(assoc, socket.MSG_MORE)
                op.sendall(plain)
                res = op.recv(assoclen + len(plain) + taglen)
                self.assertEqual(expected_ct, res[assoclen:-taglen])
                self.assertEqual(expected_tag, res[-taglen:])

            # now with msg
            op, _ = algo.accept()
            with op:
                msg = assoc + plain
                op.sendmsg_afalg(
                    [msg],
                    op=socket.ALG_OP_ENCRYPT,
                    iv=iv,
                    assoclen=assoclen,
                )
                res = op.recv(assoclen + len(plain) + taglen)
                self.assertEqual(expected_ct, res[assoclen:-taglen])
                self.assertEqual(expected_tag, res[-taglen:])

            # create anc data manually
            pack_uint32 = struct.Struct("I").pack
            op, _ = algo.accept()
            with op:
                msg = assoc + plain
                op.sendmsg(
                    [msg],
                    (
                        [
                            socket.SOL_ALG,
                            socket.ALG_SET_OP,
                            pack_uint32(socket.ALG_OP_ENCRYPT),
                        ],
                        [
                            socket.SOL_ALG,
                            socket.ALG_SET_IV,
                            pack_uint32(len(iv)) + iv,
                        ],
                        [
                            socket.SOL_ALG,
                            socket.ALG_SET_AEAD_ASSOCLEN,
                            pack_uint32(assoclen),
                        ],
                    ),
                )
                res = op.recv(len(msg) + taglen)
                self.assertEqual(expected_ct, res[assoclen:-taglen])
                self.assertEqual(expected_tag, res[-taglen:])

            # decrypt and verify
            op, _ = algo.accept()
            with op:
                msg = assoc + expected_ct + expected_tag
                op.sendmsg_afalg(
                    [msg],
                    op=socket.ALG_OP_DECRYPT,
                    iv=iv,
                    assoclen=assoclen,
                )
                res = op.recv(len(msg) - taglen)
                self.assertEqual(plain, res[assoclen:])
                print("aead gcm(aes): {}".format(res[assoclen:].hex()))

    def test_aead_rfc4106_gcm_aes(self):
        # RFC4106 wraps GCM(AES) and uses a specific IV format
        # Key is 128-bit AES key + 32-bit salt (20 bytes total)
        key = bytes.fromhex("c939cc13397c1d37de6ae0e1cb7c423c01020304")
        # RFC4106 IV is 8 bytes (explicit IV), the salt is prepended internally
        iv = bytes.fromhex("b3d8cc017cbb89b3")
        plain = bytes.fromhex("c3b3c41f113a31b73d9a5cd432103069")
        assoc = bytes.fromhex("24825602bd12a984e0092d3e448eda5f")
        taglen = 16
        assoclen = len(assoc)

        with self.create_alg("aead", "rfc4106(gcm(aes))") as algo:
            algo.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, key)
            algo.setsockopt(
                socket.SOL_ALG, socket.ALG_SET_AEAD_AUTHSIZE, None, taglen
            )

            op, _ = algo.accept()
            with op:
                msg = assoc + plain
                op.sendmsg_afalg(
                    [msg],
                    op=socket.ALG_OP_ENCRYPT,
                    iv=iv,
                    assoclen=assoclen,
                )
                res = op.recv(len(msg) + taglen)
                ciphertext = res[assoclen:-taglen]
                tag = res[-taglen:]
                self.assertEqual(len(ciphertext), len(plain))
                self.assertEqual(len(tag), taglen)

            # decrypt and verify
            op, _ = algo.accept()
            with op:
                msg = assoc + ciphertext + tag
                op.sendmsg_afalg(
                    [msg],
                    op=socket.ALG_OP_DECRYPT,
                    iv=iv,
                    assoclen=assoclen,
                )
                res = op.recv(len(msg) - taglen)
                self.assertEqual(plain, res[assoclen:])
                print("aead rfc4106(gcm(aes)): {}".format(res[assoclen:].hex()))

    def test_rng_stdrng(self):
        with self.create_alg("rng", "stdrng") as algo:
            try:
                extra_seed = os.urandom(32)
                algo.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, extra_seed)
            except OSError:
                print("failed to seeded {} to RNG".format(extra_seed))
            op, _ = algo.accept()
            with op:
                rn = op.recv(32)
                self.assertEqual(len(rn), 32)
                print("rng stdrng: {}".format(rn.hex()))

    def test_rng_jitterentropy(self):
        with self.create_alg("rng", "jitterentropy_rng") as algo:
            op, _ = algo.accept()
            with op:
                rn = op.recv(32)
                self.assertEqual(len(rn), 32)
                print("rng jitterentropy_rng: {}".format(rn.hex()))


def list_available_algorithms():
    """List all available crypto algorithms from /proc/crypto"""
    algorithms = parse_proc_crypto()
    
    if not algorithms:
        print("No algorithms found in /proc/crypto")
        return
    
    print("Available crypto algorithms in /proc/crypto:\n")
    
    # Map types to AF_ALG types
    type_mapping = {
        'shash': 'hash',
        'ahash': 'hash',
        'skcipher': 'skcipher',
        'aead': 'aead',
        'rng': 'rng',
        'compression': 'compression'
    }
    
    for algo_type in sorted(algorithms.keys()):
        af_alg_type = type_mapping.get(algo_type, algo_type)
        print(f"{algo_type} (AF_ALG type: {af_alg_type}):")
        for name in sorted(algorithms[algo_type]):
            print(f"  - {name}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Test Linux Kernel Crypto API via AF_ALG socket interface"
    )
    parser.add_argument(
        "--type",
        choices=[
            # Hash algorithms
            "hash_crc32",
            "hash_crc32c",
            "hash_crc64",
            "hash_crc64_rocksoft",
            "hash_md5",
            "hash_sha1",
            "hash_sha224",
            "hash_sha256",
            "hash_sha384",
            "hash_sha512",
            "hash_sha3_224",
            "hash_sha3_256",
            "hash_sha3_384",
            "hash_sha3_512",
            # Skcipher algorithms
            "skcipher_cbc_aes",
            "skcipher_ecb_aes",
            "skcipher_ctr_aes",
            "skcipher_xts_aes",
            # AEAD algorithms
            "aead_gcm_aes",
            "aead_rfc4106_gcm_aes",
            # RNG algorithms
            "rng_stdrng",
            "rng_jitterentropy",
        ],
        help="AF_ALG type and algorithm to test",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available crypto algorithms from /proc/crypto",
    )
    args = parser.parse_args()

    if args.list:
        list_available_algorithms()
        return

    if not args.type:
        parser.print_help()
        return

    crypto_test = LinuxKernelCryptoAPI()

    print("Starting AF_ALG type {}...".format(args.type))
    getattr(crypto_test, "test_{}".format(args.type))()


if __name__ == "__main__":
    main()
