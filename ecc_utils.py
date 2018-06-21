import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


def get_ecc_shared_key(peer_public_key, private_key):
    """
    DH(A端私钥+B端公钥)=协商密钥
    :param peer_public_key: B端公钥
    :param private_key: A端私钥
    :return: 协商密钥
    """
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    shared_key_bytes = base64.b64encode(shared_key)
    shared_key_str = bytes.decode(shared_key_bytes)
    return shared_key_str


def get_ecc_public_key_from_pem(public_key_pem):
    """
    获取ECC公钥,通过PEM格式的字符串
    :param public_key_pem: PEM格式的公钥字符串
    :return:
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    return public_key


def ecc_private_key_from_pem(private_key_pem):
    """
    获取ECC私钥,通过PEM格式的字符串
    :param private_key_pem: PEM格式的私钥字符串
    :return:
    """
    server_private_key = serialization.load_pem_private_key(data=private_key_pem.encode(), password="ecc_password".encode(),
                                                            backend=default_backend())
    return server_private_key


def get_ecc_public_key_pem_from_private(private_key):
    """
    通过ECC私钥,获取ECC公钥,返回PEM格式的字符串
    :param private_key:
    :return:
    """
    public_bytes = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return bytes.decode(public_bytes)


def generate_ecc_private_key():
    """
    获取ECC私钥
    :return: ECC私钥
    """
    return ec.generate_private_key(
        ec.SECP256K1(), default_backend())
