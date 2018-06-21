from ecc_utils import get_ecc_public_key_from_pem, get_ecc_public_key_pem_from_private, get_ecc_shared_key, generate_ecc_private_key


def test():
    # 生成S端ECC私钥
    server_ecc_private_key = generate_ecc_private_key()
    # 生成S端ECC公钥
    server_ecc_public_key_pem = get_ecc_public_key_pem_from_private(server_ecc_private_key)

    print("server_ecc_public_key_pem:", "\n", server_ecc_public_key_pem)

    # 生成C端ECC私钥
    client_ecc_private_key = generate_ecc_private_key()
    # 生成C端ECC公钥
    client_ecc_public_key_pem = get_ecc_public_key_pem_from_private(client_ecc_private_key)

    print("client_ecc_public_key_pem:", "\n", client_ecc_public_key_pem)

    # DH(S端私钥+C端公钥)
    sc_share_key = get_ecc_shared_key(get_ecc_public_key_from_pem(client_ecc_public_key_pem), server_ecc_private_key)

    # DH(C端私钥+S端公钥)
    cs_share_key = get_ecc_shared_key(get_ecc_public_key_from_pem(server_ecc_public_key_pem), client_ecc_private_key)

    print("sc_share_key:", "\n", sc_share_key)
    print("cs_share_key:", "\n", cs_share_key)


test()
