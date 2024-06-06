import time


# Message to sign
message = b"Hello Frost"

# List to store results
results = []

# Loop through each library
libs = ['utility_secp256k1', 'utility_ed448',
        'utility_ed25519', 'utility_p256', 'utility_ristretto255']
# every output in this lib is encoded in base64url and its not encrypted
for lib in libs:
    print(f"Testing {lib}")
    exec(f"from frost_rs import {lib} as frost")

    # Start measuring time
    start_time = time.time()

    min_signers = 2
    max_signers = 2

    # get an identifier (chance of collision is 1/2^64)
    identifiers: str = [frost.get_id() for _ in range(max_signers)]

    # run the three round protocol to get the key

    round1_secret_packages: dict[str:str] = {}
    round1_public_packages: dict[str:str] = {}
    for id in identifiers:
        (round1_secret_packages[id], round1_public_packages[id]) = frost.round1(
            id, min_signers, max_signers)

    round2_secret_packages: dict[str:str] = {}
    round2_public_packages: dict[str:dict[str:str]] = {}

    # every one sends their round public package to each other and use it in round 2
    for id in identifiers:
        round1_received_packages = {
            key: value for key, value in round1_public_packages.items() if key != id}
        (round2_secret_packages[id], round2_public_packages[id]) = frost.round2(
            round1_secret_packages[id], round1_received_packages)

    key_packages: dict[str:str] = {}
    pubkey_packages: dict[str:str] = {}
    # in round 2 every one made a dict (identifier to package) each package needs to be sent to the user with id=identifier
    for id in identifiers:
        round1_received_packages = {
            key: value for key, value in round1_public_packages.items() if key != id}
        round2_received_packages = {
            k: v[id] for k, v in round2_public_packages.items() if id in v}
        (key_packages[id], pubkey_packages[id]) = frost.round3(
            round2_secret_packages[id], round1_received_packages, round2_received_packages)
    # every one will get their key package and the group public key
    dkg_time = time.time() - start_time
    nonces: dict[str:str] = {}
    commitments: dict[str:str] = {}
    # nonce generation can be preprocessed
    start_time = time.time()
    for id in identifiers:
        (nonces[id], commitments[id]) = frost.preprocess(key_packages[id])
    # in this example no participant leaves so it acts as normal multi sig
    nonce_time = (time.time() - start_time)/max_signers
    signature_shares: dict[str:str] = {}
    start_time = time.time()
    for id in identifiers:
        signature_shares[id] = frost.sign(
            message, commitments, nonces[id], key_packages[id])
    sign_time = time.time() - start_time
    group_signature = frost.aggregate(
        message, commitments, signature_shares, pubkey_packages[identifiers[0]])

    # verify(message[bytes] - pubkey[string] - signature[string])-> bool
    verification_result = frost.verify(
        message, pubkey_packages[identifiers[0]], group_signature)

    # Store results
    results.append({
        "library": lib,
        "Dkg time": dkg_time,
        "nonce gen per node": nonce_time,
        "signing time": sign_time,
        "signature": group_signature,
        "verification_result": verification_result,
        "len": len(pubkey_packages[identifiers[0]])
    })

for result in results:
    print(f"Library: {result['library']}")
    print(
        f"Dkg : {result['Dkg time']} sec , \nNonce gen(per Node) : {result['nonce gen per node']} sec\nsign : {result['signing time']} sec")
    print(f"signature: {result['signature']}")
    print(f"Verification Result: {result['verification_result']}")
    low = result['len']
    print(f'len = {low}')
    print("\n")
