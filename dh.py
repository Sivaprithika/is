import socket
import hashlib
import secrets

# =====================================================
# MODULE 1 : Public Parameters
# =====================================================

P = 23
G = 5

# =====================================================
# MODULE 2 : Modular Exponentiation
# =====================================================

def mod_pow(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)

# =====================================================
# MODULE 3 : Key Pair Generation
# =====================================================

def generate_key_pair(p: int, g: int):

    private_key = secrets.randbelow(p - 3) + 2

    public_key = mod_pow(
        g,
        private_key,
        p
    )

    return private_key, public_key

# =====================================================
# MODULE 4 : Shared Secret Computation
# =====================================================

def compute_shared_secret(
        other_public: int,
        my_private: int,
        p: int) -> int:

    return mod_pow(
        other_public,
        my_private,
        p
    )

# =====================================================
# SHA-256 Utility
# =====================================================

def sha_hash(value: int) -> str:

    return hashlib.sha256(
        str(value).encode()
    ).hexdigest()

# =====================================================
# MODULE 5 : DH SERVER
# =====================================================

def run_server(port=8080):

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(("0.0.0.0", port))
    server.listen(1)

    print(f"\n[SERVER] Listening on Port {port}")

    conn, addr = server.accept()

    print(
        f"[SERVER] Connection From {addr}"
    )

    try:

        b, B = generate_key_pair(P, G)

        print(
            f"[SERVER] Private Key = {b}"
        )

        print(
            f"[SERVER] Public Key = {B}"
        )

        A = int(
            conn.recv(1024)
            .decode()
            .strip()
        )

        if A <= 1:
            raise ValueError(
                "Invalid Public Key"
            )

        conn.sendall(
            f"{B}\n".encode()
        )

        K = compute_shared_secret(
            A,
            b,
            P
        )

        print(
            f"[SERVER] Shared Secret K = {K}"
        )

        server_hash = sha_hash(K)

        conn.sendall(
            f"{server_hash}\n".encode()
        )

        client_hash = conn.recv(
            1024
        ).decode().strip()

        print(
            "[SERVER] Key Confirmation:",
            client_hash == server_hash
        )

    finally:

        conn.close()
        server.close()

# =====================================================
# MODULE 6 : DH CLIENT
# =====================================================

def run_client(
        host="127.0.0.1",
        port=8080):

    client = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    try:

        client.connect(
            (host, port)
        )

    except ConnectionRefusedError:

        print(
            "Server Not Running"
        )

        return

    a, A = generate_key_pair(P, G)

    print(
        f"[CLIENT] Private Key = {a}"
    )

    print(
        f"[CLIENT] Public Key = {A}"
    )

    client.sendall(
        f"{A}\n".encode()
    )

    B = int(
        client.recv(1024)
        .decode()
        .strip()
    )

    if B <= 1:
        raise ValueError(
            "Invalid Public Key"
        )

    K = compute_shared_secret(
        B,
        a,
        P
    )

    print(
        f"[CLIENT] Shared Secret K = {K}"
    )

    server_hash = client.recv(
        1024
    ).decode().strip()

    client_hash = sha_hash(K)

    client.sendall(
        f"{client_hash}\n".encode()
    )

    print(
        "[CLIENT] Key Confirmation:",
        client_hash == server_hash
    )

    client.close()

# =====================================================
# MODULE 7 : MITM ATTACKER
# =====================================================

def run_attacker(
        listen_port=8080,
        real_server_host="127.0.0.1",
        real_server_port=9090):

    attacker_server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    attacker_server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    attacker_server.bind(
        ("0.0.0.0",
         listen_port)
    )

    attacker_server.listen(1)

    print(
        f"[ATTACKER] Listening on Port {listen_port}"
    )

    client_conn, addr = attacker_server.accept()

    print(
        "[ATTACKER] Client Intercepted"
    )

    server_conn = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server_conn.connect(
        (
            real_server_host,
            real_server_port
        )
    )

    print(
        "[ATTACKER] Connected to Real Server"
    )

    try:

        m2, M2 = generate_key_pair(
            P,
            G
        )

        m1, M1 = generate_key_pair(
            P,
            G
        )

        A = int(
            client_conn.recv(
                1024
            ).decode().strip()
        )

        server_conn.sendall(
            f"{M1}\n".encode()
        )

        B = int(
            server_conn.recv(
                1024
            ).decode().strip()
        )

        client_conn.sendall(
            f"{M2}\n".encode()
        )

        K_clientSide = \
            compute_shared_secret(
                A,
                m2,
                P
            )

        K_serverSide = \
            compute_shared_secret(
                B,
                m1,
                P
            )

        print(
            f"[ATTACKER] K_clientSide = {K_clientSide}"
        )

        print(
            f"[ATTACKER] K_serverSide = {K_serverSide}"
        )

        server_conn.recv(1024)

        server_conn.sendall(
            f"{sha_hash(K_serverSide)}\n"
            .encode()
        )

        client_conn.recv(1024)

        client_conn.sendall(
            f"{sha_hash(K_clientSide)}\n"
            .encode()
        )

        print(
            "\n[ATTACKER] MITM Attack Successful"
        )

    finally:

        client_conn.close()
        server_conn.close()
        attacker_server.close()

# =====================================================
# TEST MODULE 2
# =====================================================

def test_key_generation():

    private_key, public_key = \
        generate_key_pair(P, G)

    print("\nMODULE 2 OUTPUT")

    print(
        "Private Key:",
        private_key
    )

    print(
        "Public Key:",
        public_key
    )

# =====================================================
# TEST MODULE 3
# =====================================================

def test_shared_secret():

    a = 6
    A = 8

    b = 15
    B = 19

    K1 = compute_shared_secret(
        B,
        a,
        P
    )

    K2 = compute_shared_secret(
        A,
        b,
        P
    )

    print("\nMODULE 3 OUTPUT")

    print(
        "Client Secret:",
        K1
    )

    print(
        "Server Secret:",
        K2
    )

    print(
        "Match:",
        K1 == K2
    )

# =====================================================
# MAIN MENU
# =====================================================

if __name__ == "__main__":

    print("\n1. Module 2 - Key Pair Generation")
    print("2. Module 3 - Shared Secret")
    print("3. Run Server")
    print("4. Run Client")
    print("5. Run MITM Attacker")

    choice = input(
        "\nEnter Choice: "
    )

    if choice == "1":
        test_key_generation()

    elif choice == "2":
        test_shared_secret()

    elif choice == "3":
        run_server(8080)

    elif choice == "4":
        run_client(
            "127.0.0.1",
            8080
        )

    elif choice == "5":
        run_attacker(
            8080,
            "127.0.0.1",
            9090
        )