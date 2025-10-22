def permute(bits, pattern):
    return "".join(bits[i - 1] for i in pattern)


def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]


def sbox_lookup(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return format(sbox[row][col], "02b")


# S-DES Tables
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
P4 = [2, 4, 3, 1]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
]


def generate_keys(key):
    steps = {}
    permuted = permute(key, P10)
    steps["P10"] = permuted

    left, right = permuted[:5], permuted[5:]
    left, right = left_shift(left, 1), left_shift(right, 1)
    steps["LS-1"] = left + right

    K1 = permute(left + right, P8)
    steps["K1"] = K1

    left, right = left_shift(left, 2), left_shift(right, 2)
    steps["LS-2"] = left + right

    K2 = permute(left + right, P8)
    steps["K2"] = K2

    return K1, K2, steps


def fk(bits, subkey):
    L, R = bits[:4], bits[4:]
    expanded = permute(R, EP)
    xor_result = format(int(expanded, 2) ^ int(subkey, 2), "08b")

    left_half, right_half = xor_result[:4], xor_result[4:]
    s0_out = sbox_lookup(left_half, S0)
    s1_out = sbox_lookup(right_half, S1)
    sbox_out = s0_out + s1_out
    p4_result = permute(sbox_out, P4)

    new_L = format(int(L, 2) ^ int(p4_result, 2), "04b")
    return new_L + R, {
        "EP(R)": expanded,
        "XOR": xor_result,
        "S0_out": s0_out,
        "S1_out": s1_out,
        "P4": p4_result,
        "L_new": new_L,
    }


def encrypt(plaintext, key):
    log = {}

    K1, K2, key_steps = generate_keys(key)
    log["Key generation"] = key_steps

    ip = permute(plaintext, IP)
    log["IP"] = ip

    # Round 1
    round1, details1 = fk(ip, K1)
    log["Round 1"] = details1

    switched = round1[4:] + round1[:4]
    log["Switch"] = switched

    # Round 2
    round2, details2 = fk(switched, K2)
    log["Round 2"] = details2

    cipher = permute(round2, IP_INV)
    log["Cipher"] = cipher

    return cipher, log


def decrypt(ciphertext, key):
    log = {}

    K1, K2, key_steps = generate_keys(key)
    log["Key generation"] = key_steps

    ip = permute(ciphertext, IP)
    log["IP"] = ip

    # Round 1 (K2)
    round1, details1 = fk(ip, K2)
    log["Round 1"] = details1

    switched = round1[4:] + round1[:4]
    log["Switch"] = switched

    # Round 2 (K1)
    round2, details2 = fk(switched, K1)
    log["Round 2"] = details2

    plain = permute(round2, IP_INV)
    log["Plain"] = plain

    return plain, log


if __name__ == "__main__":
    plaintext = "10111101"
    key = "1010000010"
    cipher, enc_log = encrypt(plaintext, key)
    print(f"Encrypted: {cipher}")
    print(f"Details: {enc_log}")
