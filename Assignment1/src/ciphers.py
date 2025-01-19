import argparse
import sys

# Caeser Cipher

def shifted_alphabet(shift: int):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    shift = 26 - (shift % 26)  # extracting from 26 to shift right
    return alphabet[shift:] + alphabet[:shift]


def encrypt_caesar(plaintext: str, shift: int):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    new_alphabet = shifted_alphabet(shift)

    result = []
    for char in plaintext:
        if char.isalpha():
            is_upper = char.isupper()  # Check if char is uppercase
            char = char.upper()  # Make uppercase for encryption
            encrypted_char = new_alphabet[alphabet.index(char)]
            # if original char is lowercase, made it lowercase when adding to the result
            result.append(encrypted_char if is_upper else encrypted_char.lower())
        else:
            result.append(char)  # if not a character add it as it is(space, punctuation etc.)

    return "".join(result)


def decrypt_caesar(ciphertext: str, shift: int):
    return encrypt_caesar(ciphertext, -shift)


# Affine Cipher

def encrypt_affine(plaintext: str, a: int, b: int):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = []

    for char in plaintext:
        if char.isalpha():
            index = alphabet.index(char.upper())
            new_index = ((a * index) + b) % 26
            new_char = alphabet[new_index]
            result.append(new_char if char.isupper() else new_char.lower())
        else:
            result.append(char)

    return "".join(result)


def decrypt_affine(ciphertext: str, a: int, b: int):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = []

    for char in ciphertext:
        if char.isalpha():
            index = alphabet.index(char.upper())
            modular_inverse = pow(a, -1, 26)
            new_index = (((index - b) * modular_inverse)) % 26
            new_char = alphabet[new_index]
            result.append(new_char if char.isupper() else new_char.lower())
        else:
            result.append(char)

    return "".join(result)


# Mono cipher

def encrypt_mono(plaintext: str, key: str):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    cipher_chars = []

    for char in plaintext:
        if char.isalpha():
            index = alphabet.index(char.upper())
            cipher_chars.append(key[index] if char.isupper() else key[index].lower())
        else:
            cipher_chars.append(char)
    return "".join(cipher_chars)


def decrypt_mono(ciphertext: str, key: str):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    plain_chars = []

    for char in ciphertext:
        if char.isalpha():
            index = key.index(char.upper())
            plain_chars.append(alphabet[index] if char.isupper() else alphabet[index].lower())
        else:
            plain_chars.append(char)
    return "".join(plain_chars)

file_name = sys.argv[2]

def main():
    parser = argparse.ArgumentParser(description="Cipher encryption/decryption tool")
    parser.add_argument("cipher", choices=["caesar", "affine", "mono"])
    parser.add_argument("file")
    parser.add_argument("mode", choices=["e", "d"])
    parser.add_argument("-s", type=int)
    parser.add_argument("-a", type=int)
    parser.add_argument("-b", type=int)
    parser.add_argument("-k")

    args = parser.parse_args()

    with open(args.file, 'r') as file:
        text = file.read()

    if args.cipher == "caesar":
        if args.mode == "e":
            if args.s is None:
                print("Caesar cipher requires a shift value!")
                return
            result = encrypt_caesar(text, args.s)
        elif args.mode == "d":
            if args.s is None:
                print("Caesar cipher requires a shift value!")
                return
            result = decrypt_caesar(text, args.s)

    elif args.cipher == "affine":
        if args.mode == "e":
            if args.a is None or args.b is None:
                print("Affine cipher requires both a and b values!")
                return
            result = encrypt_affine(text, args.a, args.b)
        elif args.mode == "d":
            if args.a is None or args.b is None:
                print("Affine cipher requires both a and b values!")
                return
            result = decrypt_affine(text, args.a, args.b)

    elif args.cipher == "mono":
        if args.mode == "e":
            if args.k is None:
                print("Mono-alphabetic cipher requires a key!")
                return
            result = encrypt_mono(text, args.k)
        elif args.mode == "d":
            if args.k is None:
                print("Mono-alphabetic cipher requires a key!")
                return
            result = decrypt_mono(text, args.k)

    print(result)

if __name__ == "__main__":
    main()
