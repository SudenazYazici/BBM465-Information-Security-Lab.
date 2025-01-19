import string
from ciphers import *
import argparse
import re


# Reads file and stores words in a set
def load_words(file_path):
    with open(file_path, "r") as file:
        words = {line.strip().lower() for line in file}
    return words


def break_caesar(text, dictionary):
    for i in range(26):
        result = decrypt_caesar(text, i)
        message = result.split()
        isMeaningful = True
        for word in message:
            # Remove punctuation to match words with the dictionary
            word_cleaned = ''.join(char for char in word if char not in string.punctuation).lower()
            if word_cleaned in dictionary:
                continue
            else:
                isMeaningful = False
                break
        if isMeaningful:
            print(result)
            break

def break_affine(text, dictionary):
    a_values = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    for a in a_values:
        for b in range(26):
            result = decrypt_affine(text, a, b)
            message = result.split()
            isMeaningful = True
            for word in message:
                # Remove punctuation to match words with the dictionary
                word_cleaned = ''.join(char for char in word if char not in string.punctuation).lower()
                if word_cleaned in dictionary:
                    continue
                else:
                    isMeaningful = False
                    break
            if isMeaningful:
                print(result)
                break


def break_mono(text, dictionary):

    # Character frequency and n-grams commonly found in English
    english_freq = "etaoinshrdlcumwfgypbvkjxqz"
    english_bigrams = ['th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd']
    english_trigrams = ['the', 'and', 'for', 'ing', 'ent', 'ion', 'ter', 'est']
    english_quadrigrams = ['that', 'ther', 'with', 'tion', 'here', 'ould', 'ight', 'have']

    # Count occurrences of each letter in the ciphertext
    alphabet_count = {}
    for char in text:
        if char.isalpha():  # Only consider alphabetic characters
            char = char.lower()
            if char in alphabet_count:
                alphabet_count[char] += 1
            else:
                alphabet_count[char] = 1

    # Sort by frequency of letters in the ciphertext
    sorted_alphabet_count = sorted(alphabet_count.items(), key=lambda item: item[1], reverse=True)
    sorted_alphabet = []

    for i in range(26):
        sorted_alphabet.append(sorted_alphabet_count[i][0])

    mapping = {}
    used_chars = set()

    # Map the most frequent letters in the ciphertext to the most frequent English letters
    for i in range(5):
        cipher_char = sorted_alphabet[i]
        mapping[cipher_char.lower()] = english_freq[i]
        used_chars.add(english_freq[i])

    def decrypt(ciphertext, mapping):
        plaintext = ''
        for char in ciphertext:
            if char.isalpha():
                if char.lower() in mapping:
                    plaintext += mapping[char.lower()]
                else:
                    plaintext += char.upper()  # Show unmapped letters as uppercase
            else:
                plaintext += char  # Keep non-alphabetic characters unchanged
        return plaintext
    
    plaintext = decrypt(text, mapping)

    # Calculate n-gram frequencies in the text
    def calculate_ngrams(ciphertext):
        bigrams = {}
        trigrams = {}
        quadrigrams = {}
        filtered_text = ''.join([c.lower() for c in ciphertext if c.isalpha()])

        # Calculate bigram frequencies
        for i in range(len(filtered_text) - 1):
            bigram = filtered_text[i:i+2]
            if bigram in bigrams:
                bigrams[bigram] += 1
            else:
                bigrams[bigram] = 1

        # Calculate trigram frequencies
        for i in range(len(filtered_text) - 2):
            trigram = filtered_text[i:i+3]
            if trigram in trigrams:
                trigrams[trigram] += 1
            else:
                trigrams[trigram] = 1

        # Calculate quadrigram frequencies
        for i in range(len(filtered_text) - 3):
            quadrigram = filtered_text[i:i+4]
            if quadrigram in quadrigrams:
                quadrigrams[quadrigram] += 1
            else:
                quadrigrams[quadrigram] = 1

        return bigrams, trigrams, quadrigrams

    def sort_by_frequency(ngram_dict):
        return sorted(ngram_dict.items(), key=lambda item: item[1], reverse=True)

    for _ in range(5):  
        bigrams, trigrams, quadrigrams = calculate_ngrams(text)

        # Try to match bigrams based on frequency analysis
        bigram_matched = False
        for bigram in english_bigrams:
            if all(c in mapping.values() for c in bigram):
                continue
            cipher_bigram_candidates = [cb for cb, count in sort_by_frequency(bigrams) if cb[0] not in mapping and cb[1] not in mapping]
            for cb in cipher_bigram_candidates:
                tentative_mapping = mapping.copy()
                conflict = False
                for c_char, p_char in zip(cb, bigram):
                    if c_char in tentative_mapping:
                        if tentative_mapping[c_char] != p_char:
                            conflict = True
                            break
                    else:
                        if p_char in tentative_mapping.values():
                            conflict = True
                            break
                        tentative_mapping[c_char] = p_char
                if not conflict:
                    mapping.update(tentative_mapping)
                    for char in bigram:
                        used_chars.add(char)
                    bigram_matched = True

        # Try to match trigrams based on frequency analysis
        trigram_matched = False
        for trigram in english_trigrams:
            for cb, count in sort_by_frequency(trigrams):
                if all(c_char in mapping for c_char in cb):
                    continue
                tentative_mapping = mapping.copy()
                conflict = False
                for c_char, p_char in zip(cb, trigram):
                    if c_char in tentative_mapping:
                        if tentative_mapping[c_char] != p_char:
                            conflict = True
                            break
                    else:
                        if p_char in tentative_mapping.values():
                            conflict = True
                            break
                        tentative_mapping[c_char] = p_char
                if not conflict:
                    mapping.update(tentative_mapping)
                    trigram_matched = True
                    for char in trigram:
                        used_chars.add(char)
                    break

        # Try to match quadrigrams based on frequency analysis
        quadrigram_matched = False
        for quadrigram in english_quadrigrams:
            for cb, count in sort_by_frequency(quadrigrams):
                if all(c_char in mapping for c_char in cb):
                    continue
                tentative_mapping = mapping.copy()
                conflict = False
                for c_char, p_char in zip(cb, quadrigram):
                    if c_char in tentative_mapping:
                        if tentative_mapping[c_char] != p_char:
                            conflict = True
                            break
                    else:
                        if p_char in tentative_mapping.values():
                            conflict = True
                            break
                        tentative_mapping[c_char] = p_char
                if not conflict:
                    mapping.update(tentative_mapping)
                    quadrigram_matched = True
                    for char in quadrigram: 
                        used_chars.add(char)
                    break

        # Exit loop if any quadrigram match was found
        if quadrigram_matched:
            break

        # Exit loop if no bigram, trigram, or quadrigram matches were found
        if not bigram_matched and not trigram_matched and not quadrigram_matched:
            break
    
    plaintext = decrypt(text, mapping)

    # Processing word to match with dictionary using regex
    def process_word(word):
        clean_cipher_word = re.sub(r'[^a-zA-Z]', '', word)  # Keep only alphabetic characters
        # Replace uppercase letters with regex patterns, keep other characters as they are
        pattern = ''.join([r'[a-zA-Z]' if c.isupper() else c for c in clean_cipher_word])
        return pattern, clean_cipher_word

    for word in plaintext.split():
        upperWord = sum(1 for c in word if c.isupper())
        lowerWord = sum(1 for c in word if c.islower())
        if upperWord < lowerWord:
            pattern, clean_cipher_word = process_word(word)
            for dict_word in dictionary:
                if len(clean_cipher_word) == len(dict_word):
                    if re.fullmatch(pattern, dict_word):
                        plaintext = plaintext.replace(word, dict_word)
                        break

    plaintext = decrypt(text, mapping)
    
    print(plaintext)


def main():

    parser = argparse.ArgumentParser(description="Cipher encryption/decryption tool")
    parser.add_argument("cipher", choices=["caesar", "affine", "mono"])
    parser.add_argument("file")
    args = parser.parse_args()

    with open(args.file, 'r') as file:
        text = file.read()

    dictionary = load_words("dictionary.txt")

    if args.cipher == "caesar":
        break_caesar(text, dictionary)

    elif args.cipher == "affine":
        break_affine(text, dictionary)

    elif args.cipher == "mono":
        break_mono(text, dictionary)

if __name__ == "__main__":
    main()
