from utils import hex_string_to_bytearray, chunks_of

def has_repeated_blocks(bt):
    chunks = chunks_of(bt, 16)

    tuple_chunks = [tuple(c) for c in chunks]
    return len(tuple_chunks) != len(set(tuple_chunks))

def detect_ecb_mode(bts):
    return [bt for bt in bts if has_repeated_blocks(bt)]

def main():
    with open("8.txt", "r") as f: lines_hex = f.readlines()
    lines_hex_stripped = [line.replace("\n", "") for line in lines_hex]
    ciphertexts_bt = [hex_string_to_bytearray(line) for line in lines_hex_stripped]

    ecb_ciphertexts = detect_ecb_mode(ciphertexts_bt)
    if len(ecb_ciphertexts) == 1:
        print("challenge 1.8 completed.")
    else:
        print("challenge 1.8 failed.")      

if __name__ == '__main__':
    main()