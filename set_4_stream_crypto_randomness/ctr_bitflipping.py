import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import unequal_chunks, xor, string_to_bytearray
from aes_ctr_mode import encrypt_aes_ctr, decrypt_aes_ctr

KEY = string_to_bytearray("YELLOW SUBMARINE")
NONCE = bytearray([0]*8)

def encrypt_params(user_input):
	user_input_stripped = user_input.replace(";", "").replace("=", "")

	prefix = "comment1=cooking%20MCs;userdata="
	suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

	message = string_to_bytearray(prefix + user_input_stripped + suffix)
	return encrypt_aes_ctr(message, KEY, NONCE)

def check_admin(ciphertext):
	message = decrypt_aes_ctr(ciphertext, KEY, NONCE)
	return b";admin=true;" in message


def ctr_bitflip():
	user_input = "AadminZtrueZ"
	desired = ";admin=true;"

	ciphertext = encrypt_params(user_input)
	ciphertext_user_input = ciphertext[32:32+len(user_input)]

	delta = xor(string_to_bytearray(user_input), string_to_bytearray(desired))
	new_ciphertext_flipped = xor(ciphertext_user_input, delta)

	new_ciphertext = ciphertext[:32] + new_ciphertext_flipped + ciphertext[32+len(user_input):]

	return new_ciphertext

def main():
	flipped_ciphertext = ctr_bitflip()

	if check_admin(flipped_ciphertext):
		print("challenge 4.26 completed.")
	else:
		print("challenge 4.26 failed.")

if __name__ == '__main__':
	main()