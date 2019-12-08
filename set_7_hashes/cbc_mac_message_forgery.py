import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
from aes_cbc_mode import encrypt_aes_cbc
from utils import crypto_random_bytes, xor

SHARED_KEY = bytearray("YELLOW SUBMARINE")

def cbc_mac_sign(message, key):
	iv = bytearray('\x00'*16)
	c = encrypt_aes_cbc(message, key, iv)
	return c[-16:]


def cbc_mac_verify(message, mac, key):
	m = cbc_mac_sign(message, key)
	return m == mac # insecure but not the scope of the exercise

def cbc_mac_sign_controlled_iv(message, key, iv):
	c = encrypt_aes_cbc(message, key, iv)
	return c[-16:]

def cbc_mac_verify_controlled_iv(message, iv, mac, key):
	m = cbc_mac_sign_controlled_iv(message, key, iv)
	return m == mac # insecure but not the scope of the exercise

# message: from=#{from_id}&to=#{to_id}&amount=#{amount}
def process_transaction_controlled_iv(message, iv, mac):
	if not cbc_mac_verify_controlled_iv(message, iv, mac, SHARED_KEY):
		raise Exception("invalid transaction!!!")

	params = message.split("&")
	from_id = params[0].split("=")[1]
	to_id   = params[1].split("=")[1]
	amount = params[2].split("=")[1]

	print "from: %s| to: %s | amount: %s" % (from_id, to_id, amount)

def break_process_transaction_controlled_iv():
	iv = crypto_random_bytes(16)
	message = bytearray("from=%s&to=%s&amount=%s" % ("friend", "me", "1000000"))

	transaction_mac = cbc_mac_sign_controlled_iv(message, SHARED_KEY, iv)
	process_transaction_controlled_iv(message, iv, transaction_mac)

	old = bytearray("from=friend&to=m")
	new = bytearray("from=target&to=m")

	crafted_iv = xor(xor(old, iv), new)
	crafted_message = bytearray("from=%s&to=%s&amount=%s" % ("target", "me", "1000000"))

	process_transaction_controlled_iv(crafted_message, crafted_iv, transaction_mac)

# message: from=#{from_id}&tx_list=to:amount(;to:amount)*
def process_transactions(message, mac):
	if not cbc_mac_verify(message, mac, SHARED_KEY):
		raise Exception("invalid transaction!!!")

	params = message.split("&")
	from_id = params[0].split("=")[1]
	tx_list   = params[1].split("=")[1]

	txs = tx_list.split(";")
	for t in txs:
		to_id = t.split(":")[0]
		amount = t.split(":")[1]
		print "from: %s| to: %s | amount: %s" % (from_id, to_id, amount)

def break_process_transaction():
	message_1 = "from=%s&tx_list=%s:%s;%s:%s" % ("target", "alice_id", "100000", "bob_id", "10000")

	tag_1 = cbc_mac_sign(message_1, SHARED_KEY)
	process_transactions(message_1, tag_1)

	message_2 = xor(bytearray(";myaccnt:1000000"), tag_1)
	tag_2 = cbc_mac_sign(message_2, SHARED_KEY) # assume you trick client into sending this transaction
	try:
		process_transactions(message_2, tag_2)
	except:
		pass # do nothing, bogus transaction

	print "#"*25 + " FORGED TRANSACTION " + "#"*25
	crafted_message = message_1 + ";myaccnt:1000000"
	process_transactions(crafted_message, tag_2)

	return True


def test_functions():
	message = "SATOSHI NAKAMOTO" * 10
	key = "YELLOW SUBMARINE"

	mac = cbc_mac_sign(message, key)
	assert cbc_mac_verify(message, mac, key)

	iv  = bytearray("ABCDEFGHIJKLMNOP")
	mac = cbc_mac_sign_controlled_iv(message, key, iv)
	assert cbc_mac_verify_controlled_iv(message, iv, mac, key)

def main():
	test_functions()

	break_process_transaction_controlled_iv()
	print "#"*50

	if break_process_transaction():
		print("challenge 7.49 completed.")
	else:
		print("challenge 7.49 failed.")

if __name__ == '__main__':
	main()