import unpadded_message_recovery_oracle as ch41
import bleichenbacher_e_3_rsa_attack as ch42
import dsa_recovery_from_nonce as ch43
import dsa_nonce_recovery_from_repeated_nonce as ch44
import dsa_parameter_tampering as ch45
import rsa_parity_oracle as ch46
import bleichenbacher_padding_oracle_simple as ch47
import bleichenbacher_padding_oracle_complete as ch48

def main():
	ch41.main()
	ch42.main()
	ch43.main()
	ch44.main()
	ch45.main()
	ch46.main()
	ch47.main()
	ch48.main()

if __name__ == '__main__':
	main()