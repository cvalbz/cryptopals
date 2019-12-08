import cbc_padding_oracle as ch17
import aes_ctr_mode as ch18
import break_fixed_nonce_ctr_substitutions as ch19
import break_fixed_nonce_ctr_statistically as ch20
import mersenne_twister_rng as ch21
import crack_mt19937_seed as ch22
import clone_mt19937_rng as ch23
import break_mt19937_stream_cipher as ch24

def main():
    ch17.main()
    ch18.main()
    ch19.main()
    ch20.main()
    ch21.main()
    ch22.main()
    ch23.main()
    ch24.main()

if __name__ == '__main__':
    main()