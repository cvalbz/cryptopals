import break_random_access_rw_aes_ctr as ch25
import ctr_bitflipping as ch26
import recover_cbc_iv_equals_key as ch27
import sha1_keyed_mac as ch28
import break_sha1_keyed_mac_length_extension as ch29
import break_md4_keyed_mac_length_extension as ch30
import break_hmac_sha1_artificial_timing_leak as ch31
import break_hmac_sha1_less_artificial_timing_leak as ch32

def main():
    ch25.main()
    ch26.main()
    ch27.main()
    ch28.main()
    ch29.main()
    ch30.main()
    ch31.main()
    ch32.main()

if __name__ == '__main__':
    main()