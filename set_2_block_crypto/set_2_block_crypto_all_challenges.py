import pkcs7_padding as ch9
import aes_cbc_mode as ch10
import ecb_cbc_detection_oracle as ch11
import byte_at_a_time_ecb_decryption_simple as ch12
import ecb_cut_and_paste as ch13
import byte_at_a_time_ecb_decryption_harder as ch14
import pkcs7_padding_validation as ch15
import cbc_bitflipping_attacks as ch16

def main():
    ch9.main()
    ch10.main()
    ch11.main()
    ch12.main()
    ch13.main()
    ch14.main()
    ch15.main()
    ch16.main()

if __name__ == '__main__':
    main()