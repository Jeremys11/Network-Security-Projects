import time

start_time = time.time()
def meet_in_the_middle_attack(plaintext_ciphertext):
    #Need looping and a table

    for plaintext in plaintext_ciphertext:
        ciphertext = plaintext_ciphertext[plaintext]

    total_time = time.time() - start_time
    return key,total_time