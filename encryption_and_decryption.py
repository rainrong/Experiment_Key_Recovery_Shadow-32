import random
import threading
import time
from collections import Counter
from itertools import product
import re
from bitstring import BitArray

# The expanded key algorithm's S-box table.
with open('s_box.txt', 'r') as file:
    s_box_data = file.read()
s_box_list = [int(value.strip(), 16) for value in s_box_data.split(',') if value.strip()]

# encryption
def encryption(plaintext, k, n):
    """
    :param plaintext: one-dimensional bit array,
    :param k:  Key, two-dimensional bit array
    :param n: Encryption rounds
    :return: returning ciphertext.

    """
    # Obtain four branches of plaintext, each with 8 bits.
    L0 = plaintext[:8]
    L1 = plaintext[8:16]
    R0 = plaintext[16:24]
    R1 = plaintext[24:32]
    for i in range(n):
        # Derive the subkeys for each round based on the key expansion algorithm.
        K0 = k[i][0:4] + k[i][8:12]
        K1 = k[i][4:8] + k[i][12:16]
        K2 = k[i][16:20] + k[i][24:28]
        K3 = k[i][20:24] + k[i][28:32]
        # Encryption process
        R0_result = operate(K0, L0, L1)
        L0_result = operate(K1, R0, R1)
        L1_result = operate(K2, R0_result, L0)
        R1_result = operate(K3, L0_result, R0)
        L0 = L0_result
        L1 = L1_result
        R0 = R0_result
        R1 = R1_result

    return L0, L1, R0, R1


# key expansion algorithm.
def change_k(k, n, k_len, C):
    if k_len == 64:
        k_16 = []
        for i in range(n):
            empty_bit_array = BitArray(length=64)
            empty_bit_array[48:64] = k[0][0:16]
            empty_bit_array[51] = empty_bit_array[51] ^ C[i][0]
            empty_bit_array[52] = empty_bit_array[52] ^ C[i][1]
            empty_bit_array[53] = empty_bit_array[53] ^ C[i][2]
            empty_bit_array[54] = empty_bit_array[54] ^ C[i][3]
            empty_bit_array[55] = empty_bit_array[55] ^ C[i][4]
            empty_bit_array[24:48] = k[0][32:56]
            empty_bit_array[4:16] = k[0][16:28]
            empty_bit_array[20:24] = k[0][28:32]
            change_8 = s_box_list[int(k[0][56:64].bin, 2)]
            binary_string_8 = format(change_8, '08b')
            binary_array_8 = [int(bit) for bit in binary_string_8]
            empty_bit_array[0], empty_bit_array[1], empty_bit_array[2], empty_bit_array[3] = binary_array_8[0], \
                                                                                             binary_array_8[1], \
                                                                                             binary_array_8[2], \
                                                                                             binary_array_8[3]
            empty_bit_array[16], empty_bit_array[17], empty_bit_array[18], empty_bit_array[19] = binary_array_8[4], \
                                                                                                 binary_array_8[5], \
                                                                                                 binary_array_8[6], \
                                                                                                 binary_array_8[7]
            k[0] = empty_bit_array
            k_16.append(empty_bit_array)
    else:
        empty_bit_array = BitArray(length=128)
    return k_16


# Encryption algorithm
def get_ciphertext():
    # Select the key and perform key expansion.
    key = [BitArray(bin='0111100100000111010001111010011011001101001100101110011000111100')]
    C = [BitArray(bin='10110'), BitArray(bin='11011'), BitArray(bin='00011'), BitArray(bin='01010'),
         BitArray(bin='10101'), BitArray(bin='00001'), BitArray(bin='00010'), BitArray(bin='11101'),
         BitArray(bin='00011'), BitArray(bin='01111'), BitArray(bin='01011'), BitArray(bin='01100'),
         BitArray(bin='11000'), BitArray(bin='10000'), BitArray(bin='10100'), BitArray(bin='10110')]
    key = change_k(key, 16, 64, C)
    print(key)
    numbers = 0
    satisfies = 0
    content = ''
    for i in range(2 ** 14):
        # Generate a random bit array of length 32.
        random_bits = [random.choice([0, 1]) for _ in range(32)]
        random_bit_array = BitArray(bin="".join(map(str, random_bits)))
        # Obtain plaintext p0
        p0_x0 = random_bit_array[0:8]
        p0_x1 = random_bit_array[8:16]
        p0_x2 = random_bit_array[16:24]
        p0_x3 = random_bit_array[24:32]
        # obtain plaintext P1 based on the input differential characteristic
        p1_x0 = p0_x0 ^ BitArray(bin='00000100')
        deta_T1 = T(p0_x0) ^ T(p1_x0)
        p1_x1 = p0_x1 ^ deta_T1
        p1_x2 = p0_x2 ^ BitArray(bin='00000100')
        deta_T3 = T(p0_x2) ^ T(p1_x2)
        p1_x3 = p0_x3 ^ deta_T3
        p0 = p0_x0 + p0_x1 + p0_x2 + p0_x3
        p1 = p1_x0 + p1_x1 + p1_x2 + p1_x3
        numbers = numbers + 1

        if not iterative(p0, p1, key, 13, '00000000', '00000100'):
            continue
        # Perform 16 rounds of encryption.
        p0_L0, p0_L1, p0_R0, p0_R1 = encryption(p0, key, 16)
        p1_L0, p1_L1, p1_R0, p1_R1 = encryption(p1, key, 16)
        # Four output differentials.
        output_T1 = p0_L0 ^ p1_L0
        output_T2 = p0_L1 ^ p1_L1
        output_T3 = p0_R0 ^ p1_R0
        output_T4 = p0_R1 ^ p1_R1
        # The first and third differentials first go through the T function
        # and then perform XOR, followed by XOR with 0000 (C1)0(C2)0.
        output_T3_X16_2 = T(p0_R0) ^ T(p1_R0)
        output_T1_X16_0 = T(p0_L0) ^ T(p1_L0)

        output_T2_1 = output_T3_X16_2 ^ BitArray(bin='00000000')
        output_T2_2 = output_T3_X16_2 ^ BitArray(bin='00000010')
        output_T2_3 = output_T3_X16_2 ^ BitArray(bin='00001000')
        output_T2_4 = output_T3_X16_2 ^ BitArray(bin='00001010')

        output_T4_1 = output_T1_X16_0 ^ BitArray(bin='00000000')
        output_T4_2 = output_T1_X16_0 ^ BitArray(bin='00000010')
        output_T4_3 = output_T1_X16_0 ^ BitArray(bin='00001000')
        output_T4_4 = output_T1_X16_0 ^ BitArray(bin='00001010')

        satisfies_condition2_1 = all(p == q for p, q in zip(output_T2_1.bin, output_T2.bin))
        satisfies_condition2_2 = all(p == q for p, q in zip(output_T2_2.bin, output_T2.bin))
        satisfies_condition2_3 = all(p == q for p, q in zip(output_T2_3.bin, output_T2.bin))
        satisfies_condition2_4 = all(p == q for p, q in zip(output_T2_4.bin, output_T2.bin))

        satisfies_condition4_1 = all(p == q for p, q in zip(output_T4_1.bin, output_T4.bin))
        satisfies_condition4_2 = all(p == q for p, q in zip(output_T4_2.bin, output_T4.bin))
        satisfies_condition4_3 = all(p == q for p, q in zip(output_T4_3.bin, output_T4.bin))
        satisfies_condition4_4 = all(p == q for p, q in zip(output_T4_4.bin, output_T4.bin))

        # The output differentials of the second and fourth branches need to be equal to 000? 0?0?, with 8 possible
        # combinations.
        satisfies_condition1 = False
        if output_T1 == BitArray(bin='00000000') or output_T1 == BitArray(bin='00000001') or output_T1 == BitArray(
                bin='00000100') or output_T1 == BitArray(bin='00000101') \
                or output_T1 == BitArray(bin='00010000') or output_T1 == BitArray(
            bin='00010001') or output_T1 == BitArray(bin='00010100') or output_T1 == BitArray(bin='00010101'):
            satisfies_condition1 = True

        satisfies_condition3 = False
        if output_T3 == BitArray(bin='00000000') or output_T3 == BitArray(bin='00000001') or output_T3 == BitArray(
                bin='00000100') or output_T3 == BitArray(bin='00000101') \
                or output_T3 == BitArray(bin='00010000') or output_T3 == BitArray(
            bin='00010001') or output_T3 == BitArray(bin='00010100') or output_T3 == BitArray(bin='00010101'):
            satisfies_condition3 = True

        if satisfies_condition1 and (satisfies_condition2_1 or satisfies_condition2_2 or satisfies_condition2_3 or
                                     satisfies_condition2_4) and satisfies_condition3 and (
                satisfies_condition4_1 or satisfies_condition4_2 or
                satisfies_condition4_3 or satisfies_condition4_4):
            satisfies = satisfies + 1
            content = content+ "明文1：" + p0.bin + " 明文2：" + p1.bin + "\n密文1：" + p0_L0.bin + p0_L1.bin + p0_R0.bin + \
                p0_R1.bin + " 密文2:" + p1_L0.bin + p1_L1.bin + p1_R0.bin + p1_R1.bin + "\n**************************" +\
                                                                                      "**************************"+\
                                                                                      "**************************\n"
            print("明文1：" + p0.bin + " 明文2：" + p1.bin + "\n密文1：" + p0_L0.bin + p0_L1.bin + p0_R0.bin + \
                p0_R1.bin + " 密文2:" + p1_L0.bin + p1_L1.bin + p1_R0.bin + p1_R1.bin + "\n**************************" +\
                                                                                      "**************************"+\
                                                                                      "**************************")

    with open('ciphertext.txt', 'w') as file:
     file.write(content)
    print("明文对满足数：" + str(numbers) + "\n" + "输出差分满足数：" + str(satisfies) + "\n概率为：" + str(
        satisfies / numbers))


# Function for the process of 0.5 encryption rounds
def operate(K, LR0, LR1):
    """
    :param K: the key for this round
    :param LR0: the left branch
    :param LR1: the right branch
    :return: the result after encryption
    """
    LR0_left_shift_1 = circular_left_shift(LR0, 1)
    LR0_left_shift_7 = circular_left_shift(LR0, 7)
    LR0_left_shift_2 = circular_left_shift(LR0, 2)
    # Perform an AND operation on the results of left shifting by 1 and 7 bits, then perform XOR with L1,
    # followed by XOR with a left shift by 2 bits, and finally XOR with K0.
    LR_result = (LR0_left_shift_1 & LR0_left_shift_7) ^ LR1 ^ LR0_left_shift_2 ^ K
    return LR_result


# The T function.
def T(LR0):
    LR0_left_shift_1 = circular_left_shift(LR0, 1)
    LR0_left_shift_7 = circular_left_shift(LR0, 7)
    LR0_left_shift_2 = circular_left_shift(LR0, 2)
    T_back = LR0_left_shift_1 & LR0_left_shift_7 ^ LR0_left_shift_2
    return T_back


# Circular left shift.
def circular_left_shift(bit_array, shift_amount):
    shifted_bits = bit_array[shift_amount:] + bit_array[:shift_amount]
    return shifted_bits


# Specify that the output differential for a certain round satisfies T1 for both the left and right branches.
def iterative(p0, p1, key, n, T1, T2):
    p0_L0, p0_L1, p0_R0, p0_R1 = encryption(p0, key, n)
    p1_L0, p1_L1, p1_R0, p1_R1 = encryption(p1, key, n)
    output_T1 = p0_L0 ^ p1_L0
    output_T2 = p0_L1 ^ p1_L1
    output_T3 = p0_R0 ^ p1_R0
    output_T4 = p0_R1 ^ p1_R1
    if not (output_T1 == BitArray(bin=T1) and output_T2 == BitArray(bin=T2) and output_T3 == BitArray(
            bin=T1) and output_T4 == BitArray(bin=T2)):
        return False
    return True


# first round key recovery,
def first_guess_8bit(p0_list, p1_list):
    k15_2_3_list = []
    possible_list = []
    ciphertext0_list = []
    ciphertext1_list = []
    # In the first round of key recovery, the keys k15_0, k15_1, k14_2, and k14_3 do not affect the result,
    # therefore all are set to 0.
    k15_0, k15_1 = BitArray(bin='00000000'), BitArray(bin='00000000')
    k14_2 = k14_3 = BitArray(bin='00000000')
    # Outer loop 2^8 times, guessing 8 bits from 0000 0000 to 1111 1111.
    for p in product(['0', '1'], repeat=8):
        flag = False
        p0_list_2round = []
        p1_list_2round = []
        k15_2, k15_3 = BitArray(bin=f'{p[0]}0{p[1]}0{p[2]}0{p[3]}0'), BitArray(bin=f'{p[4]}0{p[5]}0{p[6]}0{p[7]}0')
        # Inner loop, iterating through the number of generated ciphertext pairs during encryption.
        for i, (p0, p1) in enumerate(zip(p0_list, p1_list)):
            p0_ciphertext = BitArray(bin=p0)
            p1_ciphertext = BitArray(bin=p1)
            p0_x0, p0_x1, p0_x2, p0_x3 = p0_ciphertext[0:8], p0_ciphertext[8:16], p0_ciphertext[16:24], p0_ciphertext[
                                                                                                        24:32]
            p1_x0, p1_x1, p1_x2, p1_x3 = p1_ciphertext[0:8], p1_ciphertext[8:16], p1_ciphertext[16:24], p1_ciphertext[
                                                                                                        24:32]

            p0_r14_x1, p0_r14_x3 = get_r14(p0_x2, p0_x0, p0_x1, p0_x3, k14_2, k14_3, k15_0, k15_1, k15_2, k15_3)
            p1_r14_x1, p1_r14_x3 = get_r14(p1_x2, p1_x0, p1_x1, p1_x3, k14_2, k14_3, k15_0, k15_1, k15_2, k15_3)
            if p0_r14_x1 ^ p1_r14_x1 == BitArray(bin='00000100') and p0_r14_x3 ^ p1_r14_x3 == BitArray(bin='00000100'):
                corresponding = (str(int(k15_2[0])) + str(int(k15_2[2])) + str(int(k15_2[4])) + str(int(k15_2[6])) +
                                 str(int(k15_3[0])) + str(int(k15_3[2])) + str(int(k15_3[4])) + str(int(k15_3[6])))
                p0_list_2round.append(p0_x0 + p0_x1 + p0_x2 + p0_x3)
                p1_list_2round.append(p1_x0 + p1_x1 + p1_x2 + p1_x3)
                flag = True
        if flag:
            possible_list.append(corresponding)
            k15_2_3_list.append(k15_2.bin + k15_3.bin)
            ciphertext0_list.append(p0_list_2round)
            ciphertext1_list.append(p1_list_2round)

    return possible_list, ciphertext0_list, ciphertext1_list


# second round key recovery.
def second_guess_12bit(k, p0_list, p1_list):
    # Although there are 3 bits XORed with k14 and k15 during the guessing here,
    # k14 can be set to 0, and any 3 bits can be selected for k15.
    k14_0 = k14_1 = k14_2 = k14_3 = BitArray(bin='00000000')
    possible2_list = []
    k0 = k[0]
    k2 = k[1]
    k4 = k[2]
    k6 = k[3]
    k8 = k[4]
    k10 = k[5]
    k12 = k[6]
    k14 = k[7]
    # Outer loop 2^12 times, guessing 8 bits
    for q in product(['0', '1'], repeat=12):
        k15_2, k15_3 = BitArray(bin=f'{k0}{q[0]}{k2}0{k4}{q[1]}{k6}{q[2]}'), \
                       BitArray(bin=f'{k8}{q[3]}{k10}0{k12}{q[4]}{k14}{q[5]}')
        k15_0, k15_1 = BitArray(bin=f'000{q[6]}0{q[7]}0{q[8]}'), BitArray(bin=f'000{q[9]}0{q[10]}0{q[11]}')
        # The inner loop corresponds to the number of ciphertext pairs used in the current first-round 8-bit key guess
        for i, (p0, p1) in enumerate(zip(p0_list, p1_list)):
            p0_ciphertext = BitArray(bin=p0.bin)
            p1_ciphertext = BitArray(bin=p1.bin)
            p0_x0, p0_x1, p0_x2, p0_x3 = p0_ciphertext[0:8], p0_ciphertext[8:16], p0_ciphertext[16:24], p0_ciphertext[
                                                                                                        24:32]
            p1_x0, p1_x1, p1_x2, p1_x3 = p1_ciphertext[0:8], p1_ciphertext[8:16], p1_ciphertext[16:24], p1_ciphertext[
                                                                                                        24:32]

            p0_r14_x1, p0_r14_x3, p0_r13_x0, p0_r13_x2 = get_r13(p0_x2, p0_x0, p0_x1, p0_x3, k14_0, k14_1, k14_2,
                                                                 k14_3, k15_0, k15_1, k15_2, k15_3)
            p1_r14_x1, p1_r14_x3, p1_r13_x0, p1_r13_x2 = get_r13(p1_x2, p1_x0, p1_x1, p1_x3, k14_0, k14_1, k14_2,
                                                                 k14_3, k15_0, k15_1, k15_2, k15_3)
            output_T13_0 = T(p0_r13_x0) ^ T(p1_r13_x0)
            output_T13_2 = T(p0_r13_x2) ^ T(p1_r13_x2)
            output_T14_1 = p0_r14_x1 ^ p1_r14_x1
            output_T14_3 = p0_r14_x3 ^ p1_r14_x3
            if output_T13_0 == output_T14_1 and output_T13_2 == output_T14_3:
                corresponding = k15_0.bin, k15_1.bin, k15_2.bin, k15_3.bin
                possible2_list.append(corresponding)
    return possible2_list


# Reverse function used for decrypting  0.5 round.
def reverse_process(LR0, LR1, k):
    LR0_left_shift_1 = circular_left_shift(LR0, 1)
    LR0_left_shift_7 = circular_left_shift(LR0, 7)
    LR0_left_shift_2 = circular_left_shift(LR0, 2)
    return LR1 ^ k ^ LR0_left_shift_2 ^ (LR0_left_shift_1 & LR0_left_shift_7)


# Used for the first round key recovery, decrypting to obtain the values of the second
# and fourth branches in the input of the 14.5th round.
def get_r14(r15_2_x0, r15_2_x2, r16_x1, r16_x3, k14_2, k14_3, k15_0, k15_1, k15_2, k15_3):
    r15_2_x1, r15_2_x3 = reverse_process(r15_2_x0, r16_x1, k15_2), reverse_process(r15_2_x2, r16_x3, k15_3)
    r15_1_x0, r15_1_x2 = r15_2_x1, r15_2_x3
    r15_1_x1, r15_1_x3 = reverse_process(r15_2_x1, r15_2_x0, k15_0), reverse_process(r15_2_x3, r15_2_x2, k15_1)
    r14_2_x0, r14_2_x2 = r15_1_x2, r15_1_x0
    r14_2_x1, r14_2_x3 = reverse_process(r14_2_x0, r15_1_x1, k14_2), reverse_process(r14_2_x2, r15_1_x3, k14_3)
    return r14_2_x1, r14_2_x3


# Used for the second round key recovery, decrypting to obtain the values of the second and
# fourth branches in the input of the 14th round, as well as the values of the first and
# third branches in the input of the 13.5th round.
def get_r13(r15_2_x0, r15_2_x2, r16_x1, r16_x3, k14_0, k14_1, k14_2, k14_3, k15_0, k15_1, k15_2, k15_3):
    r15_2_x1, r15_2_x3 = reverse_process(r15_2_x0, r16_x1, k15_2), reverse_process(r15_2_x2, r16_x3, k15_3)
    r15_1_x0, r15_1_x2 = r15_2_x1, r15_2_x3
    r15_1_x1, r15_1_x3 = reverse_process(r15_2_x1, r15_2_x0, k15_0), reverse_process(r15_2_x3, r15_2_x2, k15_1)
    r14_2_x0, r14_2_x2 = r15_1_x2, r15_1_x0
    r14_2_x1, r14_2_x3 = reverse_process(r14_2_x0, r15_1_x1, k14_2), reverse_process(r14_2_x2, r15_1_x3, k14_3)
    r14_1_x0, r14_1_x2 = r14_2_x1, r14_2_x3
    r14_1_x1, r14_1_x3 = reverse_process(r14_2_x1, r14_2_x0, k14_0), reverse_process(r14_2_x3, r14_2_x2, k14_1)
    r13_2_x0, r13_2_x2 = r14_1_x2, r14_1_x0
    return r14_1_x1, r14_1_x3, r13_2_x0, r13_2_x2


# Multithreaded grouping.
def divide_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


# The function called by the first round key recovery for multithreading
def process_sublist(sublist_p0, sublist_p1, results, index):
    results[index] = first_guess_8bit(sublist_p0, sublist_p1)


# The function called by the second round key recovery for multithreading.
def process_sublist2(k, sublist_p0, sublist_p1, results, index):
    results[index] = second_guess_12bit(k, sublist_p0, sublist_p1)


if __name__ == '__main__':
    '''
    Encryption uses the following code.
    Simply remove the # symbol from the following 5 lines. 
    '''
    # start_time = time.time()
    # get_ciphertext()
    # end_time = time.time()
    # elapsed_time = (end_time - start_time) * 1000  # onverted to milliseconds.
    # print("加密结束，程序运行时间：", elapsed_time, "毫秒")

    '''
    The key recovery uses the following code.
    The ciphertext.txt contains the ciphertext obtained in this example encryption.
    '''
    list_p0 = []
    list_p1 = []

    # Open the file for reading, specifying the use of the UTF-8 encoding
    with open("ciphertext.txt", "r") as file:
        lines = file.readlines()
    # use regular expression pattern matching to locate ciphertext.
    pattern = re.compile(r"密文1：([0-1]+) 密文2:([0-1]+)")
    # Iterate through each line and search for the content of ciphertext 1 and ciphertext 2.
    for line in lines:
        match = pattern.search(line)
        if match:
            ciphertext_p0 = match.group(1)
            ciphertext_p1 = match.group(2)
            list_p0.append(ciphertext_p0)
            list_p1.append(ciphertext_p1)
    start_time1 = time.time()
    # Divide into 10 threads.
    sublists_p0 = list(divide_list(list_p0, len(list_p0) // 10))
    sublists_p1 = list(divide_list(list_p1, len(list_p1) // 10))
    threads = []
    results = [None] * 10
    # Start the threads
    for i in range(10):
        thread = threading.Thread(target=process_sublist, args=(sublists_p0[i], sublists_p1[i], results, i))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

    final_most_count_guesskey_list = []
    final_most_count_ciphertext0_list = []
    final_most_count_ciphertext1_list = []
    #  integrate the results from the 10 threads
    for result in results:
        if result is not None:
            most_count_guesskey_list, most_count_ciphertext0_list, most_count_ciphertext1_list = result
            final_most_count_guesskey_list.extend(most_count_guesskey_list)
            final_most_count_ciphertext0_list.extend(most_count_ciphertext0_list)
            final_most_count_ciphertext1_list.extend(most_count_ciphertext1_list)

    final_result_dict = {}
    for i in range(len(final_most_count_guesskey_list)):
        current_key = final_most_count_guesskey_list[i]
        if current_key in final_result_dict:
            final_result_dict[current_key][0].extend(final_most_count_ciphertext0_list[i])
            final_result_dict[current_key][1].extend(final_most_count_ciphertext1_list[i])
        else:
            final_result_dict[current_key] = [final_most_count_ciphertext0_list[i],
                                              final_most_count_ciphertext1_list[i]]

    # Extract the results.
    final_most_count_guesskey_list = list(final_result_dict.keys())
    final_most_count_ciphertext0_list = [final_result_dict[key][0] for key in final_most_count_guesskey_list]
    final_most_count_ciphertext1_list = [final_result_dict[key][1] for key in final_most_count_guesskey_list]

    most_count = 0
    most_count_guesskey_list = []
    most_count_ciphertext0_list = []
    most_count_ciphertext1_list = []
    # Retrieve the number of maximum ciphertext pairs satisfied by the guessed 8-bit key, such as 75 in this example.
    # Then, check if there are any other keys corresponding to 75 pairs of ciphertext, and perform the second round
    # of key recovery on these keys along with the 75 pairs of ciphertext corresponding to each key.
    for i in range(len(final_most_count_guesskey_list)):
        if len(final_most_count_ciphertext0_list[i]) > most_count:
            most_count = len(final_most_count_ciphertext0_list[i])
    for i in range(len(final_most_count_guesskey_list)):
        if len(final_most_count_ciphertext0_list[i]) == most_count:
            most_count_guesskey_list.append(final_most_count_guesskey_list[i])
            most_count_ciphertext0_list.append(final_most_count_ciphertext0_list[i])
            most_count_ciphertext1_list.append(final_most_count_ciphertext1_list[i])
    for i in range(len(most_count_guesskey_list)):
        print("猜测密钥", most_count_guesskey_list[i], "出现次数", len(most_count_ciphertext0_list[i]), "密文1",
              most_count_ciphertext0_list[i], "密文2", most_count_ciphertext1_list[i])
    end_time = time.time()
    elapsed_time = (end_time - start_time1) * 1000  # 转换为毫秒
    print("密钥恢复过程1运行时间：", elapsed_time, "毫秒")
    # The process of the second round of key recovery.
    start_time = time.time()
    threads = []
    # The number of threads is the number of keys that satisfy the most number of ciphertext pairs in the first round.
    results = [None] * len(most_count_guesskey_list)
    for i in range(len(most_count_guesskey_list)):
        thread = threading.Thread(target=process_sublist2, args=(
            most_count_guesskey_list[i], most_count_ciphertext0_list[i], most_count_ciphertext1_list[i], results, i))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

    final_most_count_guesskey_list = []
    # Integrate the results of each thread
    for result in results:
        if result is not None:
            final_most_count_guesskey_list.extend(result)
    # sort the keys based on the number of ciphertext pairs they satisfy, from high to low.
    # Select the key that satisfies the most number of ciphertext pairs as the guessed key.
    element_counter = Counter(final_most_count_guesskey_list)
    most_common_elements = element_counter.most_common()
    max_count = most_common_elements[0][1]
    most_common_elements = [element for element, count in most_common_elements if count == max_count]
    end_time = time.time()
    elapsed_time = (end_time - start_time) * 1000  # 转换为毫秒
    print("密钥恢复过程2程序运行时间：", elapsed_time, "毫秒")
    halfway_index = len(most_common_elements) // 2
    # The final results will be saved in output1.txt and output2.txt.
    with open('output1.txt', 'w') as file1, open('output2.txt', 'w') as file2:
        for i, element in enumerate(most_common_elements):
            file = file1 if i <= halfway_index else file2
            file.write(f"元素: {element} 出现次数: {max_count}\n")
