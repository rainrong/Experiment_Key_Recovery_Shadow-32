# **1、Program Introduction**&#x20;

This program is designed for Shadow-32, aiming to perform a 32-bit key recovery attack on the full-round of Shadow-32 using four 13.5-round differential characteristics. This program takes 00000100 as an example which is one of the differential characteristics indicated in the article, and the three other differential characteristics can be implemented by similar method.

# **2、Environment Configuration**

This program is based on the Python, and it is recommended to install Python version 3.8. Required packages include threading, collections, itertools, re, and bitstring 4.1.2. The example was run on the Win10 operating system with an Intel(R) Xeon(R) Platinum 8255C CPU.

# **3、Usage Example**

First, it is necessary to generate some encrypted ciphertexts and save them to ciphertext.txt in a format similar to that shown in Figure 1. Then, click to run the program. When trying to change other differential characteristics, the positions in the black boxes in Figures 2 and 3 need to be modified. The possible keys will be saved in output1.txt and output2.txt as shown in Figure 4. (Here, it is to prevent storing too many results in a single document.)

![image](https://github.com/rainrong/Experiment_Key_Recovery_Shadow-32/assets/101979257/5b66331c-a2bb-432f-95b5-3e08b17b8b90)
<center>Figure1</center>


![image](https://github.com/rainrong/Experiment_Key_Recovery_Shadow-32/assets/101979257/313ae2bc-4e21-4f70-83aa-06c2c7c41e6c)
<center>Figure2</center>

![image](https://github.com/rainrong/Experiment_Key_Recovery_Shadow-32/assets/101979257/43d5be41-4509-4ee7-9185-0c2350662d26)

<center>Figure3</center>

![image](https://github.com/rainrong/Experiment_Key_Recovery_Shadow-32/assets/101979257/e49bca11-dec5-4b85-bb32-d247ec9d32fe)
<center>Figure4</center>




# **4、Analysis of Computational Complexity**

（1）The first substep of key recovery requires guessing 8 bits, as shown in Figure 5.

Suppose the encryption process generates $C1$ pairs of ciphertext. Let $K1$ be the maximum number of 8-bit keys that satisfy the most ciphertext pairs. Let $K2$ be the maximum number of ciphertext pairs corresponding to these $K1$. Thus, the space complexity is $S(C2~*~K1)$.

Time complexity calculation: The key recovery in this round uses a double-layer for loop. The outer layer requires guessing an 8-bit key, leading to $2^8$ iterations. The inner loop through $C1$ ciphertext pairs. The **function get\_r14()** calls the function **reverse\_process()**, which performs a shifting operation as shown in Figure 6. Both the get\_r14() and other processes within the loop are at a constant time complexity level. Therefore, the time complexity of the first round of key recovery is $O(C1~*~2\hat{}8)$.

In the provided example, the encryption process generates 263 ciphertext pairs, resulting in $K1=64$ and $C2=75$. Thus, the space complexity is approximately $2^{12}$, and the time complexity is approximately $2^{16}$, taking 161436.34 ms.。

（2）The second substep of key recovery requires guessing 12 bits, as depicted in Figure 7.

Space complexity calculation: In this round, it is only necessary to save the keys that satisfy the most ciphertext pairs, which is denoted as $K2$. Therefore, the space complexity is $S(K2)$.

Time complexity calculation: The key recovery process in this round involves a triple-layer for loop. The outermost layer is not explicitly shown in the code as multithreading is employed. The outer layer represents the keys guessed in the first round, i.e., $K1$. The second layer involves guessing 12-bit keys, resulting in $2^{12}$ iterations. The innermost layer’s iteration count is the number of ciphertext pairs, i.e., $C2$. Similar to the first round’s recovery, the function get\_r13() (Figure 8) calls the function reverse\_process() for shifting, maintaining a constant time complexity. Thus, the time complexity of the second round is $O(K1*2^{12}*C2)$.

For the provided example, $K1$ is 64, $C2$ is 75, and $K2$ is $2^{8}$. Hence, the time complexity is approximately $2^{24}$, and the space complexity is $2^{8}$, with a total time of 67132990.29 ms.

The total time complexity of the 20-bit key recovery is $2^{24.02}$, the space complexity is $2^{12.1}$, and the actual total time is 67,294,426.63ms.

Conclusion: For the other trails in Table 5, the above steps can be repeated, and the 32-bit round key can be obtained based on four differential paths. The total time complexity is $2^{26.02}$, the space complexity is $2^{14.1}$, and the actual total time is 269,177,706.52ms.

![image](https://github.com/rainrong/Experiment_Key_Recovery_Shadow-32/assets/101979257/114b9794-392e-47d5-a96f-819ab0ecaa69)
<center>Figure5</center>

![image](https://github.com/rainrong/Experiment_Key_Recovery_Shadow-32/assets/101979257/c6da0fb3-dd4f-44be-8a2a-27b5319efc0c)
<center>Figure6</center>

![image](https://github.com/rainrong/Experiment_Key_Recovery_Shadow-32/assets/101979257/2b805bbb-29da-4928-b696-74d57ce43f38)
<center>Figure7</center>

![399723aa2cd08e4cef2950991bae446](https://github.com/rainrong/Experiment_Key_Recovery_Shadow-32/assets/101979257/5d24e44d-7026-4dbf-b100-0e11e8ac9e57)
<center>Figure8</center>




