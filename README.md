# S-AES
信息安全导论作业2：S-AES算法实现   
## 一、AES 和 S-AES：  
AES（Advanced Encryption Standard，高级加密标准）是一个对称密钥加密算法，广泛用于数据加密和保护。AES 的设计目标是提供高效的加密，同时保证足够的安全性。它有以下几个关键特点：  
加密块大小：AES 是分组加密算法，固定加密块大小为 128 位，即每次加密的数据长度为 128 位（16 字节）。  
密钥长度：AES 支持三种密钥长度：128 位、192 位和 256 位。密钥长度越长，安全性越高，但计算复杂度也相应增加。  
算法流程：  
密钥扩展：AES 首先通过密钥扩展生成多个轮密钥（轮密钥数量取决于密钥长度），这些密钥用于每一轮的加密运算。  
轮操作：AES 的加密过程分为多个轮次，不同密钥长度对应不同轮次（128 位密钥为 10 轮，192 位密钥为 12 轮，256 位密钥为 14 轮）。  
每轮操作：每轮包括以下步骤：  
字节代替（SubBytes）：使用固定的 S-Box 进行字节替换，以增加复杂性。  
行移位（ShiftRows）：将状态矩阵中的行循环左移，增加混淆性。  
列混淆（MixColumns）：对状态矩阵的每一列进行线性变换，提高扩散性。  
轮密钥加（AddRoundKey）：将轮密钥与当前状态矩阵进行异或运算。  

Simple AES 是一个简化版的 AES 加密算法模型。Simple AES 保留了核心思想和结构，但简化了操作过程和数据规模。以下是S-AES的不同之处：  
简化的分组大小：在实际 AES 中，分组大小为 128 位，而 Simple AES 通常使用更小的分组大小（例如 16 位或 32 位），使运算更直观、易于分析。  
简化的密钥长度：实际 AES 支持 128、192 和 256 位的密钥，但 Simple AES 使用更短的密钥（如 8 位或 16 位）。这缩短了轮密钥生成的过程，便于学习。  
缩短的轮数：在实际 AES 中，轮数取决于密钥长度（128 位密钥 10 轮，192 位密钥 12 轮，256 位密钥 14 轮）。而在 Simple AES 中，通常只有 2-4 轮，以降低计算复杂性。  

## 二、项目介绍  
### 项目名称
S-AES 加密解密工具  
### 项目功能  
本项目实现了一款基于 S-AES（简化的高级加密标准）算法的加密解密工具。用户可以通过简单的图形界面进行明文和密文的加解密操作。支持的功能包括：  
1、单重加密：对16位二进制字符串的明文进行单重加密。  
2、单重解密：对16位二进制字符串的密文进行单重解密。 
3、ASCII 字符串加密/解密：支持对 ASCII 字符串的加密和解密操作。
4、双重加密：对明文进行双重加密，使用32位二进制密钥。  
5、双重解密：对密文进行双重解密。  
6、三重加密：对明文进行三重加密，使用48位二进制密钥。  
7、三重解密：对密文进行三重解密。  
8、暴力破解：利用中间相遇攻击方法通过暴力破解的方式尝试找出密钥
9、CBC 模式加密：使用初始向量（IV）进行 CBC 模式的加密，支持明文为16位的倍数。  
10、CBC 模式解密：对 CBC 模式的密文进行解密。  
### UI 设计
#### 使用 Python 的 Tkinter 库创建图形用户界面（GUI），界面布局简洁易用。主要设计包括：
左侧菜单：用户可以通过按钮选择不同的操作（如加密、解密、双重加密、三重加密等）。  
主内容区域：根据用户选择的操作动态更新，显示输入框和按钮以便用户进行操作。  
消息弹窗：在加解密操作完成后，以弹窗形式显示结果或错误信息。  
### 函数说明
以下是主要函数的简介：  
show_custom_message(title, message)：弹出自定义消息框，显示指定标题和消息。  
encrypt_1()：实现单重加密功能。  
decrypt_1()：实现单重解密功能。  
encrypt_2()：实现双重加密功能。  
decrypt_2()：实现双重解密功能。  
encrypt_3()：实现三重加密功能。  
decrypt_3()：实现三重解密功能。  
encrypt_cbc()：实现 CBC 模式加密。  
decrypt_cbc()：实现 CBC 模式解密。  
encrypt_s()：对 ASCII 字符串进行加密。  
decrypt_s()：对 ASCII 字符串进行解密。  
brute_force_crack()：尝试暴力破解以找出密钥。  
show_encrypt_ui()：展示加密界面。  
show_decrypt_ui()：展示解密界面。  
show_double_ui()：展示双重加密/解密界面。  
show_triple_ui()：展示三重加密/解密界面。  
show_cbc_ui()：展示 CBC 模式加密/解密界面。 
show_brute_force_ui()：展示暴力破解界面。  
clear_ui()：清除主内容区域的组件。  
### 主要功能实现
#### 加密/解密函数  
函数：encrypt(plain_text, key)
参数：plain_text: 整数类型，待加密的明文（16位二进制转化后的整数）。key: 整数类型，密钥（16位二进制转化后的整数）。  
返回：返回加密后的密文（整数）。  
```python
# 基础加密函数
def encrypt(plain: int, key: int) -> int:
    # 密钥扩展
    key = key_expansion(key)
    # 明文转为状态矩阵
    state = int_to_matrix(plain)
    # 密钥加
    state = key_addition(state, key[:2])
    # 半字节代替
    state = substitute_nibble(state)
    # 行移位
    state = shift_rows(state)
    # 列混淆
    state = mix_columns(state)
    # 密钥加
    state = key_addition(state, key[2:4])
    # 半字节代替
    state = substitute_nibble(state)
    # 行移位
    state = shift_rows(state)
    # 密钥加
    state = key_addition(state, key[4:])
    # 状态矩阵转为数字
    return matrix_to_int(state)
```
#### ASCII 加密/解密函数
函数：encrypt_string(plain_text, key) 和 decrypt_string(cipher_text, key)  
参数：plain_text 或 cipher_text: 字符串，待处理的明文或密文。key: 整数类型，密钥（16位二进制转化后的整数）。  
返回：返回加密或解密后的结果（字符串）。
```python
# 字符串加密
def encrypt_string(plain_text: str, key: int) -> str:
    blocks = ascii_string_to_blocks(plain_text)
    cipher_blocks = []
    for block in blocks:
        cipher_block = encrypt(block, key)
        cipher_blocks.append(cipher_block)
    return blocks_to_ascii_string(cipher_blocks)
```
#### 双重加密/解密函数
函数：double_encrypt(plain_text, key)
参数：同上，key 为32位。
返回：返回加密后的密文（整数）。
```python
# 双重加密
def double_encrypt(plain: int, key: int) -> int:
    k1 = (key >> 16) & 0xFFFF
    k2 = key & 0xFFFF
    cipher = encrypt(plain, k1)
    return encrypt(cipher, k2)
```
#### 三重加密/解密函数
函数：triple_encrypt(plain_text, key)  
参数：同上，key 为48位。  
返回：返回加密后的密文（整数）。  
```python
# 三重加密
def triple_encrypt(plain: int, key: int) -> int:
    k1 = (key >> 32) & 0xFFFF
    k2 = (key >> 16) & 0xFFFF
    k3 = key & 0xFFFF
    cipher = encrypt(plain, k1)
    cipher = encrypt(cipher, k2)
    return encrypt(cipher, k3)
```
#### CBC 加密/解密函数
函数：cbc_encrypt(plain_text, key, iv)  
参数：plain_text: 字符串，待加密的明文。key: 整数类型，密钥（16位二进制转化后的整数）。iv: 整数类型，初始向量（IV，16位二进制转化后的整数）。  
返回：返回加密后的密文（字符串）。  
```python
# Cipher Block Chaining (CBC) 加密
def cbc_encrypt(plain: str, key: int, iv: int) -> str:
    plain = string_to_blocks(plain)
    cipher = []
    prev_cipher = iv
    for plain_block in plain:
        cipher_block = encrypt(plain_block ^ prev_cipher, key)
        cipher.append(cipher_block)
        prev_cipher = cipher_block
    return blocks_to_string(cipher)
```
#### 中间相遇攻击的暴力破解函数
函数：attack(plain_text, cipher_text)  
参数：plain_text: 字符串，待破解的明文。cipher_text: 字符串，待破解的密文。  
返回：返回可能的密钥组合（列表）。
```python
# 中间相遇攻击
def attack(plaintexts: str, ciphertexts: str) -> list:
    plaintexts = plaintexts.split()
    ciphertexts = ciphertexts.split()
    possible_keys = {}
    # 遍历第一个明密文对，生成初步候选密钥
    plain = int(plaintexts[0], 2)
    cipher = int(ciphertexts[0], 2)
    for k1 in range(0x10000):
        mid_value = encrypt(plain, k1)
        possible_keys[mid_value] = k1
    found_keys = []
    for k2 in range(0x10000):
        mid_value = decrypt(cipher, k2)
        if mid_value in possible_keys:
            found_keys.append((possible_keys[mid_value], k2))
    # 用剩余明密文对验证并过滤候选密钥
    for i in range(1, len(plaintexts)):
        plain = int(plaintexts[i], 2)
        cipher = int(ciphertexts[i], 2)
        found_keys = [
            (k1, k2) for k1, k2 in found_keys
            if encrypt(plain, k1) == decrypt(cipher, k2)
        ]
    return found_keys
```
##### 注意：项目具体测试实例请访问测试结果文档 
[查看文档]（https://github.com/ixsh1/SAES/blob/main/%E6%B5%8B%E8%AF%95%E7%BB%93%E6%9E%9C.doc）
---
<small> 注释：本次实验项目开发环境为python，基于 Tkinter 的 GUI 应用程序，如需修改或更新，请联系3328856646@qq.com。 </small>
