import tkinter as tk
from tkinter import messagebox, Toplevel, Label
from S_AES import encrypt, decrypt, encrypt_string, decrypt_string, double_encrypt, double_decrypt, triple_encrypt, triple_decrypt, cbc_encrypt, cbc_decrypt


def show_custom_message(title, message):
    popup = Toplevel(root)
    popup.title(title)
    popup.geometry("400x200")  # 设置弹窗大小
    Label(popup, text=message, font=("Arial", 14), wraplength=350).pack(expand=True, pady=20)
    tk.Button(popup, text="关闭", command=popup.destroy).pack(pady=10)


def encrypt_1():
    plain_text = plain_text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    if not plain_text or not (len(plain_text) == 16 and all(char in '01' for char in plain_text)):
        messagebox.showerror("错误", "明文必须是16位的二进制字符串。")
        return
    if not key or not (len(key) == 16 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是16位的二进制字符串。")
        return
    cipher_text = encrypt(int(plain_text, 2), int(key, 2))
    show_custom_message("加密结果", f"加密得到密文: {cipher_text}")


def decrypt_1():
    cipher_text = cipher_text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    if not cipher_text or not (len(cipher_text) == 16 and all(char in '01' for char in cipher_text)):
        messagebox.showerror("错误", "密文必须是16位的二进制字符串。")
        return
    if not key or not (len(key) == 16 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是16位的二进制字符串。")
        return
    plain_text = decrypt(int(cipher_text, 2), int(key, 2))
    show_custom_message("解密结果", f"解密得到明文: {plain_text}")


def encrypt_2():
    plain_text = text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    if not plain_text or not (len(plain_text) == 16 and all(char in '01' for char in plain_text)):
        messagebox.showerror("错误", "明文必须是16位的二进制字符串。")
        return
    if not key or not (len(key) == 32 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是32位的二进制字符串。")
        return
    cipher_text = encrypt(int(plain_text, 2), int(key, 2))
    show_custom_message("加密结果", f"加密得到密文: {cipher_text}")


def decrypt_2():
    cipher_text = text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    if not cipher_text or not (len(cipher_text) == 16 and all(char in '01' for char in cipher_text)):
        messagebox.showerror("错误", "密文必须是16位的二进制字符串。")
        return
    if not key or not (len(key) == 32 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是32位的二进制字符串。")
        return
    plain_text = decrypt(int(cipher_text, 2), int(key, 2))
    show_custom_message("解密结果", f"解密得到明文: {plain_text}")


def encrypt_3():
    plain_text = text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    if not plain_text or not (len(plain_text) == 16 and all(char in '01' for char in plain_text)):
        messagebox.showerror("错误", "明文必须是16位的二进制字符串。")
        return
    if not key or not (len(key) == 48 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是48位的二进制字符串。")
        return
    cipher_text = encrypt(int(plain_text, 2), int(key, 2))
    show_custom_message("加密结果", f"加密得到密文: {cipher_text}")


def decrypt_3():
    cipher_text = text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    if not cipher_text or not (len(cipher_text) == 16 and all(char in '01' for char in cipher_text)):
        messagebox.showerror("错误", "密文必须是16位的二进制字符串。")
        return
    if not key or not (len(key) == 48 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是48位的二进制字符串。")
        return
    plain_text = decrypt(int(cipher_text, 2), int(key, 2))
    show_custom_message("解密结果", f"解密得到明文: {plain_text}")


def encrypt_cbc():
    plain_text = text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    iv = iv_text_entry.get("1.0", tk.END).strip()
    if not plain_text or not ((len(plain_text) % 16) == 0 and all(char in '01' for char in plain_text)):
        messagebox.showerror("错误", "明文必须是16位倍数的二进制字符串。")
        return
    if not key or not (len(key) == 16 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是16位的二进制字符串。")
        return
    if not iv or not (len(iv) == 16 and all(char in '01' for char in iv)):
        messagebox.showerror("错误", "初始向量必须是16位的二进制字符串。")
        return
    cipher_text = cbc_encrypt(plain_text, int(key, 2), int(iv, 2))
    show_custom_message("加密结果", f"加密得到密文: {cipher_text}")


def decrypt_cbc():
    cipher_text = text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    iv = iv_text_entry.get("1.0", tk.END).strip()
    if not cipher_text or not ((len(cipher_text) % 16) == 0 and all(char in '01' for char in cipher_text)):
        messagebox.showerror("错误", "密文必须是16位倍数的二进制字符串。")
        return
    if not key or not (len(key) == 16 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是16位的二进制字符串。")
        return
    if not iv or not (len(iv) == 16 and all(char in '01' for char in iv)):
        messagebox.showerror("错误", "初始向量必须是16位的二进制字符串。")
        return
    plain_text = cbc_decrypt(cipher_text, int(key, 2), int(iv, 2))
    show_custom_message("解密结果", f"解密得到明文: {plain_text}")


def encrypt_s():
    plain_text = plain_text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    if not key or not (len(key) == 16 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是16位的二进制字符串。")
        return
    cipher_text = encrypt_string(plain_text, int(key, 2))
    show_custom_message("加密结果", f"加密得到密文: {cipher_text}")


def decrypt_s():
    cipher_text = cipher_text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    if not key or not (len(key) == 16 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是16位的二进制字符串。")
        return
    plain_text = decrypt_string(cipher_text, int(key, 2))
    show_custom_message("解密结果", f"解密得到明文: {plain_text}")


def brute_force_crack():
    plain_text = plain_text_entry.get("1.0", tk.END).strip()
    cipher_text = cipher_text_entry.get("1.0", tk.END).strip()
    keys, time = key_crack(plain_text, cipher_text)
    show_custom_message("暴力破解结果", f"破解得到密钥: {keys};\n耗时 {time} 秒")

def show_encrypt_ui():
    clear_ui()
    global plain_text_entry, key_text_entry
    tk.Label(frame, text="请输入明文", font=("Arial", 12)).pack(pady=10)
    plain_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    plain_text_entry.pack(pady=10)
    tk.Label(frame, text="请输入密钥 (16位二进制)", font=("Arial", 12)).pack(pady=10)
    key_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    key_text_entry.pack(pady=10)
    tk.Button(frame, text="二进制加密", command=encrypt_1, height=1, width=10, font=("Arial", 20)).pack(pady=20)
    tk.Button(frame, text="ascii加密", command=encrypt_s, height=1, width=10, font=("Arial", 20)).pack(pady=20)

def show_decrypt_ui():
    clear_ui()
    global cipher_text_entry, key_text_entry
    tk.Label(frame, text="请输入密文", font=("Arial", 12)).pack(pady=10)
    cipher_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    cipher_text_entry.pack(pady=10)
    tk.Label(frame, text="请输入密钥 (16位二进制)", font=("Arial", 12)).pack(pady=10)
    key_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    key_text_entry.pack(pady=10)
    tk.Button(frame, text="二进制解密", command=decrypt_1, height=1, width=10, font=("Arial", 20)).pack(pady=20)
    tk.Button(frame, text="ascii解密", command=decrypt_s, height=1, width=10, font=("Arial", 20)).pack(pady=20)


def show_double_ui():
    clear_ui()
    global text_entry, key_text_entry
    tk.Label(frame, text="请输入密文", font=("Arial", 12)).pack(pady=10)
    text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    text_entry.pack(pady=10)
    tk.Label(frame, text="请输入密钥 (32位二进制)", font=("Arial", 12)).pack(pady=10)
    key_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    key_text_entry.pack(pady=10)
    tk.Button(frame, text="二重加密", command=encrypt_2, height=1, width=10, font=("Arial", 20)).pack(pady=20)
    tk.Button(frame, text="二重解密", command=decrypt_2, height=1, width=10, font=("Arial", 20)).pack(pady=20)


def show_triple_ui():
    clear_ui()
    global text_entry, key_text_entry
    tk.Label(frame, text="请输入密文", font=("Arial", 12)).pack(pady=10)
    text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    text_entry.pack(pady=10)
    tk.Label(frame, text="请输入密钥 (48位二进制)", font=("Arial", 12)).pack(pady=10)
    key_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    key_text_entry.pack(pady=10)
    tk.Button(frame, text="三重加密", command=encrypt_3, height=1, width=10, font=("Arial", 20)).pack(pady=20)
    tk.Button(frame, text="三重解密", command=decrypt_3, height=1, width=10, font=("Arial", 20)).pack(pady=20)


def show_cbc_ui():
    clear_ui()
    global text_entry, key_text_entry, iv_text_entry
    tk.Label(frame, text="请输入密文", font=("Arial", 12)).pack(pady=10)
    text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    text_entry.pack(pady=10)
    tk.Label(frame, text="请输入密钥 (16位二进制)", font=("Arial", 12)).pack(pady=10)
    key_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    key_text_entry.pack(pady=10)
    tk.Label(frame, text="请输入初始向量", font=("Arial", 12)).pack(pady=10)
    iv_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    iv_text_entry.pack(pady=10)
    tk.Button(frame, text="cbc加密", command=encrypt_cbc, height=1, width=10, font=("Arial", 20)).pack(pady=20)
    tk.Button(frame, text="cbc解密", command=decrypt_cbc, height=1, width=10, font=("Arial", 20)).pack(pady=20)


def show_brute_force_ui():
    clear_ui()
    global plain_text_entry, cipher_text_entry
    tk.Label(frame, text="请输入明文", font=("Arial", 12)).pack(pady=10)
    plain_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    plain_text_entry.pack(pady=10)
    tk.Label(frame, text="请输入密文", font=("Arial", 12)).pack(pady=10)
    cipher_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    cipher_text_entry.pack(pady=10)
    tk.Button(frame, text="破解", command=brute_force_crack, height=1, width=10, font=("Arial", 20)).pack(pady=20)

def clear_ui():
    for widget in frame.winfo_children():
        widget.destroy()

# 创建主窗口
root = tk.Tk()
root.title("S-DES 加密解密工具")
root.geometry("600x400")

# 创建左侧菜单
menu_frame = tk.Frame(root)
menu_frame.pack(side=tk.LEFT, fill=tk.Y)

tk.Button(menu_frame, text="加密", command=show_encrypt_ui, height=1, width=10, font=("Arial", 20)).pack(pady=20)
tk.Button(menu_frame, text="解密", command=show_decrypt_ui, height=1, width=10, font=("Arial", 20)).pack(pady=20)
tk.Button(menu_frame, text="二重加密", command=show_double_ui, height=1, width=10, font=("Arial", 20)).pack(pady=20)
tk.Button(menu_frame, text="三重加密", command=show_triple_ui, height=1, width=10, font=("Arial", 20)).pack(pady=20)
tk.Button(menu_frame, text="cbc加密", command=show_cbc_ui, height=1, width=10, font=("Arial", 20)).pack(pady=20)
tk.Button(menu_frame, text="破解", command=show_brute_force_ui, height=1, width=10, font=("Arial", 20)).pack(pady=20)

# 创建主内容区域
frame = tk.Frame(root)
frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# 启动主循环
root.mainloop()
