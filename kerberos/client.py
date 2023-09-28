import socket
import login
import ast
import time
from des import ArrangeSimpleDES
import rsa
import tkinter as tk

CLIENT_IP = '127.0.0.1'
c_name = "liuchuhao"

AS_IP = '127.0.0.1'
AS_PORT = 5000

client_key = '12345678'

mydes = ArrangeSimpleDES()  # 创建一个des加密算法的对象，以调用加密和解密的方法

myrsa = rsa.RSA(256, 5)


def connect_as():
    as_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    as_sock.connect((AS_IP, AS_PORT))

    ts_c_as = time.time()

    C_AS = {
        'c_name': c_name,
        'c_ip': CLIENT_IP,
        'ts_c_as': ts_c_as
    }
    # c给as发送请求消息
    c_as = mydes.encrypt(str(C_AS), client_key)
    c_as = c_as.encode()
    as_sock.send(c_as)
    # 接受AS的回应
    global as_c_ciphertext, as_c_plaintext  # 设为全局变量

    as_c_ciphertext = as_sock.recv(1024).decode()
    as_c_plaintext = mydes.decrypt(str(as_c_ciphertext), client_key)
    as_c_plaintext = ast.literal_eval(as_c_plaintext)  # 最终可使用的明文

    tgs_ip = as_c_plaintext['tgs_ip']
    tgs_port = as_c_plaintext['tgs_port']

    global tgt
    tgt = as_c_plaintext['TGT']

    global key_c_tgs
    key_c_tgs = as_c_plaintext['KEY_C_TGS']

    ts_as_c = as_c_plaintext['ts_as_c']
    # 判断时延是否正常，定义可接受的时延小于100秒
    if ts_as_c - ts_c_as < 100:
        return tgs_ip, tgs_port
    else:
        # 时延过大，身份可能不正确
        pass

    as_sock.close()


def connect_tgs():
    tgs_ip, tgs_port = connect_as()
    tgs_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tgs_sock.connect((tgs_ip, tgs_port))

    ts_c_tgs = time.time()
    # 构建C_TGS
    c_info = {
        'c_name': c_name,
        'c_ip': CLIENT_IP,
        'ts_c_tgs': ts_c_tgs,
    }
    c_info = mydes.encrypt(str(c_info), key_c_tgs)

    C_TGS = {
        'TGT': tgt,
        'service': {'login', 'register', 'add', 'delete', 'search'},
        'c_info': c_info
    }

    # 给tgs发送请求信息
    C_TGS = str(C_TGS).encode()
    tgs_sock.send(C_TGS)

    # 接受TGS回复的信息,然后解密并转回字典
    global tgs_c_ciphertext, tgs_c_plaintext
    tgs_c_ciphertext = tgs_sock.recv(1024).decode()
    tgs_c_plaintext = mydes.decrypt(tgs_c_ciphertext, key_c_tgs)
    tgs_c_plaintext = ast.literal_eval(tgs_c_plaintext)

    # 取出server的ip和端口号
    server_ip = tgs_c_plaintext['server_ip']
    server_port = tgs_c_plaintext['server_port']

    # 取出tgs发包时的时间戳并与当前时间戳对比
    ts_tgs_c = tgs_c_plaintext['ts_tgs_c']
    ts_c_server = time.time()

    if (ts_c_server - ts_tgs_c) < 100:
        # 取出c与v的会话秘钥和ST
        key_c_server = tgs_c_plaintext['key_c_server']
        st = tgs_c_plaintext['ST']
        #
        c_v_info = {
            'c_name': c_name,
            'c_ip': CLIENT_IP,
            'ts_c_server': ts_c_server
        }

        # 用c与v的会话秘钥 加密client的信息
        c_v_info = mydes.encrypt(str(c_v_info), key_c_server)

        c_server = {
            'c_v_info': c_v_info,
            'ST': st
        }
        c_server = str(c_server).encode()

    tgs_sock.close()
    return server_ip, server_port, c_server, key_c_server


def connect_server():
    server_ip, server_port, c_server, key_c_server = connect_tgs()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((server_ip, server_port))

    # 给server发送消息,包括服务票据和客户端信息
    server_sock.send(c_server)

    # 接受V的回复消息然后解密并转成原类型
    global v_c_ciphertext, v_c_plaintext
    v_c_ciphertext = server_sock.recv(1024).decode()
    v_c_plaintext = mydes.decrypt(v_c_ciphertext, key_c_server)
    v_c_plaintext = ast.literal_eval(v_c_plaintext)

    # 获取当前时间戳，然后作差判断时延
    now_time = time.time()
    if (now_time - v_c_plaintext) < 100:

        # 给server发送数字签名和公钥
        sign_plain = b'20230601'
        sign_cipher = myrsa.encrypt(sign_plain, myrsa.d)

        c_server_sign = [sign_plain, sign_cipher, myrsa.e, myrsa.n]

        # 将c_server_sign转成字符串然后再encode
        c_server_sign = str(c_server_sign).encode()
        server_sock.send(c_server_sign)

        server_sock.close()
        return True

    else:
        # 时延过大，可能遭受攻击
        pass

    server_sock.close()


class mylogin(login.Login):

    def __init__(self):
        login.Login.__init__(self)
        tk.Label(self.window, text='已通过KDC的认证，成功与server建立连接！', fg='red').pack()

        self.output_text = tk.Text(self.window, width=95, height=30)
        self.output_text.pack()

        self.output_text.insert(tk.END, "AS端发送的des密文为：" + str(as_c_ciphertext) + '\n' + '\n')
        self.output_text.insert(tk.END, "解密后的明文为：" + str(as_c_plaintext) + '\n' + '\n' + '\n' + '\n')

        self.output_text.insert(tk.END, "TGS端发送的des密文为：" + str(tgs_c_ciphertext) + '\n' + '\n')
        self.output_text.insert(tk.END, "解密后的明文为：" + str(tgs_c_plaintext) + '\n' + '\n' + '\n' + '\n')

        self.output_text.insert(tk.END, "server端发送的des密文为：" + str(v_c_ciphertext) + '\n' + '\n')
        self.output_text.insert(tk.END, "解密后的明文为：" + str(v_c_plaintext) + '\n' + '\n' + '\n')


if __name__ == '__main__':
    # 设一个布尔类型的值，当服务端验证签名成功后 则提供服务
    connect_flag = connect_server()

    if connect_flag:
        mlogin = mylogin()

        mlogin.window.mainloop()
