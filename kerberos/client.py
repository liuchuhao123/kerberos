import socket
import login
import ast
import time
from des import ArrangeSimpleDES
import rsa
import tkinter as tk

CLIENT_IP = '127.0.0.1'
CLIENT_NAME = "liuchuhao"
CLIENT_KEY = '12345678'

AS_IP = '127.0.0.1'
AS_PORT = 5000

mydes = ArrangeSimpleDES()  # 创建一个des加密算法的对象，以调用加密和解密的方法
myrsa = rsa.RSA(256, 5)


class Client:
    def __init__(self):
        self.v_c_plaintext = None
        self.v_c_ciphertext = None
        self.tgs_c_plaintext = None
        self.tgs_c_ciphertext = None
        self.key_c_tgs = None
        self.tgt = None
        self.as_c_plaintext = None
        self.as_c_ciphertext = None
        self.tgs_ip = None
        self.tgs_port = None
        self.server_ip = None
        self.server_port = None
        self.c_server = None
        self.key_c_server = None

    def run(self):
        self.connect_as()
        self.connect_tgs()
        return self.connect_server()

    def connect_as(self):
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect((AS_IP, AS_PORT))

        ts_c_as = time.time()

        C_AS = {
            'c_name': CLIENT_NAME,
            'c_ip': CLIENT_IP,
            'ts_c_as': ts_c_as
        }
        # c给as发送请求消息
        c_as = mydes.encrypt(str(C_AS), CLIENT_KEY)
        c_as = c_as.encode()
        client_sock.send(c_as)
        # 接受AS的回应
        self.as_c_ciphertext = client_sock.recv(1024).decode()
        raw_as_c_plaintext = mydes.decrypt(self.as_c_ciphertext, CLIENT_KEY)
        self.as_c_plaintext: dict = ast.literal_eval(raw_as_c_plaintext)  # 最终可使用的明文

        tgs_ip = self.as_c_plaintext['tgs_ip']
        tgs_port = self.as_c_plaintext['tgs_port']

        self.tgt = self.as_c_plaintext['TGT']
        self.key_c_tgs = self.as_c_plaintext['KEY_C_TGS']

        ts_as_c = self.as_c_plaintext['ts_as_c']
        # 判断时延是否正常，定义可接受的时延小于100秒
        if ts_as_c - ts_c_as < 100:
            self.tgs_ip = tgs_ip
            self.tgs_port = tgs_port
        else:
            # 时延过大，身份可能不正确
            pass

        client_sock.close()

    def connect_tgs(self):

        tgs_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tgs_sock.connect((self.tgs_ip, self.tgs_port))

        ts_c_tgs = time.time()
        # 构建C_TGS
        c_info = {
            'c_name': CLIENT_NAME,
            'c_ip': CLIENT_IP,
            'ts_c_tgs': ts_c_tgs,
        }
        c_info = mydes.encrypt(str(c_info), self.key_c_tgs)

        C_TGS = {
            'TGT': self.tgt,
            'service': {'login', 'register', 'add', 'delete', 'search'},
            'c_info': c_info
        }

        # 给tgs发送请求信息
        C_TGS = str(C_TGS).encode()
        tgs_sock.send(C_TGS)

        # 接受TGS回复的信息,然后解密并转回字典
        self.tgs_c_ciphertext = tgs_sock.recv(1024).decode()
        raw_tgs_c_plaintext = mydes.decrypt(self.tgs_c_ciphertext, self.key_c_tgs)
        self.tgs_c_plaintext = ast.literal_eval(raw_tgs_c_plaintext)

        # 取出server的ip和端口号
        self.server_ip = self.tgs_c_plaintext['server_ip']
        self.server_port = self.tgs_c_plaintext['server_port']

        # 取出tgs发包时的时间戳并与当前时间戳对比
        ts_tgs_c = self.tgs_c_plaintext['ts_tgs_c']
        ts_c_server = time.time()

        if (ts_c_server - ts_tgs_c) < 100:
            # 取出c与v的会话秘钥和ST
            self.key_c_server = self.tgs_c_plaintext['key_c_server']
            st = self.tgs_c_plaintext['ST']
            #
            c_v_info = {
                'c_name': CLIENT_NAME,
                'c_ip': CLIENT_IP,
                'ts_c_server': ts_c_server
            }

            # 用c与v的会话秘钥 加密client的信息
            c_v_info = mydes.encrypt(str(c_v_info), self.key_c_server)

            c_server = {
                'c_v_info': c_v_info,
                'ST': st
            }
            self.c_server = str(c_server).encode()

        tgs_sock.close()

    def connect_server(self):

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((self.server_ip, self.server_port))

        # 给server发送消息,包括服务票据和客户端信息
        server_sock.send(self.c_server)

        # 接受V的回复消息然后解密并转成原类型
        self.v_c_ciphertext = server_sock.recv(1024).decode()
        raw_v_c_plaintext = mydes.decrypt(self.v_c_ciphertext, self.key_c_server)
        self.v_c_plaintext = ast.literal_eval(raw_v_c_plaintext)

        # 获取当前时间戳，然后作差判断时延
        now_time = time.time()
        if (now_time - self.v_c_plaintext) < 100:

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


class MyLogin(login.Login, Client):

    def __init__(self):
        login.Login.__init__(self)
        Client.__init__(self)
        self.flag = self.run()
        tk.Label(self.window, text='已通过KDC的认证，成功与server建立连接！', fg='red').pack()

        self.output_text = tk.Text(self.window, width=95, height=30)
        self.output_text.pack()

        self.output_text.insert(tk.END, "AS端发送的des密文为：" + str(self.as_c_ciphertext) + '\n' + '\n')
        self.output_text.insert(tk.END, "解密后的明文为：" + str(self.as_c_plaintext) + '\n' + '\n' + '\n' + '\n')

        self.output_text.insert(tk.END, "TGS端发送的des密文为：" + str(self.tgs_c_ciphertext) + '\n' + '\n')
        self.output_text.insert(tk.END, "解密后的明文为：" + str(self.tgs_c_plaintext) + '\n' + '\n' + '\n' + '\n')

        self.output_text.insert(tk.END, "server端发送的des密文为：" + str(self.v_c_ciphertext) + '\n' + '\n')
        self.output_text.insert(tk.END, "解密后的明文为：" + str(self.v_c_plaintext) + '\n' + '\n' + '\n')


if __name__ == '__main__':

    mylogin = MyLogin()
    if mylogin.flag:
        mylogin.window.mainloop()
