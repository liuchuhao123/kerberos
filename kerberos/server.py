import tkinter as tk
import socket
import threading
import ast
import time
import rsa

from des import ArrangeSimpleDES

myrsa = rsa.RSA()

SERVER_IP = '127.0.0.1'
SERVER_PORT = 5007

server_key = '22334455'

mydes = ArrangeSimpleDES()


class Server(threading.Thread):
    def __init__(self, output_text):
        threading.Thread.__init__(self)
        self.output_text = output_text

    def run(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((SERVER_IP, SERVER_PORT))
        server_sock.listen(5)
        self.update_output_text('Server已启动，等待连接...\n')

        while True:
            client_sock, client_address = server_sock.accept()
            self.update_output_text('与客户端连接已建立: ' + str(client_address) + '\n')

            client_v_ciphertext = client_sock.recv(1024).decode()
            self.update_output_text('\n' + 'client发送给server的des加密密文为: ' + str(client_v_ciphertext) + '\n')

            # 把收到的消息转回字典
            client_v_ciphertext = ast.literal_eval(client_v_ciphertext)

            # 对st进行解密并将其取出,然后转成字典
            st = client_v_ciphertext['ST']
            st = mydes.decrypt(str(st), server_key)
            st = ast.literal_eval(st)

            # 核对时间差
            ts_tgs_c = st['ts_tgs_c']
            ts_v_c = time.time()

            # 时间差小于100则可以接受，继续之后的步骤
            if (ts_v_c - ts_tgs_c) < 100:
                # 取出c与V的会话秘钥
                key_c_server = st['key_c_server']

                # 用c与v的会话密钥，解密客户端信息 ,并将客户端信息取出,然后转成字典
                c_v_info = client_v_ciphertext['c_v_info']
                c_v_info = mydes.decrypt(str(c_v_info), key_c_server)
                c_v_info = ast.literal_eval(c_v_info)

                # 将st中的用户信息和客户端自己发送的用户信息进行对比
                if st['c_ip'] == c_v_info['c_ip'] and st['c_name'] == c_v_info['c_name']:
                    # 构建明文
                    client_v_plaintext = f"st:{st},c_v_info:{c_v_info}"
                    self.update_output_text('\n' + '明文为: ' + client_v_plaintext + '\n' + '\n' + '\n' + '\n' + '\n')

                    # 构建v给C的回复信息,一个+1的时间戳（避免消息重放）
                    ts_v_c = mydes.encrypt(str(ts_v_c+1), key_c_server)
                    ts_v_c = ts_v_c.encode()
                    client_sock.send(ts_v_c)

                else:
                    # 终止服务
                    pass

            # 再次调用recv 接受c给v发送的数字签名,并将其转为原数据类型：列表
            c_server_sign_cipher = client_sock.recv(1024).decode()
            c_server_sign_cipher = ast.literal_eval(c_server_sign_cipher)

            # 取出列表中的值
            sign_cipher = c_server_sign_cipher[1]
            myrsa.e = c_server_sign_cipher[2]
            myrsa.n = c_server_sign_cipher[3]

            # 将收到的信息中的明文命名为sign_plain_send
            sign_plain_send = c_server_sign_cipher[0]

            # 将解密的明文命名为sign_plain_recv
            sign_plain_recv = myrsa.decrypt(sign_cipher, myrsa.e)
            if sign_plain_send == sign_plain_recv:
                public_key = (myrsa.n, myrsa.e)
                self.update_output_text('\n' + 'client发送的rsa公钥为: ' + str(public_key) + '\n')
                self.update_output_text('\n' + 'client发送的数字签名密文为: ' + str(sign_cipher) + '\n')
                self.update_output_text('\n' + 'client发送的数字签名明文为: ' + str(sign_plain_send) + '\n')
                self.update_output_text(
                    '\n' + 'server将数字签名密文解密后得到的明文为：: ' + str(sign_plain_recv) + '\n' + '\n\n')
                self.update_output_text('\t\t\t  数字签名认证成功!!!')

            else:

                self.update_output_text('数字签名认证失败')

            client_sock.close()

    def update_output_text(self, text):
        self.output_text.insert(tk.END, text)


def start_server():
    server_thread = Server(output_text)
    server_thread.start()


window = tk.Tk()
window.title("server服务器")
window.geometry("600x400+450+150")

label = tk.Label(window, text="服务器状态:")
label.pack()

output_text = tk.Text(window)
output_text.pack(fill=tk.BOTH, expand=True)

start_button = tk.Button(window, text="启动服务器", command=start_server)
start_button.pack()

window.mainloop()
