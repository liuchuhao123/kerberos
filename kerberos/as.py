import tkinter as tk
import socket
import threading
import ast
import time
from database import DB
from des import ArrangeSimpleDES

client_key = '12345678'
tgs_key = '23456789'
key_c_tgs = b'66666666'

AS_IP = '127.0.0.1'
AS_PORT = 5000

TGS_IP = '127.0.0.1'
TGS_PORT = 5001

mydes = ArrangeSimpleDES()

db = DB()
db.cursor.execute("select username from user")
username_list = db.cursor.fetchall()
username_list = [username_list[0][0],username_list[1][0]]


class AS(threading.Thread):
    def __init__(self, output_text):
        threading.Thread.__init__(self)
        self.output_text = output_text

    def run(self):
        as_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        as_sock.bind((AS_IP, AS_PORT))
        as_sock.listen(5)
        self.update_output_text('AS服务器已启动，等待连接...\n')

        while True:
            client_sock, client_address = as_sock.accept()
            self.update_output_text('与客户端连接已建立: ' + str(client_address) + '\n')

            client_request = client_sock.recv(1024).decode()
            self.update_output_text('\n' + 'client发送给AS的des加密密文为: ' + str(client_request) + '\n')
            # 将收到的消息解密，然后转回字典
            client_request = mydes.decrypt(client_request, client_key)
            client_request = ast.literal_eval(client_request)

            self.update_output_text('\n' + '明文为: ' + str(client_request) + '\n')

            ts_as_c = time.time()
            lt_TGT = 666

            if client_request.get('c_name') in username_list:
                self.update_output_text(
                    '\n' + '该客户端用户名存在于AD数据库中,身份验证成功！' + '\n' + '\n' + '\n' + '\n' + '\n' + '\n')

                TGT = {
                    'KEY_C_TGS': key_c_tgs,
                    'c_ip': client_request['c_ip'],
                    'c_name': client_request['c_name'],
                    'tgs_ip': TGS_IP,
                    'tgs_port': TGS_PORT,
                    'ts_as_c': ts_as_c,
                    'lt_TGT': lt_TGT
                }

                TGT = mydes.encrypt(str(TGT), tgs_key)
                AS_C = {
                    'KEY_C_TGS': key_c_tgs,
                    'tgs_ip': TGS_IP,
                    'TGT': TGT,
                    'tgs_port': TGS_PORT,
                    'ts_as_c': ts_as_c,
                    'lt_TGT': lt_TGT
                }
                AS_C = mydes.encrypt(str(AS_C), client_key)
                AS_C = AS_C.encode()
                client_sock.send(AS_C)
            else:
                self.update_output_text('\n' + '该客户端用户名不存在于AD数据库中,身份验证失败！' + '\n' + '\n')

            client_sock.close()

    def update_output_text(self, text):
        self.output_text.insert(tk.END, text)


def start_as_server():
    as_thread = AS(output_text)
    as_thread.start()


window = tk.Tk()
window.title("AS服务器")
window.geometry("600x400+450+150")

label = tk.Label(window, text="AS服务器状态:")
label.pack()

output_text = tk.Text(window)
output_text.pack(fill=tk.BOTH, expand=True)

start_button = tk.Button(window, text="启动AS服务器", command=start_as_server)
start_button.pack()

window.mainloop()
