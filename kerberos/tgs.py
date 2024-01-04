import tkinter as tk
import socket
import threading
import ast
import time

from des import ArrangeSimpleDES

able_service = {'login', 'register', 'add', 'delete', 'search'}
client_key = '12345678'
TGS_KEY = '23456789'
SERVER_KEY = '22334455'
KEY_C_SERVER = '11223344'

TGS_IP = '127.0.0.1'
TGS_PORT = 5001

SERVER_IP = '127.0.0.1'
SERVER_PORT = 5007

mydes = ArrangeSimpleDES()


class TGS(threading.Thread):
    def __init__(self, output_text):
        threading.Thread.__init__(self)
        self.output_text = output_text

    def run(self):
        tgs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tgs_socket.bind((TGS_IP, TGS_PORT))
        tgs_socket.listen(5)
        self.update_output_text('TGS服务器已启动，等待连接...\n')

        while True:
            client_sock, client_address = tgs_socket.accept()
            self.update_output_text('与客户端连接已建立: ' + str(client_address) + '\n')

            # 接受客户端的请求信息,并转回字典
            client_request = client_sock.recv(1024).decode()
            self.update_output_text('\n' + 'client发送给TGS的des加密密文为: ' + str(client_request) + '\n')
            client_request = ast.literal_eval(client_request)

            # 取出client想获得的服务，然后与服务列表对照
            service_request = client_request['service']

            if (service_request & able_service) == service_request:

                # 解密TGT并转回字典
                tgt = client_request['TGT']
                tgt = mydes.decrypt(tgt, TGS_KEY)
                tgt = ast.literal_eval(tgt)

                # 比较两个时间戳，得出时延
                ts_tgs_c = time.time()
                ts_as_c = tgt['ts_as_c']

                if (ts_tgs_c - ts_as_c) < 100:

                    # 取得会话密钥
                    key_c_tgs = tgt['KEY_C_TGS']

                    # 获取用户自己发送的用户信息并转回字典
                    c_info = client_request['c_info']
                    c_info = mydes.decrypt(c_info, key_c_tgs)
                    c_info = ast.literal_eval(c_info)

                    # 对tgt中的用户信息和用户自己发送的用户信息比对
                    if tgt['c_ip'] == c_info['c_ip'] and tgt['c_name'] == c_info['c_name']:

                        # 构建明文
                        client_tgs_plaintext = f"TGT:{tgt},service:{service_request},c_info:{c_info}"
                        self.update_output_text(
                            '\n' + '明文为: ' + client_tgs_plaintext + '\n' + '\n' + '\n' + '\n' + '\n')

                        # 构建ST（服务票据）
                        lt_st = 666  # 设置ST的有效时间为666秒

                        ST = {
                            'c_ip': tgt['c_ip'],
                            'c_name': tgt['c_name'],
                            'server_ip': SERVER_IP,
                            'lt_st': lt_st,
                            'ts_tgs_c': ts_tgs_c,
                            'key_c_server': KEY_C_SERVER
                        }

                        # 对ST加密
                        ST = mydes.encrypt(str(ST), SERVER_KEY)

                        tgs_c = {
                            'ST': ST,
                            'lt_st': lt_st,
                            'ts_tgs_c': ts_tgs_c,
                            'key_c_server': KEY_C_SERVER,
                            'server_ip': SERVER_IP,
                            'server_port': SERVER_PORT
                        }

                        tgs_c = mydes.encrypt(str(tgs_c), key_c_tgs)
                        tgs_c = tgs_c.encode()
                        client_sock.send(tgs_c)

                    else:
                        # 终止服务，信息不对，该客户端可能是攻击者
                        pass
                else:
                    # 终止服务，时延过大
                    pass
            else:
                # 终止服务，客户端想获得的服务并不全在服务列表中
                pass

            client_sock.close()

    def update_output_text(self, text):
        self.output_text.insert(tk.END, text)


if __name__ == '__main__':
    window = tk.Tk()
    window.title("TGS服务器")
    window.geometry("600x400+450+150")

    label = tk.Label(window, text="TGS服务器状态:")
    label.pack()

    output_text = tk.Text(window)
    output_text.pack(fill=tk.BOTH, expand=True)

    # 实例化一个TGS对象
    tgs_thread = TGS(output_text)

    start_button = tk.Button(window, text="启动TGS服务器", command=tgs_thread.start())
    start_button.pack()

    window.mainloop()
