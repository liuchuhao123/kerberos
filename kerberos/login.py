import tkinter as tk
from tkinter import messagebox
from database import DB
from gui import GUI


class Login:
    def __init__(self):
        self.db = DB()
        self.window = tk.Tk()  # 创建主窗口
        self.window.title('基于kerberos认证登录的学生管理系统')
        self.window.geometry('700x600+400+80')

        tk.Label(self.window, text='用户名:').place(x=210, y=450)
        tk.Label(self.window, text='密   码:').place(x=210, y=500)
        self.entry_user = tk.Entry(self.window)
        self.entry_user.place(x=280, y=450)
        self.entry_pwd = tk.Entry(self.window)
        self.entry_pwd.place(x=280, y=500)
        # 绑定登录和注册的按钮
        tk.Button(self.window, text='登 录', width=10,
                  command=self.login, relief=tk.GROOVE).place(x=230, y=550)
        tk.Button(self.window, text='注 册', width=10,
                  command=self.register, relief=tk.GROOVE).place(x=350, y=550)

        self.flag = False

    def login(self):
        _user = self.entry_user.get()
        _pwd = self.entry_pwd.get()
        users = self.db.login()
        # 验证用户名和密码
        if len(users) > 0:
            for user in users:
                if _user == user[1] and _pwd == user[2]:  # user[0]是序号
                    # 销毁登录界面然后加载主界面
                    self.window.destroy()
                    GUI().start()
                    self.flag = True
                    break

            if not self.flag:
                tk.messagebox.showinfo(message='用户名或密码错误')
        else:
            tk.messagebox.showinfo(message='数据库中用户数为0，请注册')

    def register(self):

        # 向数据库添加用户
        def add_user():
            # 获取输入
            _user = self._entry_username.get()
            _pwd = self._entry_pwd.get()
            confirm_password = self._entry_pwd_confirm.get()
            # 判断输入
            if _user != '' and _pwd != '' and confirm_password != '':
                if _pwd == confirm_password:
                    if self.db.register(username=_user, password=_pwd):
                        tk.messagebox.showinfo(message='注册成功')
                    else:
                        tk.messagebox.showinfo(message='注册失败')
                else:
                    tk.messagebox.showinfo(message='两次输入的密码不一致')
            else:
                tk.messagebox.showinfo(message='请补全信息')

        # 实现注册界面
        self.window_register = tk.Toplevel(self.window)
        self.window_register.geometry('350x200+560+260')
        self.window_register.title('账号注册')
        self._entry_username = tk.Entry(self.window_register)
        self._entry_pwd = tk.Entry(self.window_register, show='*')
        self._entry_pwd_confirm = tk.Entry(self.window_register, show='*')
        tk.Label(self.window_register, text='用户名: ').place(x=80, y=10)
        self._entry_username.place(x=140, y=10)

        tk.Label(self.window_register, text='密 码: ').place(x=85, y=50)
        self._entry_pwd.place(x=140, y=50)
        tk.Label(self.window_register, text='确认密码: ').place(x=70, y=90)
        self._entry_pwd_confirm.place(x=140, y=90)
        # 绑定注册按钮
        self.btn_register = tk.Button(self.window_register, text='注 册',
                                      width=15, command=add_user, relief=tk.GROOVE)
        self.btn_register.place(x=140, y=130)


if __name__ == '__main__':
    login = Login()
    login.window.mainloop()
