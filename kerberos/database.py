import pymysql as mysql

host = 'localhost'
port = 3306
user = "root"
password = "lch667997"
db_name = "student"


class DB:
    def __init__(self):
        self.conn = mysql.connect(host=host, port=port, user=user, password=password, database=db_name)
        self.cursor = self.conn.cursor()

        self._select = 'SELECT * FROM info;'
        self._insert = 'INSERT INTO info(sno, name, sex, college, clazz) VALUES(%s, %s, %s, %s, %s);'
        self._delete = 'DELETE FROM info WHERE sno=%s;'
        self._update = 'UPDATE info SET name=%s, sex=%s, college=%s, clazz=%s WHERE sno=%s;'
        self._search = 'SELECT * FROM info WHERE sno LIKE %s OR name LIKE %s OR sex LIKE %s' \
                       'OR college LIKE %s OR clazz LIKE %s;'
        self._login = 'SELECT * FROM user;'
        self._register = 'INSERT INTO user(username, password) VALUES(%s, %s);'

    # 添加信息
    def insert(self, **kwargs):
        param = [kwargs['sno'], kwargs['name'], kwargs['sex'], kwargs['college'], kwargs['clazz']]
        self.cursor.execute(self._insert, param)
        self.conn.commit()
        return True

    # 查找全部信息
    def select(self):
        self.cursor.execute(self._select)
        result = self.cursor.fetchall()
        return result

    # 按学号删除信息
    def delete(self, sno):
        self.cursor.execute(self._delete, [sno])
        self.conn.commit()
        effect_row = self.cursor.rowcount
        if effect_row > 0:
            return True

    # 按学号修改信息
    def update(self, **kwargs):
        param = [kwargs['name'], kwargs['sex'], kwargs['college'], kwargs['clazz'], kwargs['sno']]
        self.cursor.execute(self._update, param)
        self.conn.commit()
        return True

    # 按关键词查找信息
    def search(self, key):
        param = ['%' + str(key) + '%' for i in range(5)]  # 模糊匹配
        self.cursor.execute(self._search, param)
        result = self.cursor.fetchall()
        return result

    def login(self):
        self.cursor.execute(self._login)
        result = self.cursor.fetchall()
        return result

    def register(self, **kwargs):
        param = [kwargs['username'], kwargs['password']]
        self.cursor.execute(self._register, param)
        self.conn.commit()
        return True



