from random import randrange
import math


def prime(n):
    # 判断一个数是不是素数

    mid = math.sqrt(n)
    mid = math.floor(mid)
    for item in range(2, mid):
        if n % item == 0:
            return False
    return True


def generate_n_bit_odd(n: int):
    # 生成大数,不确定是不是素数

    assert n > 1
    return randrange(2 ** (n - 1) + 1, 2 ** n, 2)


first_50_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
                   37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
                   79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
                   131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
                   181, 191, 193, 197, 199, 211, 223, 227, 229, 233]


def get_lowlevel_prime(n):
    # 选择满足不能够整除前50个素数的大数，没找到就一直循环

    while True:
        c = generate_n_bit_odd(n)
        for divisor in first_50_primes:
            if c % divisor == 0 and divisor ** 2 <= c:
                break
        return c


def miller_rabin_primality_check(n, k=20):
    # 由于假设n是一个素数，n-1=a^s*d,s和d是常量，改变a的值，检测20次

    assert n > 3
    if n % 2 == 0:
        return False
    # 找出n-1 = 2^s*d
    s, d = 0, n - 1
    while d % 2 == 0:
        d >>= 1
        s += 1

    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def get_random_prime(num_bits):
    # 获取大素数

    while True:
        pp = get_lowlevel_prime(num_bits)
        if miller_rabin_primality_check(pp):
            return pp


def gcd(a, b):
    # 求最大公约数

    while b:
        a, b = b, a % b
    return a


def lcm(a, b):
    # 求最大公倍数

    # divisor = gcd(a, b)
    # multiple = (a * b) / divisor
    # return multiple
    return a // gcd(a, b) * b


def exgcd(a, b):
    old_s, s = 1, 0
    old_t, t = 0, 1
    while b:
        q = a // b
        s, old_s = old_s - q * s, s
        t, old_t = old_t - q * t, t
        a, b = b, a % b
    return a, old_s, old_t


def invmod(e, m):
    """
    求模逆元：知道x * e + y * m = g
    :param e:
    :param m:
    :return:
    """
    g, d, y = exgcd(e, m)
    assert g == 1
    if d < 0:
        d += m
    return d


def uint_from_bytes(xbytes: bytes) -> int:
    """
    比特转换位整数
    :param xbytes:
    :return:
    """
    return int.from_bytes(xbytes, 'big')


def uint_to_bytes(x: int) -> bytes:
    """
    整数转换成比特的时候，一个整数对应32位比特数
    :param x:
    :return:
    """
    if x == 0:
        return bytes(1)
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')  # 做到尽量不补零


RSA_DEFAULT_EXPONENT = 65537
RSA_DEFAULT_MODULUS_LEN = 2048


class RSA:
    """
    RSA算法(self.n, self.e)加密密钥
    (self.n, self.d)解密密钥
    """

    def __init__(self, key_length=RSA_DEFAULT_MODULUS_LEN,
                 exponent=RSA_DEFAULT_EXPONENT):
        self.e = exponent
        t = 0
        p = q = 2
        # 找出一个e使1<e<(p-1)*(q-1)
        while gcd(self.e, t) != 1:
            p = get_random_prime(key_length // 2)
            q = get_random_prime(key_length // 2)
            t = lcm(p - 1, q - 1)

        self.n = p * q
        self.d = invmod(self.e, t)

    # 加密和解密使比特和整数之间的加解密

    def encrypt(self, binary_data: bytes, private_key):
        int_data = uint_from_bytes(binary_data)
        return pow(int_data, private_key, self.n)

    def decrypt(self, encrypted_int_data: int, public_key):
        int_data = pow(encrypted_int_data, public_key, self.n)
        return uint_to_bytes(int_data)


if __name__ == '__main__':
    # rsa = RSA(256,3)  # 实例化RSA对象
    #
    # plaintext = b'liuchuhao'  # 原始数据
    #
    # # 使用私钥加密
    # encrypted_data = rsa.encrypt(plaintext, rsa.d)
    # print(type(encrypted_data))
    # # 使用公钥解密
    # decrypted_data = rsa.decrypt(encrypted_data, rsa.e)
    # print(decrypted_data)
    # # 验证是否恢复原始数据

    rsa = RSA(256, 3)  # 实例化RSA对象
    private_key = rsa.d  # 获取私钥
    public_key = rsa.e  # 获取公钥
    mydict = [1, 2, 3, 4]
    print(rsa.n)
    text = str(mydict).encode()
    cipher = rsa.encrypt(text, private_key)
    print(type(cipher))
    plain = rsa.decrypt(cipher, public_key)
    print(cipher)
    print(plain)
