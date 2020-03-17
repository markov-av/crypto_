
"""
Задание 1.
Напишите функцию конвертации текста, представленном в шестнацеричном виде, в base64.

Пример:

Входные данные:

49276d207374756479696e672043727970746f677261706879206c696b6520436c6175646520456c776f6f64205368616e6e6f6e21

Выходные данные:

SSdtIHN0dWR5aW5nIENyeXB0b2dyYXBoeSBsaWtlIENsYXVkZSBFbHdvb2QgU2hhbm5vbiE=
"""
import base64

s = '49276d207374756479696e672043727970746f677261706879206c696b6520436c6175646520456c776f6f64205368616e6e6f6e21'


def convert_hex16_to_base64(hex_str: str) -> str:

    def _convert_hex16_to_string(hex_str):
        bytes = []
        hex_str = ''.join(hex_str.split(" "))
        for i in range(0, len(hex_str), 2):
            bytes.append(chr(int(hex_str[i:i + 2], 16)))

        return ''.join(bytes)

    def _convert_str_to_ascii(string):
        return [ord(c) for c in string]

    def _base64_encode(data):
        symbols = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L",
                   "M", "N", "O", "P","Q","R","S","T","U","V","W","X","Y","Z",
                   "a","b","c","d","e","f","g","h","i","j","k","l","m","n","o",
                   "p","q","r","s","t","u","v","w","x","y","z","0","1","2","3",
                   "4","5","6","7","8","9","+","/"]
        bit_str = ""
        base64_str = ""

        for char in data:
            bin_char = bin(char).lstrip("0b")
            bin_char = bin_char.zfill(8)
            bit_str += bin_char

        brackets = [bit_str[x:x + 6] for x in range(0, len(bit_str), 6)]

        for bracket in brackets:
            if (len(bracket) < 6):
                bracket = bracket + (6 - len(bracket)) * "0"
            base64_str += symbols[int(bracket, 2)]

        padding_indicator = len(base64_str) % 4
        if padding_indicator == 3:
            base64_str += "="
        elif padding_indicator == 2:
            base64_str += "=="

        return base64_str

    text = _convert_hex16_to_string(hex_str)
    base64_str = _base64_encode(_convert_str_to_ascii(text))
    assert base64.b64encode(text.encode('ascii')).decode("utf-8") == base64_str
    return base64_str


print("Задание 1.", convert_hex16_to_base64(s))

"""
Напишите функцию, которая принимает в качестве параметров два буфера одинаковой 
длины и производит операцию XOR над ними.

Пример:

Входные данные:

506561636520416c6c204f7665722054686520576f726c64

XOR

4949544353551c0111001f010100061a021f010100061a02

=

192C352036755D6D7D2050776472264E6A7A21566F747666
"""

s1 = "506561636520416c6c204f7665722054686520576f726c64"
s2 = "4949544353551c0111001f010100061a021f010100061a02"


def xor_two_str(a, b):
    return ''.join([hex(ord(a[i % len(a)]) ^ ord(b[i % (len(b))]))[2:]
                    for i in range(max(len(a), len(b)))])


print("Задание 2.", xor_two_str(s1, s2))
"""
Задание 3.

(не использовать метод полного перебора ключа)

Дана строка закодированная в 16-виде. Данную строку получили путем операции XOR
 некоторого текста с одним символом. Расшифруйте это сообщение. 

Пример:

Входные данные:

19367831362e3d2b2c353d362c783136783336372f343d3c3f3d7839342f39212b782839212b782c303d783a3d2b2c7831362c3d2a3d2b2c

Стадии выполнения задания:

1: выполните задание без программной автоматизации - "на листочке".
2: напишите программу дешифратор.

"""

s = "19367831362e3d2b2c353d362c783136783336372f343d3c3f3d7839342f39212b782839212b782c303d783a3d2b2c7831362c3d2a3d2b2c"


import collections
from itertools import cycle


def _convert_hex16_to_string(hex_str):
    bytes = []
    for i in range(0, len(hex_str), 2):
        bytes.append(chr(int(hex_str[i:i + 2], 16)))

    return bytes


message = _convert_hex16_to_string(s)
# print(collections.Counter(message))
# print([s[i:i + 2] for i in range(0, len(s), 2)])
cryptedMessage = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(message, cycle('x')))
print("Задание 3.", cryptedMessage)


"""
Задание 4.
В качестве входных данных дается файл со строками в hex. Одна из этих строк 
зашифрована с помощью XOR на одно-символьном ключе. Найдите и расшифруйте эту 
https://drive.google.com/open?id=0B9jRznVc1EjLT2sxR1BJUldJVk0.
"""

with open('task14.input') as f:
    content = f.readlines()
contents = [x.strip() for x in content]


def decrypt_with_key_selection(s):
    messages = []
    message = _convert_hex16_to_string(s)
    keys_count = collections.Counter(message)
    # print(keys_count)
    for key, _ in keys_count.most_common(1):
        # print(key)
        cryptedMessage = ''.join(chr(ord(c) ^ ord(k)) for c, k in
                                 zip(message, cycle(key)))
        # print(cryptedMessage)
        # print(cryptedMessage.index("\\"))
        # print(cryptedMessage.count("\x00"))
        if cryptedMessage.count("\x00") >= 4:
            # if "\\" not in r"%r" % cryptedMessage:
            messages.append(cryptedMessage)
    return messages


# d = 100000
# #
# for num, s in enumerate(contents):
#     if decrypt_with_key_selection(s):
#         print(num, decrypt_with_key_selection(s))
# 191 ['B;Ä²\x8d\x8e\x13\x85¡æï\x15\x8e\x14\x00\x00\\\x00\x1al]Ó\x1aR\x00%r\x9fãK']
# 373 ['kAKIM\x00UMNYM\x00JA\x00SEBJA\x00CHUVSTVUU']

# 374
s = "2a000a080c41140c0f180c410b00411204030b0041020914171215171414"
print("Задание 4.", decrypt_with_key_selection(s))


"""
Задание 5.
Реализуйте шифрование XOR'ом с повторяющимся ключом.
Входные данные: https://drive.google.com/open?id=0B9jRznVc1EjLTHh2M2NXaERCbU0
"""

key = 'Shannon'
expected_result = "00000000000000730b0e001a1d07311d150b0a4f1a3c4815060b4f083a0d0d0a4e0008730b13171e1b0f3d090d171d061d730e0e1c4e010f27010e000f034e370d070b001c0b730c141c070109733f0e1c020b4e0409134e272642736208000d031b37010f094e07072048030f1d060d731f0e1c054f013d4802010a0a0c210d000507010973090f0a4e1c0b301d130b4e1b0b3f0d020103021b3d01020f1a06013d1b4f"
with open('task15.input') as f:
    content = f.read()[:-1]


def to_xor_by_key(message, key):
    cryptedMessage = ''.join(chr(ord(c) ^ ord(k)) for c, k in
                             zip(message, cycle(key)))
    return cryptedMessage


cod = to_xor_by_key(content, key)
assert bytes.hex(cod.encode()) == expected_result
print("Задание 5.", bytes.hex(cod.encode()))


"""
Задание 6.
Задание: Расшифруйте данные зашифрованные XOR'ом с повторяющимся ключом.
Входные данные: https://drive.google.com/open?id=0B9jRznVc1EjLRTRPSUFKQUUzRFk
"""

with open('task16.input') as f:
    coded_data = f.read()

coded_data = base64.decodebytes(coded_data.encode()).decode()


def str_rshift(str, n):
    n = n % len(str)
    n = len(str) - n
    return str[n:] + str[:n]


def calc_match(input1, input2):
    matches = 0
    for idx in range(len(input1)):
        if input1[idx] == input2[idx]:
            matches += 1
    return (100.0 * matches) / len(input1)


def detect_key_len(coded_text):
    decoded = []
    # print(len(coded_data) / 2 )
    for key_len in range(1, int(len(coded_data) / 2) + 1):
        shifted_text = str_rshift(coded_data, key_len)
        info = {
            'len': key_len,
            'match': calc_match(coded_data, shifted_text),
            'shifted': shifted_text
        }
        decoded += [info]

    key_info = sorted(decoded, key=lambda item: item['match'], reverse=True)[0]
    return key_info['len']


def expand_key(key, length):
    return (key * int((length/len(key) + 1)))[:length]


def str_xor(input, key):
    output = ''
    key = expand_key(key, len(input))
    for i in range(len(input)):
        output += chr(ord(input[i]) ^ ord(key[i]))
    return output


def detect_possible_key(coded_text, key_len):
    # split text into groups based on founded key len and xor with ' ' (space)
    groups = [coded_data[i:i + key_len] for i in range(0, len(coded_data), key_len)]

    possible_key = ''
    for i in range(key_len):
        freq = {}
        scaned_chars = 0
        for item in groups:
            # check if text part not less that current index
            if i < len(item):
                char = str_xor(item[i], ' ')
                if char in freq:
                    freq[char] += 1
                else:
                    freq[char] = 1
                scaned_chars += 1

        freq = {k: float(v) / scaned_chars for k, v in freq.items()}
        key_char = sorted(freq.items(), key=lambda item: item[1], reverse=True)[0]
        possible_key += key_char[0]
    return possible_key


import re


def find_key(string):
    r = re.compile(r"(.+?)\1+")
    return min(r.findall(string) or [""], key=len)


key_len = detect_key_len(coded_data)
possible_key = detect_possible_key(coded_data, key_len)
# print(str_xor(coded_data, possible_key))
print("Задание 6.", possible_key)
# Ответ: Ro'er5 Laurenc* Bi+*<n

