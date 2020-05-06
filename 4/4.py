import collections
from itertools import cycle


"""
Задание 4.
В качестве входных данных дается файл со строками в hex. Одна из этих строк 
зашифрована с помощью XOR на одно-символьном ключе. Найдите и расшифруйте эту 
https://drive.google.com/open?id=0B9jRznVc1EjLT2sxR1BJUldJVk0.
"""
def _convert_hex16_to_string(hex_str):
    bytes = []
    for i in range(0, len(hex_str), 2):
        bytes.append(chr(int(hex_str[i:i + 2], 16)))

    return bytes

with open('task142.input') as f:
    content = f.readlines()
contents = [x.strip() for x in content]


def decrypt_with_key_selection(s):
    messages = []
    message = _convert_hex16_to_string(s)
    keys_count = collections.Counter(message)
    for key, _ in keys_count.most_common(1):
        cryptedMessage = ''.join(chr(ord(c) ^ ord(k)) for c, k in
                                 zip(message, cycle(key)))
        if cryptedMessage.count("\x00") >= 4:
            messages.append(cryptedMessage)
    return messages


for num, s in enumerate(contents):
    if decrypt_with_key_selection(s):
        print(num, decrypt_with_key_selection(s))

"""
task140.input -> 373 ['kAKIM\x00UMNYM\x00JA\x00SEBJA\x00CHUVSTVUU']
task141.input -> 170 ['nOW\x00THAT\x00THE\x00PARTY\x00IS\x00JUMPING*']
task142.input -> 501 ['NDON\x0c\x00cAPITAL\x00OF\x00gREAT\x00bRITAIN']
"""
