## Схема злому:

1. відправляємо три блоки по 16 байтів до прикладу символом "а"

```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 
```

2. отримуємо зашифрований текст

```
a85d30f8fcb12a42749d3d3cdead53d7f0c0f70a76c5270b30b1f97a57de92fad0a272bf2d212257bef33c0fdbdeb327
```

3. змінюємо у ньому другий і третій блок, тобто по 16 байтів і вказуємо у другому блоці 32 нулі, а у третій  ідентичний першому

```
a85d30f8fcb12a42749d3d3cdead53d700000000000000000000000000000000a85d30f8fcb12a42749d3d3cdead53d7
```

4. декодуємо це і отримуємо 

```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa461cb3c94e389b30efcff80a633f33da066cda004317a57bcfa284583d19e2e8
```

5. у даному випадку ми отримали `acc670aae9bd0fd165082ef297b34842` (bytes.fromhex із [xor_p0_p2.py](https://github.com/Zavada-Nazarii/Cryptography-course/blob/master/lesson-4/Task%201/xor_p0_p2.py) що є ключем для отримання прапора.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Прапор crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?}
