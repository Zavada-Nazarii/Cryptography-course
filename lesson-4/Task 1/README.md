''Схема злому:''

1. відправляємо три блоки по 16 байтів до прикладу символом "а"
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 
2. отримуємо зашифрований текст
a85d30f8fcb12a42749d3d3cdead53d7f0c0f70a76c5270b30b1f97a57de92fad0a272bf2d212257bef33c0fdbdeb327
3. змінюємо у ньому другий і третій блок, тобто по 16 байтів і вказуємо у другому блоці 32 нулі, а у третій  ідентичний першому
a85d30f8fcb12a42749d3d3cdead53d700000000000000000000000000000000a85d30f8fcb12a42749d3d3cdead53d7
4. декодуємо це і отримуємо 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa461cb3c94e389b30efcff80a633f33da066cda004317a57bcfa284583d19e2e8
5. у даному випадку ми отримали bytes.fromhex acc670aae9bd0fd165082ef297b34842 що є ключем для отримання ключа до прапора.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Шифрований текст після атаки, для отримання ключа після ХОР маніпуляцій aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa461cb3c94e389b30efcff80a633f33da066cda004317a57bcfa284583d19e2e8
Ключ для отримання прапора acc670aae9bd0fd165082ef297b34842
Шифрований текст у hex 63727970746f7b35306d335f703330706c335f64306e375f3768316e6b5f49565f31355f316d70307237346e375f3f7d
Прапор crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?}
