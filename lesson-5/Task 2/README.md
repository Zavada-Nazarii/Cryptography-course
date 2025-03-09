# Базові вимоги

1. згенерувати імітовставку для перевірки цілісності та автентичності;
2. вибрати алгоритм для перевірки автентифікації даних;
2. створити ключ для перевірки імітовставки, автентичності та цілісності шифротексту;

# Обґрунтування реалізованого методу

За основу використано алгоритм `HMAC-SHA256`, оскільки він є криптографічно стійким, включає вектор ініціалізації, що захищає від підробок повторення та запобігає від атаки по часу - Timming Attack.

Оскільки у нас немає ключа для обчислення імітовставки, а використання одного і того самого головного ключа для шифрування та перевірки не є безпечним методом, використано метод `HKDF (HMAC-based Key Derivation Function)` який дозволяє отримати MAC ключ із головного ключа шифруванн та забезпечує криптографічну стійкість. В результаті, наш шифр неможливо відтворити без знання відповідного MAC-ключ який збережено у [mac_key.txt](https://github.com/Zavada-Nazarii/Cryptography-course/blob/master/lesson-5/Task%202/mac_key.txt), а імітоставку збережено у [mac.txt](https://github.com/Zavada-Nazarii/Cryptography-course/blob/master/lesson-5/Task%202/mac.txt).

Також, для генерування імітоставки ми включаємо `IV + ciphertext` щоб забкезпечити від атак повторення та підміни.

Скрипт [check_mac.py](https://github.com/Zavada-Nazarii/Cryptography-course/blob/master/lesson-5/Task%202/check_mac.py) проводить перевірут працездатосні головного скрита [main.py](https://github.com/Zavada-Nazarii/Cryptography-course/blob/master/lesson-5/Task%202/main.py). Якщо внести зміни у [ciphertext](https://github.com/Zavada-Nazarii/Cryptography-course/blob/master/lesson-5/Task%202/ciphertext.txt) скрипт перевірить це і виведе відповідну резолюцію верифікації.
