CLI утилита для чтение, записи, обновления секретов.


=====================Пример запуска утилиты======================

crypto.exe arg1 arg2

=====================Параметры для запуска======================

1)arg1 - Путь до шифрованного файла с секретами;

2)arg2 - Метод взаимодействия с файлом секретов. Допустимые методы get, update, create.

====================Описание методом работы с файлом секретов========

1)get - Получить значение секрета имеющегося в базе;

Пример: crypto.exe \home\test\data get

2)update - Обновить секрет имеющийся в базе(Данный метод находится в разработке, на данный момент не работает);

Пример: crypto.exe \home\test\data update

3)create - Создать новый секрет.

Пример: crypto.exe \home\test\data create
