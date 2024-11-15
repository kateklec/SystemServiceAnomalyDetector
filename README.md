# SystemServiceAnomalyDetector

## Программный модуль обнаружения аномальной активности хоста посредством анализа системных служб
____
Аномалии в работе системных служб Windows могут быть индикаторами наличия вирусов или других вредоносных программ на компьютере, поэтому их своевременное обнаружение является важным шагом в обеспечении безопасности и стабильности работы системы.
В контексте моей работы под ***аномалиями хоста*** подразумеваются самопроизвольные отключения или остановки критических служб, нарушения в работе которых могут вызвать сбои в операционной системе.
____
## Последовательность работы стенда для анализа служб ПК с операционной системой Windows
Процесс начинается с воздействия ВПО, которое потенциально может влиять на системные службы. Информация о состоянии служб поступает на схему считывания, после чего формируется БД с конфигурациями и статусами служб. Стенд также использует три JSON-файла — файл с системными  службами и файл с пользовательскими службами, которые не должны быть отключены, файл с системными службами, которые не должны быть остановлены. Последний из них изображен внутри первого, т.к., те службы, которые не должны быть остановлены, так же и не должны быть отключены. *Файлы системный администратор наполняет по необходимым ему требованиям в зависимости от целей конечного пользователя.* Используя файлы и ранее сформированную базу данных, осуществляется анализ служб на предмет отключения и остановки. Далее выполняется схема анализа служб на наличие комбинаций, характерных для возможного ВПО. На основе собранной информации формируется вывод о состоянии служб. Если обнаруживаются проблемы, предоставляются рекомендации по их устранению.

![image](https://github.com/user-attachments/assets/ac13f990-93f9-408b-b1d2-7e9ba1baf853)
____
## Интерфейс программы
Главное окно программы содержит следующие основные элементы управления, которые представлены на рисунке ниже:
-	кнопка «Состояния служб» открывает диалоговое окно, отображающее информацию о текущих состояниях служб;
-	нажатие на кнопку «Проверить службы (сканирование по запросу)» инициирует проверку всех важных служб на наличие проблем, связанных с их состоянием (остановлены или отключены), а также на наличие возможных вирусов;
-	кнопка «Настроить мониторинг» открывает диалоговое окно, позволяющее настроить интервал мониторинга служб в режиме реального времени. Пользователь может выбрать предустановленные интервалы или задать интервал вручную в секундах;
-	кнопка «Добавить описания вирусов» открывает файл viruses.json в текстовом редакторе для редактирования списка вирусов. Доступ к этой функции защищен паролем администратора;
-	кнопка «Не отключены» позволяет администратору редактировать список важных служб, которые не должны быть отключены, открывая файл services_not_disabled.json по паролю;
-	кнопка «Не остановлены» позволяет администратору редактировать список важных служб, которые не должны быть остановлены, открывая файл services_not_stopped.json по паролю;
-	кнопка «Пользовательские службы» открывает файл custom_services.json по паролю для редактирования пользовательских служб и их описаний;
-	кнопка «Изменить пароль» открывает диалог для изменения пароля администратора. Изначальный пароль - admin;
-	в текстовом поле отображаются результаты проверок и мониторинга.
Для обеспечения безопасности доступа к важным функциям программы, таким как редактирование файлов служб и вирусов, используется система аутентификации на основе пароля администратора. При вводе пароля, он хэшируется алгоритмом SHA-256 и сравнивается с эталонным хэшом в json-файле password. Если они совпали, то списки можно редактировать, иначе будет выдана ошибка.

![image](https://github.com/user-attachments/assets/b112e3ab-a427-4569-831b-cf42d537029e)
____
### Диалоговое окно «Состояния служб»

![image](https://github.com/user-attachments/assets/b0fc54ed-870e-4e44-9cf9-1acf1431b048)
____
### Диалоговое окно «Настройка мониторинга»

![image](https://github.com/user-attachments/assets/099766ff-5f61-45ee-a6a7-fe6646db6d49)
____
### Тест, когда важная служба Winmgmt отключена

![image](https://github.com/user-attachments/assets/9a4b6958-96c0-4f46-a6f3-756cc6aeb8cd)
____
Данный модуль не является универсальным средством для обнаружения вирусов или другого ВПО, поэтому его использование следует рассматривать как дополнительное средство защиты.




