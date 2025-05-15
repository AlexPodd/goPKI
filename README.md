Конфигурация в формате JSON:
  "trustPath": "cmd/web/trustCertificate",   #Путь к папке, содержащей все доверенные сертификаты
  "keyPath": "cmd/web/root/ca/intermediate/private", #Путь к папке с приватными ключами
  "rootCACertificatePath": "cmd/web/trustCertificate/ca.cert.pem", #Путь к файлу корневого сертификата PKI
  "tlsServerCert": "cmd/web/tls/serverTLS.crt", #Путь к сертификату сервера
  "tlsServerKey": "cmd/web/tls/keyTLS.pem",     #Путь к приватному ключу сервера
  "validationDays": 180,                        #Количество дней на которое пользователям выдают ключи
   "database": {                                #Конфигурация подключения к базе данных
    "user": "root",                              #Имя пользователя БД
    "password": "",                              #Пароль пользователя
    "host": "localhost",                         #Хост
    "port": 3306,                                #Порт
    "name": "pki"                                #Название базы данных
  },
  "caKeys":                                     #Информация о промежуточных ЦС
    {
      "certFile": "intermediate.cert.pem",      #Файл ЦС 
      "keyFile": "intermediate.key.pem",        #Файл приватного ключа ЦС
      "password": ""                             #Пароль от приватного ключа
    }
}
Для добавления новых ЦС необходимо подписать с помощью корневого сертификата, а также добавить сертификат по пути: $trustPath Приватный ключ добавить по пути $keyPath
Для запуска проекта перейти в корневую директорию и ввести команду: go run ./cmd/web
