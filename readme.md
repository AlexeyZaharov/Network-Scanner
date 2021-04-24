# Network scanner
Привет! Опишу в двух словах: сетевой сканер! :)
![](imgs/hackerman.png)

Для работы необходимо установить `python3-nmap >= 1.5`. Поймали на хитрость? Именно так!
Ведь зачем самостоятельно писать сетевой сканер на сокетах, если существует такая мощная штука, как `nmap`? Это ведь
`python`-яка, давным давно умные люди уже все написали. Программист - человек ленивый, так зачем ходить на костылях? :)
![](imgs/mem.png)

# А теперь серьезно
Сетевой сканер - вещь мощная и опасная. Он нужен для анализа, какие хосты в сети живые и какие порты
на них открыты. Что делать с полученной информацией - каждый решает сам...

Данная программа использует хорошо известную утилиту `nmap`, которая прозрачно для пользователя сканирует указанный
диапазон сети на наличие открытых портов. В данной программе изначально делается `ping-сканирование` диапазона адресов:

`nmap -sP <ip_range>`

Затем несколько потоков берут один из живых хостов и проверяют открытые порты:

`nmap -Pn -p <port_range> <host>`

Кроме того, ~~чтобы сканировать чужие сети и не попасться,~~ используется параметр `-D RND:10`, который скрывает
собственный IP-адрес от сканируемого хоста, подменяя его на рандомный. Также для оптимизации сканирования используется
параметр `T4`, говорят, так быстрее.

# Приступим к делу
Собственно, программа сама все скажет:
```
python3 test_task.py --help
usage: test_task.py [-h] --ip_range [IP_RANGE] --port_range [PORT_RANGE]
                    [--get_service_info [GET_SERVICE_INFO]] [--out [OUT]]

Network Scanner: search opened ports in IP range

optional arguments:
  -h, --help            show this help message and exit
  --ip_range [IP_RANGE]
                        IP range for scanning. Can pass IP addresses, networks
                        or IP range. Ex: 192.168.0.1; ::1; 192.168.1.0/24;
                        ::1/112; 10.0.0-255.1-254
  --port_range [PORT_RANGE]
                        Port range for search open ones. Can pass ports
                        separated by comma, port range or both. Ex: 80,443;
                        1-1024; 80,100-300,443
  --get_service_info [GET_SERVICE_INFO]
                        Try to get service info on 80 and 443 ports.Note: do
                        not pass 80 and 443 ports in port range if use this
                        parameter.
  --out [OUT]           Path for report. Default is 'report.json'.
```

# Пример
Результат сканирования записывается в файл в формате `json`. Я рад, если Вы дочитали до этого места, но так как
тут уже и так "много букав", результат работы программы разместил в файлике `report.json`.
![](imgs/thanks.png)