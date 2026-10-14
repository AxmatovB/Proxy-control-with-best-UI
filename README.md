# ProxyTool

Веб-панель для управления прокси на Windows: исключения прокси (`ProxyOverride`) на одном или многих компьютерах,
включение и выключение прокси на этом компьютере, автообновление по расписанию, журнал. Открывается в браузере
по адресу **http://127.0.0.1:1805**, работает в фоне без окон и сама запускается после включения компьютера.

> Подробная справка по возможностям ниже написана на узбекском. Этот раздел (запуск и решение проблем) на русском.

---

## ⚡ Быстрый старт (3 шага)

**Нужно:** Windows 10/11 и установленный [Python 3](https://www.python.org/downloads/) (при установке поставьте
галочку **Add python.exe to PATH**). Больше ничего: `pip install` не нужен.

1. **Один раз** запустите **`Install-Autostart.bat`** (двойной щелчок). Он попросит права администратора и:
   - создаст в Планировщике заданий две задачи (запуск при входе в Windows и «сторож» раз в 5 минут);
   - сразу запустит сервер в фоне, без чёрного окна.
2. Откройте в браузере **http://127.0.0.1:1805** (удобно добавить в закладки).
3. Всё. После перезагрузки компьютера сервер поднимется сам, ваши настройки и список IP останутся на месте.

Если автозапуск не нужен, просто запускайте **`ProxyTool.bat`** и нажимайте **`1`**.

---

## 🧰 Ежедневное использование

| Что нужно | Что сделать |
|---|---|
| Открыть сайт | `ProxyTool.bat` → **1** (если сервер уже работает, просто откроется браузер) |
| Остановить сервер | `ProxyTool.bat` → **0** (убивает все копии; сторож его не поднимет обратно до следующего запуска или входа в Windows) |
| Запустить снова после остановки | `ProxyTool.bat` → **1** |
| Проверить, всё ли в порядке | **`Status.bat`**: сам проверит Python, автозапуск, сервер, версию, журналы и подскажет, что делать |
| Убрать автозапуск | `Uninstall-Autostart.bat` (данные и список IP не удаляются) |
| Спрашивать пароль в окне UAC | `UAC-Password.bat` (необязательно, см. ниже) |

**Важно после обновления файлов.** Сервер читает `proxy_tool.py` только при старте. Если вы заменили или изменили файл,
перезапустите: `ProxyTool.bat` → **0**, затем `ProxyTool.bat` → **1**. Иначе продолжит работать старая версия
(`Status.bat` показывает это предупреждением).

**Прокси включается автоматически.** Кнопка «Добавить» и автообновление на каждом компьютере из списка (своём и
удалённых) сначала **включают прокси** (даже если сервер не задан), и только потом добавляют исключения. Уже
включённый прокси не трогается; если включить не удалось, исключения не пишутся и в журнале ошибка. Выключение в эту
операцию не входит. Автообновление включает прокси заново каждый цикл.

**Автообновление** (раздел «Автообновление» на сайте) сохраняет своё состояние: если вы нажали «Запустить» и компьютер
выключился или сервер упал, после запуска сервера оно **продолжится само** (через ~15 секунд, чтобы поднялась сеть).
Отключается только кнопкой «Остановить».

---

## 🛠 Если что-то не работает

**Первым делом запустите `Status.bat`.** Он ничего не меняет, не требует прав администратора и в конце пишет
пронумерованный список «Что сделать». Ниже самые частые случаи.

| Симптом | Причина | Что делать |
|---|---|---|
| Сайт не открывается (страница «не удаётся подключиться») | Сервер не запущен или остановлен вручную | `ProxyTool.bat` → **1**. Если не помогло, `Status.bat` и смотрите раздел 3 |
| Вместо сайта страница ошибки от прокси (например, «Connection to server failed») | Браузер ходит на `127.0.0.1` через корпоративный прокси | Добавьте `127.0.0.1;localhost` в исключения прокси (в самой программе: «Локальный прокси» → «Исключения»). Либо откройте http://localhost:1805 |
| После перезагрузки сайт не открылся | Автозапуск не установлен, отключён, или путь устарел | `Status.bat`. Чаще всего помогает снова запустить `Install-Autostart.bat` |
| Папку ProxyTool переместили/переименовали, обновили или переустановили Python | Задача в Планировщике хранит старые пути | Снова запустите `Install-Autostart.bat` **из новой папки**: он перезапишет задачи |
| `Install-Autostart.bat`: «pythonw.exe не найден» | Python не установлен или не в PATH | Установите Python с галочкой **Add python.exe to PATH**, откройте новое окно и повторите |
| Сайт открывается, но в журнале «Нет связи (выключен или порт закрыт)» | Удалённый ПК выключен или firewall закрыл порты 445/135 | Включите ПК/правило firewall. Это ошибка конкретного ПК, не программы |
| «Не удалось запустить Remote Registry», «Не удалось прочитать HKU» | Нет прав администратора на удалённом ПК | Войдите в Windows под учёткой с правами администратора на целевых ПК. Установите автозапуск: сервер тогда работает с правами администратора |
| «Профиль пользователя не найден» | На удалённом ПК никто не вошёл в систему | Это нормально, повторите, когда пользователь войдёт |
| Вверху «Без прав администратора» | Сервер запущен без повышенных прав | Установите автозапуск (`Install-Autostart.bat`) или запустите `ProxyTool.bat` из окна, открытого «от имени администратора» |
| Изменения на сайте (анимации, звук) не появились | Работает старая копия сервера | `ProxyTool.bat` → **0**, затем **1** |
| `Status.bat`: «запущено N процессов pythonw» | Остались лишние копии сервера | `ProxyTool.bat` → **0** (убивает все копии), затем **1** |
| Порт 1805 занят другой программой | Конфликт портов | Закройте программу, которая его занимает (`Status.bat` покажет её имя). Либо запустите вручную на другом порту: `python proxy_tool.py --port 1900` |
| Настройки сбросились или не читаются | Повреждён `settings.json` | Удалите `%APPDATA%\ProxyTool\settings.json` (настройки вернутся к стандартным) |
| Сервер падает сразу после запуска | Ошибка в работе (подробности в файле) | Откройте `%APPDATA%\ProxyTool\crash.log` (его последние строки показывает и `Status.bat`) |
| Антивирус блокирует `.bat`/`pythonw` | Ложное срабатывание на скрипты | Добавьте папку ProxyTool в исключения антивируса |
| Окно UAC не просит пароль | Вы администратор: Windows показывает только «Да/Нет» | Это политика Windows. Чтобы всегда просить логин и пароль, запустите `UAC-Password.bat` → **1** |

**Где смотреть журналы:** в самой панели (блок «Журнал»), файл `%APPDATA%\ProxyTool\proxytool.log` (полный журнал)
и `%APPDATA%\ProxyTool\crash.log` (только если сервер упал; обычно файла нет).

**Как «перезагрузить» всё с нуля, если ничего не помогает:**
1. `Uninstall-Autostart.bat` (убирает задачи и останавливает сервер).
2. `Install-Autostart.bat` (ставит заново и запускает).
3. `Status.bat`: должно быть «Всё в порядке».

---

## 📍 Что где лежит

| Что | Где |
|---|---|
| Программа и скрипты | папка `ProxyTool` (где лежит этот файл) |
| Ваши данные: список IP, исключения, настройки, состояние автообновления | `%APPDATA%\ProxyTool\` (`settings.json`, `auto_state.json`) |
| Журналы | `%APPDATA%\ProxyTool\proxytool.log`, `crash.log` |
| Автозапуск | Планировщик заданий Windows → задачи `ProxyTool` и `ProxyTool-Watchdog` |

Скрипты в папке:

| Файл | Назначение |
|---|---|
| `proxy_tool.py` | сама программа (сервер и веб-интерфейс) |
| `ProxyTool.bat` | меню: **1** запустить в фоне и открыть сайт, **0** остановить |
| `Install-Autostart.bat` / `Uninstall-Autostart.bat` | установить / убрать автозапуск (нужны права администратора) |
| `Status.bat` | диагностика, ничего не меняет |
| `UAC-Password.bat` | (необязательно) просить пароль в окне UAC |
| `autostart.ps1`, `status.ps1` | вспомогательные скрипты для `.bat` (запускать вручную не нужно) |

**Полное удаление:** `Uninstall-Autostart.bat`, затем удалите папку ProxyTool и (если хотите стереть данные) папку
`%APPDATA%\ProxyTool`.

---

## 🔒 Безопасность в двух словах

- Сервер слушает только `127.0.0.1`: с других компьютеров к нему не подключиться. Не запускайте с `--host 0.0.0.0`:
  у панели нет пароля.
- Автозапуск работает с правами администратора и не спрашивает пароль при каждом входе: так задумано, иначе
  удалённые ПК не настроить. Доступ к самой панели есть только у программ на этом компьютере.
- Перед массовой записью на много ПК сначала проверьте на 1–2 компьютерах кнопкой «Прочитать текущие».

---

## Подробная справка (на узбекском)

Proxy sozlamalarini **veb-sahifa orqali** boshqaradigan vosita (Neumorphism uslubida, interfeys to'liq **rus tilida**).
`Network-Scanner` loyihasidagi (`NS.py`) "Proxy istisnolari" moduli tkinter'dan ajratib olingan va
`http://127.0.0.1:1805` da ochiladigan veb-saytga aylantirilgan.

- Bitta fayl: `proxy_tool.py`
- Faqat Python standart kutubxonasi (**`pip install` kerak emas**)
- Faqat Windows uchun (registry, `reg`, `sc` buyruqlari)

---

### Imkoniyatlar

| Bo'lim | Vazifasi |
|---|---|
| **Исключения прокси** | Bir yoki ko'p kompyuterning `ProxyOverride` ro'yxatiga yozuv **qo'shadi**, **olib tashlaydi**, joriy holatini **o'qiydi**. Mavjud yozuvlarni buzmaydi, faqat yo'qlarini qo'shadi. **Yangi:** qo'shishdan oldin proksini avtomatik **yoqadi** (pastga qarang). |
| **Автообновление** | Proxy doimiy o'zgarib/tozalanib turadigan tarmoqda yozuvlarni har N soat/daqiqada qayta tiqib turadi. |
| **Локальный прокси** | Katta neumorphic **yoqish/o'chirish tugmasi**, proxy server manzili va istisnolarini tahrirlash. |
| **Журнал** | Rangli natijalar, qidiruv, daraja bo'yicha filtr, `.txt` ga saqlash, tozalash. |

Amallar **lokal** (`localhost`) va **masofaviy** (IP bo'yicha) kompyuterlarda ishlaydi.
Tepada o'ng burchakdagi **◐** tugmasi yorug'/qorong'i temani almashtiradi.

**Animatsiya va ovozlar:** vkladkalar, ro'yxatlar va tugmalar silliq animatsiya bilan ishlaydi (bosganda to'lqin
effekti). Bosish, vkladka almashtirish, manzil qo'shish/o'chirish, muvaffaqiyat, xato, proxy yoqish/o'chirish
uchun yumshoq ovozlar bor (brauzerning o'zida hosil qilinadi, tashqi fayl yo'q). Tepadagi **dinamik** tugmasi
ovozni o'chirib-yoqadi, tanlov `settings.json` da saqlanadi. Tizimda "animatsiyani kamaytirish" yoqilgan
bo'lsa, vizual effektlar o'chadi.

**Ko'rinish:** asosiy oyna bitta ekranga sig'adi (sahifa scroll qilinmaydi). Chapda manzillar, o'rtada
istisnolar va avto-yangilash, o'ngda joriy vazifa va jurnal. Ko'p IP diapazon kiritsangiz, ro'yxat
o'z ichida scroll bo'ladi (har biri nechta manzil ekanini ko'rsatadi); jurnal ham o'z ichida scroll bo'ladi.
Tanlov ro'yxatlari va raqam maydonlari ham sayt dizaynida (brauzerning standart elementlari emas).

---

## Ishga tushirish

```powershell
cd %USERPROFILE%\Desktop\ProxyTool
python proxy_tool.py
```

Brauzer o'zi ochiladi: **http://127.0.0.1:1805**. To'xtatish: konsolda `Ctrl+C`.

Masofaviy kompyuterlar uchun terminalni **administrator** sifatida oching. Sahifa tepasida
"Администратор" yozuvi chiqsa, hammasi tayyor.

| Amal | Admin kerakmi? |
|---|---|
| Lokal proxy (o'qish/yozish, istisnolar) | Yo'q (faqat joriy foydalanuvchi registri) |
| **Masofaviy** kompyuterlar | **Ha** — maqsad kompyuterda admin huquqli hisob bilan kirgan bo'lishingiz kerak |

Parametrlar:

```
python proxy_tool.py --port 1805     # port
python proxy_tool.py --no-browser    # brauzerni ochmaslik
python proxy_tool.py --host 0.0.0.0  # tarmoqdan ochiq (parolsiz! faqat ishonchli tarmoqda)
```

---

## Fonda ishlatish va avtozapusk (.bat fayllar)

Qora oynasiz ishlaydi (`pythonw.exe` orqali).

| Fayl | Nima qiladi |
|---|---|
| **`ProxyTool.bat`** | Ishga tushirganda menyu chiqadi: **`1`** — serverni **oynasiz, fonda** ishga tushiradi va brauzerda saytni ochadi (allaqachon ishlayotgan bo'lsa, faqat brauzerni ochadi, ikkinchi nusxa ochilmaydi). **`0`** — fondagi sessiyani **to'xtatadi (kill)**. Argument bilan ham ishlaydi: `ProxyTool.bat 1` / `ProxyTool.bat 0`. |
| **`Install-Autostart.bat`** | **Bir marta** ishga tushiring (administrator so'raydi). Windows'ga ikkita vazifa qo'shadi: "ProxyTool" — kompyuter yonib, tizimga kirilganda server o'zi fonda ishga tushadi (administrator huquqi bilan, UAC so'ramaydi); "ProxyTool-Watchdog" — har 5 daqiqada tekshiradi va server ishdan chiqqan bo'lsa, qayta ishga tushiradi. |
| **`Uninstall-Autostart.bat`** | Avtozapuskni (ikkala vazifani) o'chiradi va serverni to'xtatadi. Ma'lumotlaringiz (IP ro'yxat, sozlamalar) o'chmaydi. |

**`0` bilan to'xtatganda:** server o'chadi va watchdog uni qayta yoqmaydi (`stopped.flag` belgisi qo'yiladi).
Qayta yoqish — `ProxyTool.bat` → `1`. Keyingi safar Windows'ga kirganingizda server avtomatik yana ishga tushadi.
Avtozapusk o'rnatilgan bo'lsa, `0` administrator huquqini so'raydi (server administrator huquqi bilan ishlagani uchun).

Tavsiya etilgan tartib: `Install-Autostart.bat` ni bir marta ishga tushiring, keyin sayt har doim
http://127.0.0.1:1805 da tayyor turadi. Brauzerga yorliq (закладка) qo'yib qo'ysangiz bo'ldi.

> Eslatma: `Install-Autostart.bat` ni **o'zingizning hisobingizdan** administrator sifatida tasdiqlang
> (UAC'da parol so'ramay "Ha" bosiladigan odatdagi holat). Agar alohida admin hisob paroli so'ralsa, vazifa
> o'sha hisobga yoziladi va sizning proxy sozlamalaringizga tegmaydi.

### UAC'da parol so'rash (ixtiyoriy)

`UAC-Password.bat` administrator huquqi so'ralganda "Ha/Yo'q" o'rniga **foydalanuvchi nomi + parol** so'raladigan
qiladi (`ConsentPromptBehaviorAdmin = 1`). Ishga tushirgach menyu chiqadi: `1` yoqish, `0` avvalgi holatga
qaytarish, `2` hozirgi holatni ko'rish (administrator kerak emas). Eski qiymat `%APPDATA%\ProxyTool\uac_prev.txt` ga
saqlanadi va `0` bilan qaytariladi.

- Bu **butun kompyuterning** sozlamasi: boshqa dasturlar ham parol so'raydi. Faqat ProxyTool uchun alohida yoqib bo'lmaydi.
- Parolsiz hisobda yoqilmaydi (bat o'zi to'xtatadi), aks holda administrator huquqini ololmay qolasiz.
- Kompyuter domenda bo'lsa, domen siyosati (GPO) sozlamani qayta yozib qo'yishi mumkin.
- Avtozapusk vazifasi parol so'ramaydi: u Planirovshchikda oldindan administrator huquqi bilan o'rnatilgan.

### Kompyuter o'chib-yonganda ma'lumotlar yo'qolmaydi

- IP diapazonlar va barcha sozlamalar har o'zgarishda `%APPDATA%\ProxyTool\settings.json` ga yoziladi.
- **Avto-yangilash** (real-time) holati `auto_state.json` da saqlanadi. **Запустить** bosilgan bo'lsa va
  kompyuter o'chib/yonsa yoki server uzilsa, server qayta ishga tushganda avto-yangilash **o'zi davom etadi**
  (tarmoq ko'tarilishi uchun 15 soniya kutadi, jurnalda "ВОССТАНОВЛЕНО после перезапуска" yoziladi).
  Faqat **Остановить** tugmasini o'zingiz bossangiz, qayta ishga tushganda u o'z-o'zidan yonmaydi.
- Server fonda xatoga uchrasa, sabab `%APPDATA%\ProxyTool\crash.log` ga yoziladi.

---

## Ma'lumotlar qayerda saqlanadi

Hammasi **`%APPDATA%\ProxyTool\`** papkasida (brauzer xotirasida emas):

| Fayl | Mazmuni |
|---|---|
| `settings.json` | Manzillar ro'yxati, istisnolar matni, oqim/kutish, avto-interval, proxy server, tema |
| `auto_state.json` | Avto-yangilash ishlab turibdimi va uning parametrlari (qayta ishga tushganda davom etish uchun) |
| `proxytool.log` | To'liq jurnal (vaqt bilan) |
| `crash.log` | Faqat kutilmagan xato bo'lsa paydo bo'ladi |

Sahifani yopib qayta ochsangiz yoki boshqa brauzerdan kirsangiz ham, ma'lumotlar joyida turadi.
Kiritganingiz 0,4 soniyada o'zi saqlanadi. Hammasini tozalash uchun shu papkani o'chirib tashlang.

---

## Foydalanish

### 1. Manzillar (IP diapazonni qo'lda kiritish)

- **Начальный IP** va **Конечный IP** maydonlariga diapazon chegaralarini yozing
  (masalan `10.145.37.1` va `10.145.37.254`) va **Добавить** bosing.
- Faqat birinchi maydonni to'ldirsangiz, bitta manzil qo'shiladi. U yerga CIDR (`10.0.0.0/24`)
  yoki host nomini ham yozish mumkin.
- **Этот компьютер** — `localhost` ni qo'shadi.
- Qo'shilganlar "chip" ko'rinishida chiqadi, `✕` bilan olib tashlanadi.
- **Потоков** — bir vaqtda nechta kompyuter (standart 50), **Таймаут** — har biri uchun kutish (soniya).

### 2. Исключения прокси

1. "Исключения" maydoniga yozuvlarni kiriting: `*.local; 10.145.*; <local>` (`;` yoki yangi qator bilan).
2. **Добавить в исключения** — yo'qlari qo'shiladi, borlari "Без изменений" deb o'tkaziladi.
   **Удалить из исключений** — ko'rsatilganlar o'chadi. **Прочитать текущие** — hozirgi qiymatni jurnalda ko'rsatadi.

**Proksi avtomatik yoqiladi (yangi):** **Добавить** va avtoyangilash har bir kompyuterda (lokal ham, masofaviy ham)
avval proksini **yoqadi** (`ProxyEnable=1`), keyin yozuvlarni ro'yxatga qo'shadi. Proksi allaqachon yoqilgan bo'lsa,
tegmaydi. Proksi serveri kiritilmagan bo'lsa ham yoqadi. Yoqib bo'lmasa (reestr xatosi), yozuvlar qo'shilmaydi va
jurnalda xato chiqadi. Jurnalda: `Прокси включён; Добавлено: ...`. Proksini o'chirish bu amalga kirmaydi
(o'chirish: "Локальный прокси" vkladkasidagi tugma). Avtoyangilash har siklda proksini qayta yoqadi, shuning
uchun uni qo'lda o'chirsangiz, keyingi siklda yana yoqiladi.

**Автообновление:** "Каждые N часов/минут" ni tanlab **Запустить** bosing. Birinchi sikl darrov
bajariladi, keyingilari belgilangan oraliqda; holat satrida keyingi ishga tushish vaqti ko'rinadi.
**Остановить** darrov to'xtatadi. Avto-rejim server ochiq turganida ishlaydi.

### 3. Локальный прокси

Katta yumaloq tugma proxy'ni **yoqadi/o'chiradi** (bosilgan = yoqilgan). Server (`host:port`) va
istisnolarni tahrirlab, **Сохранить параметры** bilan yozib qo'yasiz.

### 4. Журнал

Yashil — muvaffaqiyatli, qizil — xato, kulrang — o'zgarish kerak bo'lmadi, ko'k — sarlavha.

---

## Masofaviy kompyuterlar qanday ishlaydi

Maqsad kompyuterda *Remote Registry* xizmatini kerak bo'lsa ishga tushiradi va `HKU\<SID>` ostidagi
barcha foydalanuvchi profillarini o'zgartiradi. Oldin 445 va 135 portlar tekshiriladi.

| Xabar (jurnalda) | Sabab / yechim |
|---|---|
| Нет связи (выключен или порт закрыт) | Kompyuter o'chiq yoki firewall 445/135 ni yopgan |
| Не удалось запустить Remote Registry | Admin huquqli hisob bilan kirmagansiz |
| Не удалось прочитать HKU | Xuddi shu — admin huquqi kerak |
| Профиль пользователя не найден | Maqsad kompyuterda hech kim tizimga kirmagan |
| Без изменений | Xato emas, o'zgartirish shart bo'lmadi |

---

## Xavfsizlik

- Standart holatda server **faqat `127.0.0.1`** da tinglaydi.
- `Host` va `X-Requested-With` sarlavhalari tekshiriladi: boshqa veb-sahifa brauzeringiz orqali bu
  serverga yashirin buyruq yubora olmaydi.
- `--host 0.0.0.0` bilan tarmoqqa ochsangiz **parol yo'q**. Faqat ishonchli tarmoqda, vaqtincha ishlating.
- Ko'p kompyuterga yozishdan oldin **Прочитать текущие** bilan kichik guruhda sinab ko'ring.

---

## Fayllar

```
Desktop\ProxyTool\
├── proxy_tool.py            # dastur (server + veb-interfeys)
├── ProxyTool.bat            # fonda ishga tushirish + brauzerda ochish
├── Install-Autostart.bat    # avtozapusk o'rnatish (bir marta)
├── Uninstall-Autostart.bat  # avtozapuskni olib tashlash
├── UAC-Password.bat         # UAC da parol so'rashni yoqish/qaytarish (ixtiyoriy)
├── Status.bat               # diagnostika (hech narsani o'zgartirmaydi)
├── status.ps1               # Status.bat yordamchisi
├── autostart.ps1            # yuqoridagi .bat fayllarning yordamchisi
└── README.md                # shu qo'llanma

%APPDATA%\ProxyTool\         # ishga tushgach avtomatik yaratiladi
├── settings.json
├── auto_state.json
├── proxytool.log
└── crash.log                # faqat xato bo'lsa
```
