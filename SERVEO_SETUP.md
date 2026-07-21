# Полная настройка Serveo

Этот гайд предназначен для пользователей Windows, у которых нет собственного домена, VPS, ngrok или Cloudflare Tunnel.

Notion Local MCP Easy поддерживает два варианта:

- **Temporary mode** — запускается без аккаунта Serveo, но URL меняется после перезапуска.
- **Stable mode** — бесплатный аккаунт Serveo, отдельный SSH-ключ и зарезервированный hostname. URL остаётся постоянным.

## Вариант 1: временный URL без аккаунта

1. Распакуйте архив.
2. Запустите `START.bat`.
3. Выберите workspace.
4. Включите или отключите trusted developer mode.
5. На вопрос `Use a reserved Serveo hostname?` ответьте `n` или нажмите Enter.
6. Скопируйте показанные URL и Bearer-токен в настройки Custom MCP в Notion.

После следующего запуска Serveo может выдать другой URL. Этот режим подходит для проверки работы MCP.

---

## Вариант 2: постоянный URL

### Шаг 1. Проверьте OpenSSH

Откройте PowerShell и выполните:

```powershell
ssh -V
```

Если команда не найдена:

1. Откройте **Параметры Windows**.
2. Перейдите в **Приложения → Дополнительные компоненты**.
3. Добавьте **OpenSSH Client**.
4. Перезапустите PowerShell.

### Шаг 2. Создайте аккаунт Serveo

1. Откройте [Serveo](https://serveo.net/).
2. Создайте аккаунт и войдите в панель управления.
3. Откройте раздел **SSH Keys**.

### Шаг 3. Создайте отдельный SSH-ключ

В PowerShell выполните:

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\serveo_notion_mcp" -C "notion-mcp-easy"
```

Когда появится запрос passphrase, дважды нажмите **Enter**. Пустой passphrase нужен, чтобы launcher мог подключаться автоматически.

Будут созданы два файла:

```text
%USERPROFILE%\.ssh\serveo_notion_mcp
%USERPROFILE%\.ssh\serveo_notion_mcp.pub
```

- `serveo_notion_mcp` — приватный ключ. Никому не отправляйте.
- `serveo_notion_mcp.pub` — публичный ключ. Его нужно добавить в Serveo.

### Шаг 4. Добавьте публичный ключ в Serveo

Скопируйте публичный ключ:

```powershell
Get-Content "$env:USERPROFILE\.ssh\serveo_notion_mcp.pub" | Set-Clipboard
```

В панели Serveo:

1. Откройте **SSH Keys**.
2. Нажмите **Add SSH Key**.
3. В поле **Name** укажите `notion-mcp-easy`.
4. Вставьте публичный ключ.
5. Сохраните.

Публичный ключ обычно начинается с:

```text
ssh-ed25519 AAAA...
```

### Шаг 5. Зарезервируйте hostname

1. В панели Serveo откройте **Domains**.
2. Создайте новый hostname, например `my-notion-mcp`.
3. Выберите forwarding type **SSH**.
4. Сохраните.

Постоянный адрес будет выглядеть так:

```text
https://my-notion-mcp.serveousercontent.com/mcp
```

Hostname должен быть уникальным. Вводите в launcher только часть `my-notion-mcp`, без `https://` и без `.serveousercontent.com`.

### Шаг 6. Настройте Notion Local MCP Easy

Запустите:

```text
SETUP.bat
```

Ответьте на вопросы:

1. **Workspace folder** — папка, к которой агент получит доступ.
2. **Enable trusted developer mode?**
   - `n` или Enter — только файловые инструменты;
   - `y` — Python, Git, Node и другие команды с правами пользователя Windows.
3. **Use a reserved Serveo hostname?** — ответьте `y`.
4. **Reserved hostname** — введите зарезервированное имя без домена.
5. **Serveo private SSH key** — нажмите Enter, если использовали стандартный путь из этого гайда.

После настройки запустите:

```text
START.bat
```

### Шаг 7. Добавьте MCP в Notion

В настройках Custom MCP укажите:

- **URL:** адрес, показанный launcher, обязательно с `/mcp`;
- **Authentication:** Bearer Token;
- **Token:** значение из окна launcher или `SHOW_CONNECTION.bat`.

Пример URL:

```text
https://my-notion-mcp.serveousercontent.com/mcp
```

После этого URL можно оставить в Notion постоянно. Обычные остановки и повторные запуски не требуют пересоздания подключения.

---

## Управление

- `START.bat` — запустить MCP и Serveo-туннель.
- `STOP.bat` — остановить процессы.
- `SETUP.bat` — изменить workspace, режим, hostname, ключ или сгенерировать новый токен.
- `SHOW_CONNECTION.bat` — показать URL, токен и текущий режим.
- `BUILD_RELEASE.bat` — создать безопасный архив без локальной конфигурации и ключей; готовый ZIP сохраняется в `release/` внутри проекта, при этом сама папка `release/` не входит ни в Git, ни в архив.

Окно `START.bat` необходимо держать открытым или свёрнутым. `Ctrl+C` останавливает сервер.

Если `run_command`, `grep_files` или `list_dir` возвращают слишком большой результат, MCP сохранит полный вывод во временный файл и отдаст первую безопасную часть с путём вида `@temp/...`. Продолжение чтения выполняется через `read_file(..., offset=...)`. Такие временные файлы лежат в `temp/` рядом с `server.py`, удаляются после дочитывания и дополнительно очищаются при следующем запуске сервера.

---

## Проверка постоянного адреса

1. Запомните URL из первого запуска.
2. Остановите сервер через `STOP.bat`.
3. Снова запустите `START.bat`.
4. Убедитесь, что URL не изменился.
5. Отправьте агенту простую команду, например попросите показать список файлов workspace.

---

## Частые ошибки

### `ssh` не найден

Установите Windows OpenSSH Client через дополнительные компоненты Windows.

### `Permission denied (publickey)`

Проверьте:

- публичный `.pub`-ключ добавлен в аккаунт Serveo;
- launcher использует соответствующий приватный ключ без `.pub`;
- путь к ключу указан правильно;
- в настройке stable mode передаётся `IdentitiesOnly=yes` автоматически.

### Serveo выдаёт случайный URL

Значит stable mode не включён или hostname не сохранён в конфигурации. Повторно запустите `SETUP.bat` и ответьте `y` на вопрос о reserved hostname.

### Hostname уже занят

Выберите другое уникальное имя в разделе **Domains** Serveo.

### Notion показывает HTTP 401

Bearer-токен в Notion не совпадает с текущим токеном. Запустите `SHOW_CONNECTION.bat` и обновите токен в настройках подключения.

### Notion показывает HTTP 421

Убедитесь, что используется версия 1.2.0 или новее. В ней поддерживаются публичные Serveo Host-заголовки.

### Порт 8765 занят

Остановите старый MCP через `STOP.bat`. Если порт занят другим приложением, измените `port` в `%LOCALAPPDATA%\NotionMcpEasy\config.json`.

### Туннель переподключился

- В temporary mode URL может измениться — обновите его в Notion.
- В stable mode launcher повторно использует зарезервированный hostname, поэтому URL остаётся прежним.

---

## Безопасность

Никогда не публикуйте:

- Bearer-токен;
- приватный SSH-ключ;
- `config.json`;
- `connection.txt`;
- логи с приватными путями.

Публичный `.pub`-ключ не является секретом, но включать его в общий архив также не требуется.

Trusted developer mode не является песочницей: Python, Node, Git hooks и npm scripts могут обращаться за пределы workspace. Для незнакомых агентов используйте file-only mode.

---

## Промпт для AI-агента

Если настройкой занимается AI-агент, можно отправить ему архив и этот запрос:

```text
Распакуй проект, прочитай README.md, SECURITY.md и SERVEO_SETUP.md. Помоги установить и настроить Notion Local MCP Easy. Не публикуй Bearer-токен или приватный SSH-ключ. Сначала предложи file-only mode. Для постоянного URL используй зарезервированный Serveo hostname и отдельный ключ serveo_notion_mcp.
```
