# crypto-stream-auth

Прототип сетевого протокола непрерывной криптографической аутентификации медиапотока в реальном времени.

Цель проекта: подтвердить, что медиапоток поступает от доверенного аппаратного источника и не был изменён при передаче через сеть или сервер.

## Идея

Система строится по принципу сквозного доверия:

- producer (продюсер, камера или эмулятор) имеет сертификат X.509 (стандарт сертификатов открытого ключа), выпущенный заводским RSA Root CA (Rivest-Shamir-Adleman Root Certificate Authority, корневой центр сертификации RSA);
- долговременный закрытый ключ камеры RSA-2048 (Rivest-Shamir-Adleman, криптосистема с открытым ключом) создаётся и хранится в TPM (Trusted Platform Module, доверенный платформенный модуль);
- handshake (рукопожатие) подписывается аппаратным ключом из TPM (Trusted Platform Module, доверенный платформенный модуль) по схеме RSA-PSS (Probabilistic Signature Scheme, вероятностная схема подписи RSA) + SHA-256 (Secure Hash Algorithm, защищённый алгоритм хеширования);
- каждый кадр подписывается временным ключом Ed25519, созданным в RAM (Random Access Memory, оперативная память) для текущей сессии;
- server (сервер) проверяет сертификат камеры и маршрутизирует поток;
- consumer (консюмер) самостоятельно проверяет сертификат камеры, подпись handshake (рукопожатия) и подписи кадров.

Сервер не проверяет подпись каждого кадра. Он работает как Fast Pipe (быстрый канал передачи), а доверие устанавливается между камерой и консюмером.

## Текущая реализация

- Язык: Go (язык программирования).
- Транспорт: QUIC (Quick UDP Internet Connections, быстрые соединения поверх UDP) поверх UDP (User Datagram Protocol, протокол пользовательских датаграмм).
- Текущий режим передачи: один QUIC stream (стрим, логический поток).
- Сертификаты: X.509 (стандарт сертификатов открытого ключа).
- Root CA (Root Certificate Authority, корневой центр сертификации): RSA-4096 (Rivest-Shamir-Adleman, криптосистема с открытым ключом).
- Сертификат камеры: RSA-PSS (Probabilistic Signature Scheme, вероятностная схема подписи RSA) + SHA-384 (Secure Hash Algorithm, защищённый алгоритм хеширования).
- Ключ камеры в TPM (Trusted Platform Module, доверенный платформенный модуль): RSA-2048 (Rivest-Shamir-Adleman, криптосистема с открытым ключом).
- Подпись handshake (рукопожатия): RSA-PSS (Probabilistic Signature Scheme, вероятностная схема подписи RSA) + SHA-256 (Secure Hash Algorithm, защищённый алгоритм хеширования).
- Подпись кадров: Ed25519.
- Источник медиа: FFmpeg (набор медиаутилит).
- Отображение: ffplay (проигрыватель из FFmpeg).
- Демонстрационный контейнер: MPEG-TS (MPEG Transport Stream, транспортный поток MPEG).
- Демонстрационный видеокодек: H.264 (стандарт видеокодирования).

Протокол не привязан к H.264 (стандарту видеокодирования) или MPEG-TS (MPEG Transport Stream, транспортному потоку MPEG). Он подписывает ограниченный по размеру `payload` — полезную нагрузку — и не разбирает внутреннюю структуру видеокодека.

## Архитектура

```text
consumer -> server -> producer   handshake request
producer -> server -> consumer   handshake response
producer -> server -> consumers  signed media frames
```

Основные пакеты:

```text
internal/app       сборка приложений producer/server/consumer
internal/transport QUIC, TLS, чтение и запись сообщений
internal/handshake формат, подпись и проверка рукопожатия
internal/crypto    X.509, Root CA, сертификаты, trust manifest, подписи кадров
internal/tpm       работа с аппаратным ключом камеры
internal/stream    отправка, приём, проверка кадров и политика реакции
internal/media     FFmpeg-источник и ffplay-вывод
internal/domain    общие доменные структуры кадра
cmd                точки входа
```

Сейчас поддерживается один producer (продюсер) и несколько consumer (консюмеров). Поддержка нескольких producer (продюсеров) оставлена как следующий этап.

## Формат доверия

На этапе подготовки устройства:

1. В TPM (Trusted Platform Module, доверенном платформенном модуле) создаётся долговременный закрытый ключ камеры RSA-2048.
2. Публичный ключ камеры экспортируется в файл.
3. Заводской RSA Root CA (Rivest-Shamir-Adleman Root Certificate Authority, корневой центр сертификации RSA) выпускает сертификат камеры.
4. Манифест связывает UID (Unique Identifier, уникальный идентификатор) камеры, отпечаток сертификата камеры и отпечаток Root CA (Root Certificate Authority, корневого центра сертификации).
5. Закрытый ключ камеры не покидает TPM (Trusted Platform Module, доверенный платформенный модуль).

Во время handshake (рукопожатия) подписывается:

```text
Session ID
consumer nonce
timestamp
ephemeral public key
```

Каждый кадр подписывается по данным:

```text
Session ID
Sequence ID
Timestamp
Payload
```

## Проверка кадров

Consumer (консюмер) проверяет:

- `Session ID` — идентификатор сессии;
- `Sequence ID` — порядковый номер кадра;
- `Timestamp` — временную метку;
- размер `payload` — полезной нагрузки;
- подпись Ed25519;
- долю кадров с некорректной подписью.

Если за окно 3 секунды получено больше 30 кадров и больше 20% из них имеют некорректную подпись, consumer (консюмер) запрашивает новый handshake (рукопожатие). Если после повторного handshake (рукопожатия) ситуация повторяется, соединение считается недоверенным.

## Подготовка

Нужны:

- Go (язык программирования) 1.26;
- FFmpeg (набор медиаутилит) с командами `ffmpeg` и `ffplay` в `PATH`;
- Windows TPM (Trusted Platform Module, доверенный платформенный модуль) для реального аппаратного ключа;
- камера DirectShow с именем `HD User Facing`.

Проверить список камер Windows:

```powershell
ffmpeg -list_devices true -f dshow -i dummy
```

Если имя камеры другое, измени строку `video=HD User Facing` в `internal/media/source.go`.

## Ключи и сертификаты

Команды выполнять из корня проекта.

1. Создать Root CA (Root Certificate Authority, корневой центр сертификации):

```powershell
go run ./cmd/factory/rootgen
```

Создаются:

```text
artifacts/trust/roots/root_ca2.crt
artifacts/keys/root_ca2.key
```

2. Создать или открыть ключ камеры в TPM (Trusted Platform Module, доверенном платформенном модуле) и экспортировать публичный ключ:

```powershell
go run ./cmd/producer/provision
```

Создаётся:

```text
artifacts/camera/camera_public2.pem
```

3. Выпустить сертификат камеры:

```powershell
go run ./cmd/factory/certgen
```

Создаются или обновляются:

```text
artifacts/camera/camera2.crt
artifacts/trust/camera_manifest.json
```

Файлы сертификатов и ключей не перетираются случайно: для новых файлов используется создание только если файла ещё нет, а манифест обновляется отдельно.

## Запуск

Открыть три терминала.

1. Producer (продюсер):

```powershell
go run ./cmd/producer
```

2. Server (сервер):

```powershell
go run ./cmd/server
```

3. Consumer (консюмер):

```powershell
go run ./cmd/consumer
```

После успешного handshake (рукопожатия) consumer (консюмер) откроет окно `ffplay` и начнёт показывать поток.

## Логи

Успешные кадры не логируются по одному. Раз в секунду выводится статистика:

```text
producer stats: frames=30 bytes=840000 fps=29.8 avg_payload=28000
server relay stats: frames=30 bytes=840000 fps=29.9 avg_payload=28000 consumers=2
consumer stats: accepted=30 dropped=0 bad_signatures=0 bytes=840000 fps=29.7 avg_payload=28000
```

Ошибки handshake (рукопожатия), отброшенные кадры и проблемы подписи логируются сразу.

## TPM

Текущий постоянный handle (идентификатор объекта TPM) ключа камеры:

```text
0x81000005
```

Он задан как `DefaultCameraKeyHandle` в `internal/tpm/signer.go`.

Удалить ключ из TPM (Trusted Platform Module, доверенного платформенного модуля):

```powershell
go run ./cmd/producer/evict --confirm
```

После удаления TPM-ключа старый сертификат камеры больше не соответствует новому ключу.

## Тесты

Запустить все тесты:

```powershell
go test ./...
```

Запустить только сценарии угроз:

```powershell
go test -v ./internal/handshake ./internal/stream -run Threat
```

Проверяемые угрозы:

```text
threat_01_rejects_foreign_camera_certificate
threat_02_rejects_replayed_handshake_response
threat_03_rejects_expired_handshake_timestamp
threat_04_rejects_tampered_handshake_signature
threat_05_rejects_tampered_payload
threat_06_rejects_replayed_frame
threat_07_rejects_old_frame_sequence
threat_08_rejects_foreign_session_id
```

## Важные файлы

```text
cmd/factory/rootgen/main.go              создание Root CA
cmd/producer/provision/main.go           создание TPM-ключа и экспорт публичного ключа
cmd/factory/certgen/main.go              выпуск сертификата камеры
cmd/producer/main.go                     запуск producer
cmd/server/main.go                       запуск server
cmd/consumer/main.go                     запуск consumer
internal/app/server/media_hub.go         рассылка потока нескольким consumer
internal/handshake/security_threats_test.go
internal/stream/frame_security_threats_test.go
```

Секретный файл:

```text
artifacts/keys/root_ca2.key
```

Этот ключ нельзя публиковать или хранить в открытом репозитории.
