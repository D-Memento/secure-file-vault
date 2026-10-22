# Отчёт о готовности

Дата: 22 октября 2026 года (Asia/Yerevan).

## Реально выполнено

- Компиляция всех исходников на Java 21.
- Полная Maven-сборка `clean verify`: **BUILD SUCCESS**.
- **32 теста JUnit 5: успешно 32, ошибок 0, провалов 0, пропусков 0.**
- Создан `dist/secure-file-vault-1.0.0.jar` размером около 41 КиБ. Это JAR приложения без внешних зависимостей внутри; запуск через Maven описан в README.
- Безэкранная проверка JavaFX через Monocle: создание, блокировка, неверный пароль, успешная разблокировка и запрос закрытия — успешно.
- Большой файл 72 МиБ зашифрован, проверен и восстановлен с точным совпадением при `-Xmx256m`.
- Смоделированный отказ INSERT в SQLite оставляет исходник и проверенную зашифрованную копию, не создавая запись.

Среда: Linux x86_64, Amazon Corretto 21.0.12, Maven 3.9.11. Из-за ограничений среды Maven-зависимости предварительно загружены из Maven Central в локальный репозиторий, затем сборка выполнена офлайн. Временный каталог JVM перенаправлен в доступную рабочую папку. Это настройки среды проверки; они не включены в пользовательский `pom.xml` и не нужны на обычной машине.

Фактическая команда проверки в этой среде: `mvn -o -s <настройки локального репозитория> -B -e clean verify`, с JDK 21 в `JAVA_HOME` и доступным `java.io.tmpdir`. До подготовки среды были ошибки доступа к зависимостям и временному каталогу; окончательный результат выше относится к успешному полному прогону.

Логи: `verification/maven-verify.log`, `verification/junit-summary.txt`, `verification/ui-smoke.log`. В Maven-логе корень временной рабочей среды заменён на `<workspace>`; результат и сообщения не изменены. В безэкранном запуске JavaFX выдаёт предупреждение о загрузке с classpath; проверка после него успешно завершилась. Обычный запуск выполняет JavaFX Maven plugin.

## Реализованные функции

Создание одного локального хранилища; проверка подтверждения и длины пароля; Argon2id и двухуровневая защита ключей; AES-256-GCM файлов и исходных имён; SQLite с одной прикладной таблицей; список; добавление с обратной проверкой; восстановление с проверкой тега; подтверждаемое удаление; явная и автоматическая блокировка; фоновые операции; ожидание операции перед закрытием; защита от повторного запуска; проверка путей и формата; обнаружение отсутствующих и неучтённых файлов; понятные сообщения об ошибках.

## Что не подтверждено и какие ограничения остаются

- Нативные диалоги выбора/сохранения, визуальный вид окон на Windows/macOS/Linux и реальное ожидание пяти минут автоблокировки не проверялись на физическом рабочем столе. Логика интерфейса проверена безэкранно; ручной сценарий есть в README.
- Отказы физического носителя, отключение питания, заполненный диск и все варианты ACL не моделировались. Между SQLite и файловой системой нет общей атомарной транзакции. Порядок операций, остаточные файлы и восстановление подробно описаны в README.
- Экспорт использует временный открытый файл. После принудительного завершения он может остаться. Защита от вредоносного ПО, полного чтения памяти и отката хранилища не заявляется.
- Нет автономного установщика, смены/сброса пароля и независимого аудита безопасности. Исходники и Maven-проект готовы к сборке и учебной демонстрации.
- В интерфейсе нет заглушек. Непроверенные сценарии выше — предел фактической проверки, а не заменённые описанием функции.

## Перечень выполненных тестов

| Тест | Результат |
|---|---|
| `rejectsWrongPasswordWithoutChangingData` | Пройден |
| `missingSourceDoesNotCreateRecord` | Пройден |
| `largeFileUsesStreamingRoundTrip` | Пройден |
| `noncesDifferForRepeatedFile` | Пройден |
| `roundTripTextAndKeepOriginal` | Пройден |
| `invalidTagPreservesExistingDestination` | Пройден |
| `unreferencedEncryptedFilesAreNotDeletedAtStartup` | Пройден |
| `createsCompleteVault` | Пройден |
| `incompleteExistingDirectoryNeverOverwritten` | Пройден |
| `binaryRoundTrip` | Пройден |
| `swappedCiphertextsFailAuthentication` | Пройден |
| `tamperingNeverPublishesPlaintext` | Пройден |
| `malformedConfigRejectedWithoutChanges` | Пройден |
| `missingCiphertextReportedAndRecordRetained` | Пройден |
| `lockPreventsOperations` | Пройден |
| `rejectWeakOrUnconfirmedPasswordWithoutPartialVault` | Пройден |
| `unlocksWithCorrectPassword` | Пройден |
| `missingDatabaseNeverRecreated` | Пройден |
| `traversalStorageNameRejected` | Пройден |
| `emptyFileRoundTrip` | Пройден |
| `secretsNotStoredInConfigOrDatabase` | Пройден |
| `processLockPreventsSecondInstance` | Пройден |
| `databaseInsertFailurePreservesOriginalAndEncryptedCopy` | Пройден |
| `swappedEncryptedNamesFailAuthentication` | Пройден |
| `databaseInsertSelectDelete` | Пройден |
| `duplicateConfigFieldsRejected` | Пройден |
| `deleteKeepsOriginalAndRemovesRecordAndCiphertext` | Пройден |
| `overwriteRequiresPermission` | Пройден |
| `hostileKdfParametersRejectedBeforeAllocation` | Пройден |
| `cannotRestoreOverVaultConfiguration` | Пройден |
| `truncatedHeaderRejected` | Пройден |
| `corruptDatabaseRejected` | Пройден |
