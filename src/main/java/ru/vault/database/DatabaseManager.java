package ru.vault.database;

import java.nio.file.Path;
import java.sql.*;
import java.util.*;
import ru.vault.service.SafeFiles;

public final class DatabaseManager {
    private DatabaseManager() {}

    public static void create(Path path) throws Exception {
        if (java.nio.file.Files.exists(path)) throw new SQLException("База уже существует.");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + path)) {
            try (var statement = connection.createStatement()) {
                statement.execute("PRAGMA journal_mode=DELETE");
                statement.execute("PRAGMA synchronous=FULL");
                statement.execute("CREATE TABLE StoredFile (id INTEGER PRIMARY KEY AUTOINCREMENT, storage_name TEXT NOT NULL UNIQUE, original_name_enc BLOB NOT NULL)");
                statement.execute("PRAGMA user_version=1");
            }
        }
        SafeFiles.restrict(path, false);
    }

    public static Connection open(Path path) throws Exception {
        SafeFiles.regular(path);
        Connection connection = DriverManager.getConnection("jdbc:sqlite:" + path.toUri() + "?mode=rw");
        try {
            try (var statement = connection.createStatement()) {
                statement.execute("PRAGMA trusted_schema=OFF");
                statement.execute("PRAGMA busy_timeout=5000");
                statement.execute("PRAGMA synchronous=FULL");
                try (var result = statement.executeQuery("PRAGMA quick_check")) {
                    if (!result.next() || !"ok".equals(result.getString(1)) || result.next())
                        throw new SQLException("Нарушена целостность базы данных.");
                }
                try (var result = statement.executeQuery("PRAGMA user_version")) {
                    if (!result.next() || result.getInt(1) != 1) throw new SQLException("Неподдерживаемая версия базы данных.");
                }
                List<String> columns = new ArrayList<>();
                try (var result = statement.executeQuery("PRAGMA table_info(StoredFile)")) {
                    while (result.next()) columns.add(result.getString("name") + ":" + result.getString("type")
                            + ":" + result.getInt("notnull") + ":" + result.getInt("pk"));
                }
                if (!columns.equals(List.of("id:INTEGER:0:1", "storage_name:TEXT:1:0", "original_name_enc:BLOB:1:0")))
                    throw new SQLException("Схема базы данных не соответствует формату хранилища.");
                boolean uniqueStorage = false;
                try (var indexes = connection.prepareStatement("SELECT name FROM pragma_index_list('StoredFile') WHERE \"unique\"=1 AND partial=0");
                     var indexRows = indexes.executeQuery()) {
                    while (indexRows.next()) {
                        try (var info = connection.prepareStatement("SELECT name FROM pragma_index_info(?) ORDER BY seqno")) {
                            info.setString(1, indexRows.getString(1));
                            try (var names = info.executeQuery()) {
                                if (names.next() && "storage_name".equals(names.getString(1)) && !names.next()) uniqueStorage = true;
                            }
                        }
                    }
                }
                if (!uniqueStorage) throw new SQLException("Отсутствует ограничение уникальности имён хранения.");
                try (var result = statement.executeQuery("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")) {
                    int count = 0;
                    while (result.next()) {
                        if (!"table".equals(result.getString(1)) || !"StoredFile".equals(result.getString(2)))
                            throw new SQLException("Обнаружены посторонние объекты базы данных.");
                        count++;
                    }
                    if (count != 1) throw new SQLException("Некорректная схема базы данных.");
                }
            }
            return connection;
        } catch (Exception e) {
            connection.close();
            throw e;
        }
    }
}
