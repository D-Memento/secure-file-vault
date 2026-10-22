package ru.vault.database;

import java.sql.*;
import java.util.*;
import ru.vault.model.StoredFile;

public final class StoredFileRepository {
    private final Connection connection;
    public StoredFileRepository(Connection connection) { this.connection = connection; }

    public List<StoredFile> list() throws SQLException {
        var rows = new ArrayList<StoredFile>();
        try (var statement = connection.prepareStatement("SELECT id, storage_name, original_name_enc FROM StoredFile ORDER BY id");
             var result = statement.executeQuery()) {
            while (result.next()) {
                byte[] name = result.getBytes(3);
                if (name == null || name.length < 32 || name.length > 16384)
                    throw new SQLException("Повреждены метаданные имени файла.");
                rows.add(new StoredFile(result.getLong(1), result.getString(2), name));
            }
        }
        return rows;
    }

    public void insert(String storageName, byte[] encryptedName) throws SQLException {
        try (var statement = connection.prepareStatement("INSERT INTO StoredFile(storage_name,original_name_enc) VALUES (?,?)")) {
            statement.setString(1, storageName);
            statement.setBytes(2, encryptedName);
            if (statement.executeUpdate() != 1) throw new SQLException("Не удалось добавить запись.");
        }
    }

    public void delete(long id, String storageName) throws SQLException {
        try (var statement = connection.prepareStatement("DELETE FROM StoredFile WHERE id=? AND storage_name=?")) {
            statement.setLong(1, id);
            statement.setString(2, storageName);
            if (statement.executeUpdate() != 1) throw new SQLException("Запись уже отсутствует или изменена.");
        }
    }
}
