package ru.vault.service;

import java.io.IOException;
import java.nio.channels.*;
import java.nio.file.*;
import java.sql.Connection;
import java.util.*;
import ru.vault.crypto.VaultKeyService;
import ru.vault.database.*;

public final class VaultService implements AutoCloseable {
    private final Path root;
    private final FileChannel lockChannel;
    private final FileLock processLock;
    private Connection connection;
    private byte[] key;

    public VaultService(Path root) throws Exception {
        this.root = root.toAbsolutePath().normalize();
        SafeFiles.directory(this.root.getParent());
        Path lockPath = this.root.resolveSibling("." + this.root.getFileName() + ".lock");
        if (Files.isSymbolicLink(lockPath)) throw new IOException("Файл блокировки не должен быть ссылкой.");
        lockChannel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        try {
            SafeFiles.restrict(lockPath, false);
            processLock = lockChannel.tryLock();
            if (processLock == null) throw new IOException("Хранилище уже открыто другим экземпляром приложения.");
        } catch (Exception e) {
            lockChannel.close();
            throw new IOException("Не удалось заблокировать хранилище. Возможно, приложение уже запущено.", e);
        }
    }

    public Path root() { return root; }
    public synchronized boolean isUnlocked() { return key != null; }
    public boolean exists() { return Files.exists(root, LinkOption.NOFOLLOW_LINKS); }

    public synchronized void create(char[] password, char[] confirmation) throws Exception {
        if (exists()) throw new IOException("Каталог хранилища уже существует. Данные не перезаписаны.");
        if (!Arrays.equals(password, confirmation)) throw new IllegalArgumentException("Пароли не совпадают.");
        Path staging = Files.createTempDirectory(root.getParent(), ".svf-create-");
        byte[] createdKey = null;
        try {
            SafeFiles.restrict(staging, true);
            Files.createDirectory(staging.resolve("files"));
            SafeFiles.restrict(staging.resolve("files"), true);
            createdKey = new VaultKeyService().create(staging.resolve("vault_config.json"), password);
            SafeFiles.restrict(staging.resolve("vault_config.json"), false);
            DatabaseManager.create(staging.resolve("vault.db"));
            SafeFiles.force(staging.resolve("vault_config.json"));
            SafeFiles.force(staging.resolve("vault.db"));
            SafeFiles.publishNew(staging, root);
            connection = DatabaseManager.open(root.resolve("vault.db"));
            key = createdKey;
            createdKey = null;
        } finally {
            if (createdKey != null) Arrays.fill(createdKey, (byte) 0);
            if (Files.exists(staging)) {
                try (var paths = Files.walk(staging)) {
                    for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
                }
            }
        }
    }

    public synchronized void unlock(char[] password) throws Exception {
        if (isUnlocked()) throw new IllegalStateException("Хранилище уже открыто.");
        SafeFiles.directory(root);
        SafeFiles.directory(root.resolve("files"));
        SafeFiles.regular(root.resolve("vault_config.json"));
        SafeFiles.regular(root.resolve("vault.db"));
        byte[] openedKey = new VaultKeyService().unlock(root.resolve("vault_config.json"), password);
        try {
            connection = DatabaseManager.open(root.resolve("vault.db"));
            key = openedKey;
            openedKey = null;
        } finally {
            if (openedKey != null) Arrays.fill(openedKey, (byte) 0);
        }
    }

    synchronized byte[] key() {
        if (key == null) throw new IllegalStateException("Хранилище заблокировано.");
        return key;
    }

    synchronized StoredFileRepository repository() {
        key();
        return new StoredFileRepository(connection);
    }

    public synchronized void lock() throws Exception {
        try {
            if (connection != null) connection.close();
        } finally {
            connection = null;
            if (key != null) Arrays.fill(key, (byte) 0);
            key = null;
        }
    }

    @Override public synchronized void close() throws Exception {
        try { lock(); }
        finally {
            try { if (processLock.isValid()) processLock.release(); }
            finally { lockChannel.close(); }
        }
    }
}
