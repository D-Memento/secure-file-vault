package ru.vault.service;

import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import ru.vault.crypto.FileEncryptionService;
import ru.vault.model.*;

public final class FileService {
    private final VaultService vault;
    private final FileEncryptionService crypto = new FileEncryptionService();
    public FileService(VaultService vault) { this.vault = vault; }

    public List<FileEntry> list() throws Exception {
        synchronized (vault) {
            var result = new ArrayList<FileEntry>();
            for (StoredFile row : vault.repository().list()) {
                Path stored = SafeFiles.stored(vault.root().resolve("files"), row.storageName());
                byte[] plain = crypto.decryptBytes(row.originalNameEnc(), vault.key(), "name:" + row.storageName());
                try {
                    String name = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                            .decode(java.nio.ByteBuffer.wrap(plain)).toString();
                    validateName(name);
                    result.add(new FileEntry(row.id(), row.storageName(), name));
                } finally { Arrays.fill(plain, (byte) 0); }
                if (Files.exists(stored, LinkOption.NOFOLLOW_LINKS) && Files.isSymbolicLink(stored))
                    throw new IOException("Зашифрованный файл подменён ссылкой.");
            }
            return result;
        }
    }

    public String health() throws Exception {
        synchronized (vault) {
            Set<String> referenced = new HashSet<>();
            int missing = 0, extra = 0;
            for (var row : vault.repository().list()) {
                Path path = SafeFiles.stored(vault.root().resolve("files"), row.storageName());
                referenced.add(row.storageName());
                if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) < 32) missing++;
            }
            try (var files = Files.list(vault.root().resolve("files"))) {
                for (var path : files.toList()) if (!referenced.contains(path.getFileName().toString())) extra++;
            }
            return missing == 0 && extra == 0 ? "Хранилище открыто. Целостность содержимого проверяется при восстановлении."
                    : "Внимание: отсутствующих/повреждённых файлов: " + missing + "; файлов вне базы: " + extra
                      + ". Ничего не удалено. См. README: восстановление после сбоя.";
        }
    }

    public void add(Path source) throws Exception {
        synchronized (vault) {
            vault.key();
            SafeFiles.regular(source);
            if (!Files.isReadable(source)) throw new IOException("Нет прав на чтение исходного файла.");
            if (source.toRealPath().startsWith(vault.root().toRealPath()))
                throw new IOException("Нельзя добавлять служебные файлы самого хранилища.");
            String original = source.getFileName().toString();
            validateName(original);
            if (Files.size(source) > FileEncryptionService.MAX_PLAINTEXT) throw new IOException("Файл больше предела AES-GCM.");
            String storage = UUID.randomUUID() + ".enc";
            Path directory = vault.root().resolve("files"), target = SafeFiles.stored(directory, storage);
            SafeFiles.directory(directory);
            Path temp = SafeFiles.temp(directory, ".part");
            try {
                byte[] digest;
                try (var input = Files.newInputStream(source, LinkOption.NOFOLLOW_LINKS);
                     var output = Files.newOutputStream(temp)) {
                    digest = crypto.transform(input, output, vault.key(), "file:" + storage, true);
                }
                SafeFiles.force(temp);
                byte[] verified;
                try (var input = Files.newInputStream(temp)) {
                    verified = crypto.transform(input, OutputStream.nullOutputStream(), vault.key(), "file:" + storage, false);
                }
                if (!MessageDigest.isEqual(digest, verified)) throw new IOException("Проверка зашифрованной копии не пройдена.");
                byte[] name = original.getBytes(StandardCharsets.UTF_8);
                byte[] encryptedName;
                try { encryptedName = crypto.encryptBytes(name, vault.key(), "name:" + storage); }
                finally { Arrays.fill(name, (byte) 0); }
                SafeFiles.publishNew(temp, target);
                try { vault.repository().insert(storage, encryptedName); }
                catch (Exception e) {
                    throw new IOException("Ошибка записи в базу. Проверенная зашифрованная копия сохранена: " + storage
                            + ". Исходник не изменён. См. README.", e);
                }
            } finally { Files.deleteIfExists(temp); }
        }
    }

    public void restore(FileEntry entry, Path destination, boolean overwrite) throws Exception {
        synchronized (vault) {
            requireEntry(entry);
            Path source = SafeFiles.stored(vault.root().resolve("files"), entry.storageName());
            SafeFiles.regular(source);
            Path absolute = destination.toAbsolutePath().normalize();
            Path parent = absolute.getParent().toRealPath();
            Path target = parent.resolve(absolute.getFileName());
            if (target.startsWith(vault.root().toRealPath()) || target.equals(vault.root().resolveSibling("." + vault.root().getFileName() + ".lock")))
                throw new IOException("Нельзя восстанавливать файлы внутрь хранилища или поверх его блокировки.");
            if (Files.isSymbolicLink(target)) throw new IOException("Нельзя восстанавливать поверх символической ссылки.");
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                SafeFiles.regular(target);
                if (!overwrite) throw new FileAlreadyExistsException(target.toString());
            }
            Path temp = SafeFiles.temp(parent, ".restore");
            try {
                try (var input = Files.newInputStream(source, LinkOption.NOFOLLOW_LINKS);
                     var output = Files.newOutputStream(temp)) {
                    crypto.transform(input, output, vault.key(), "file:" + entry.storageName(), false);
                }
                SafeFiles.force(temp);
                if (overwrite) SafeFiles.publishReplacement(temp, target);
                else SafeFiles.publishNew(temp, target);
            } finally { Files.deleteIfExists(temp); }
        }
    }

    public void delete(FileEntry entry) throws Exception {
        synchronized (vault) {
            requireEntry(entry);
            Path source = SafeFiles.stored(vault.root().resolve("files"), entry.storageName());
            SafeFiles.regular(source);
            vault.repository().delete(entry.id(), entry.storageName());
            try { Files.delete(source); }
            catch (IOException e) {
                throw new IOException("Запись удалена, но зашифрованная копия осталась: " + entry.storageName()
                        + ". Освободите доступ к файлу и удалите его вручную после резервного копирования. См. README.", e);
            }
        }
    }

    private void requireEntry(FileEntry entry) throws Exception {
        if (vault.repository().list().stream().noneMatch(row -> row.id() == entry.id() && row.storageName().equals(entry.storageName())))
            throw new IOException("Запись отсутствует или изменилась. Откройте хранилище заново.");
    }

    private static void validateName(String name) throws IOException {
        if (name.isBlank() || name.equals(".") || name.equals("..") || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0
                || name.indexOf('\0') >= 0 || name.getBytes(StandardCharsets.UTF_8).length > 4096)
            throw new IOException("Недопустимое исходное имя файла.");
    }
}
