package ru.vault.service;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.regex.Pattern;

public final class SafeFiles {
    private static final Pattern STORAGE = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.enc");
    private SafeFiles() {}

    public static void regular(Path path) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Файл отсутствует, недоступен или является ссылкой: " + path.getFileName());
    }

    public static void directory(Path path) throws IOException {
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Каталог отсутствует или является ссылкой: " + path.getFileName());
    }

    public static Path stored(Path directory, String name) throws IOException {
        if (name == null || !STORAGE.matcher(name).matches())
            throw new IOException("Некорректное имя файла в базе данных.");
        return directory.resolve(name);
    }

    public static void restrict(Path path, boolean directory) throws IOException {
        if (Files.getFileAttributeView(path, java.nio.file.attribute.PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS) != null)
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"));
    }

    public static Path temp(Path directory, String suffix) throws IOException {
        if (Files.getFileAttributeView(directory, java.nio.file.attribute.PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS) != null)
            return Files.createTempFile(directory, ".svf-", suffix,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        return Files.createTempFile(directory, ".svf-", suffix);
    }

    public static void force(Path path) throws IOException {
        try (var channel = FileChannel.open(path, StandardOpenOption.WRITE)) { channel.force(true); }
    }

    public static void publishNew(Path source, Path target) throws IOException {
        Files.move(source, target);
    }

    public static void publishReplacement(Path source, Path target) throws IOException {
        Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }
}
