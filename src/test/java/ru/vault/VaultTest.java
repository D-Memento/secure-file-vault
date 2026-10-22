package ru.vault;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import ru.vault.crypto.*;
import ru.vault.database.*;
import ru.vault.model.FileEntry;
import ru.vault.service.*;
import static org.junit.jupiter.api.Assertions.*;

class VaultTest {
    @TempDir Path directory;
    private static final String PASSWORD = "correct horse battery staple 42";
    private Path root;
    private VaultService vault;
    private FileService files;

    @BeforeEach void prepare() throws Exception {
        root = directory.resolve("SecureFileVault");
        vault = new VaultService(root);
        files = new FileService(vault);
    }
    @AfterEach void close() throws Exception { if (vault != null) vault.close(); }
    private void create() throws Exception { vault.create(PASSWORD.toCharArray(), PASSWORD.toCharArray()); }
    private Path input(byte[] data) throws Exception {
        Path path = directory.resolve("секретный-документ.bin");
        Files.write(path, data);
        return path;
    }
    private FileEntry add(byte[] data) throws Exception {
        files.add(input(data));
        return files.list().getLast();
    }
    private Path encrypted(FileEntry entry) { return root.resolve("files").resolve(entry.storageName()); }

    @Test void createsCompleteVault() throws Exception {
        create();
        assertTrue(vault.isUnlocked());
        assertTrue(Files.isRegularFile(root.resolve("vault_config.json")));
        assertTrue(Files.isRegularFile(root.resolve("vault.db")));
        assertTrue(Files.isDirectory(root.resolve("files")));
        assertTrue(files.list().isEmpty());
    }
    @Test void unlocksWithCorrectPassword() throws Exception {
        create(); vault.lock();
        assertFalse(vault.isUnlocked());
        vault.unlock(PASSWORD.toCharArray());
        assertTrue(vault.isUnlocked());
    }
    @Test void rejectsWrongPasswordWithoutChangingData() throws Exception {
        create(); FileEntry entry = add(new byte[]{1, 2, 3}); vault.lock();
        byte[] config = Files.readAllBytes(root.resolve("vault_config.json"));
        byte[] data = Files.readAllBytes(encrypted(entry));
        assertThrows(GeneralSecurityException.class, () -> vault.unlock("wrong password".toCharArray()));
        assertFalse(vault.isUnlocked());
        assertArrayEquals(config, Files.readAllBytes(root.resolve("vault_config.json")));
        assertArrayEquals(data, Files.readAllBytes(encrypted(entry)));
    }
    @Test void roundTripTextAndKeepOriginal() throws Exception {
        create(); byte[] data = "Секретный текст 🛡\n".repeat(5000).getBytes(StandardCharsets.UTF_8);
        FileEntry entry = add(data);
        Path destination = directory.resolve("restored.txt");
        files.restore(entry, destination, false);
        assertArrayEquals(data, Files.readAllBytes(destination));
        assertArrayEquals(data, Files.readAllBytes(directory.resolve("секретный-документ.bin")));
        assertFalse(Arrays.equals(data, Files.readAllBytes(encrypted(entry))));
    }
    @Test void emptyFileRoundTrip() throws Exception {
        create(); FileEntry entry = add(new byte[0]);
        Path out = directory.resolve("empty"); files.restore(entry, out, false);
        assertEquals(0, Files.size(out)); assertEquals(32, Files.size(encrypted(entry)));
    }
    @Test void binaryRoundTrip() throws Exception {
        create(); byte[] data = new byte[200000]; new Random(17).nextBytes(data);
        FileEntry entry = add(data); Path out = directory.resolve("binary");
        files.restore(entry, out, false); assertArrayEquals(data, Files.readAllBytes(out));
    }
    @Test void tamperingNeverPublishesPlaintext() throws Exception {
        create(); FileEntry entry = add(new byte[200000]);
        byte[] ciphertext = Files.readAllBytes(encrypted(entry)); ciphertext[50] ^= 1;
        Files.write(encrypted(entry), ciphertext);
        Path out = directory.resolve("out");
        assertThrows(GeneralSecurityException.class, () -> files.restore(entry, out, false));
        assertFalse(Files.exists(out));
        try (var paths = Files.list(directory)) { assertTrue(paths.noneMatch(p -> p.toString().endsWith(".restore"))); }
    }
    @Test void invalidTagPreservesExistingDestination() throws Exception {
        create(); FileEntry entry = add(new byte[]{1, 2});
        byte[] bytes = Files.readAllBytes(encrypted(entry)); bytes[bytes.length - 1] ^= 1;
        Files.write(encrypted(entry), bytes);
        Path out = directory.resolve("existing"); Files.writeString(out, "keep me");
        assertThrows(GeneralSecurityException.class, () -> files.restore(entry, out, true));
        assertEquals("keep me", Files.readString(out));
    }
    @Test void overwriteRequiresPermission() throws Exception {
        create(); FileEntry entry = add(new byte[]{42});
        Path out = directory.resolve("existing"); Files.write(out, new byte[]{24});
        assertThrows(FileAlreadyExistsException.class, () -> files.restore(entry, out, false));
        assertArrayEquals(new byte[]{24}, Files.readAllBytes(out));
        files.restore(entry, out, true); assertArrayEquals(new byte[]{42}, Files.readAllBytes(out));
    }
    @Test void databaseInsertSelectDelete() throws Exception {
        create();
        try (var connection = DatabaseManager.open(root.resolve("vault.db"))) {
            var repository = new StoredFileRepository(connection);
            String name = UUID.randomUUID() + ".enc";
            repository.insert(name, new byte[32]);
            var rows = repository.list(); assertEquals(1, rows.size());
            assertEquals(name, rows.getFirst().storageName());
            repository.delete(rows.getFirst().id(), name); assertTrue(repository.list().isEmpty());
        }
    }
    @Test void deleteKeepsOriginalAndRemovesRecordAndCiphertext() throws Exception {
        create(); FileEntry entry = add(new byte[]{1}); files.delete(entry);
        assertTrue(files.list().isEmpty()); assertFalse(Files.exists(encrypted(entry)));
        assertTrue(Files.exists(directory.resolve("секретный-документ.bin")));
    }
    @Test void secretsNotStoredInConfigOrDatabase() throws Exception {
        create(); FileEntry entry = add(new byte[]{1});
        String config = Files.readString(root.resolve("vault_config.json"));
        byte[] key = new VaultKeyService().unlock(root.resolve("vault_config.json"), PASSWORD.toCharArray());
        try {
            assertFalse(config.contains(PASSWORD));
            assertFalse(config.contains(Base64.getEncoder().encodeToString(key)));
            assertFalse(config.contains(HexFormat.of().formatHex(key)));
        } finally { Arrays.fill(key, (byte) 0); }
        assertFalse(new String(Files.readAllBytes(root.resolve("vault.db")), StandardCharsets.UTF_8).contains(entry.originalName()));
    }
    @Test void rejectWeakOrUnconfirmedPasswordWithoutPartialVault() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> vault.create("short".toCharArray(), "short".toCharArray()));
        assertFalse(Files.exists(root));
        assertThrows(IllegalArgumentException.class, () -> vault.create(PASSWORD.toCharArray(), "different".toCharArray()));
        assertFalse(Files.exists(root));
    }
    @Test void missingDatabaseNeverRecreated() throws Exception {
        create(); vault.lock(); Files.delete(root.resolve("vault.db"));
        assertThrows(IOException.class, () -> vault.unlock(PASSWORD.toCharArray()));
        assertFalse(Files.exists(root.resolve("vault.db"))); assertFalse(vault.isUnlocked());
    }
    @Test void corruptDatabaseRejected() throws Exception {
        create(); vault.lock(); Files.writeString(root.resolve("vault.db"), "broken");
        assertThrows(Exception.class, () -> vault.unlock(PASSWORD.toCharArray()));
        assertFalse(vault.isUnlocked()); assertEquals("broken", Files.readString(root.resolve("vault.db")));
    }
    @Test void malformedConfigRejectedWithoutChanges() throws Exception {
        create(); vault.lock(); Files.writeString(root.resolve("vault_config.json"), "{}");
        assertThrows(IOException.class, () -> vault.unlock(PASSWORD.toCharArray()));
        assertEquals("{}", Files.readString(root.resolve("vault_config.json")));
    }
    @Test void hostileKdfParametersRejectedBeforeAllocation() throws Exception {
        create(); vault.lock(); Path config = root.resolve("vault_config.json");
        Files.writeString(config, Files.readString(config).replace("65536", "2147483647"));
        assertThrows(IOException.class, () -> vault.unlock(PASSWORD.toCharArray()));
    }
    @Test void incompleteExistingDirectoryNeverOverwritten() throws Exception {
        Files.createDirectory(root); Files.writeString(root.resolve("keep"), "keep");
        assertThrows(IOException.class, this::create); assertEquals("keep", Files.readString(root.resolve("keep")));
    }
    @Test void processLockPreventsSecondInstance() throws Exception {
        assertThrows(IOException.class, () -> new VaultService(root));
    }
    @Test void lockPreventsOperations() throws Exception {
        create(); vault.lock(); assertThrows(IllegalStateException.class, () -> files.list());
    }
    @Test void missingCiphertextReportedAndRecordRetained() throws Exception {
        create(); FileEntry entry = add(new byte[]{3}); Files.delete(encrypted(entry));
        assertThrows(IOException.class, () -> files.restore(entry, directory.resolve("out"), false));
        assertEquals(1, files.list().size()); assertTrue(files.health().contains("1"));
    }
    @Test void traversalStorageNameRejected() throws Exception {
        create();
        try (var connection = DatabaseManager.open(root.resolve("vault.db"))) {
            new StoredFileRepository(connection).insert("../outside.enc", new byte[32]);
        }
        assertThrows(IOException.class, () -> files.list());
    }
    @Test void cannotRestoreOverVaultConfiguration() throws Exception {
        create(); FileEntry entry = add(new byte[]{1});
        byte[] before = Files.readAllBytes(root.resolve("vault_config.json"));
        assertThrows(IOException.class, () -> files.restore(entry, root.resolve("vault_config.json"), true));
        assertArrayEquals(before, Files.readAllBytes(root.resolve("vault_config.json")));
    }
    @Test void noncesDifferForRepeatedFile() throws Exception {
        create(); FileEntry a = add(new byte[]{5}), b = add(new byte[]{5});
        assertFalse(Arrays.equals(Arrays.copyOfRange(Files.readAllBytes(encrypted(a)), 4, 16),
                Arrays.copyOfRange(Files.readAllBytes(encrypted(b)), 4, 16)));
    }
    @Test void swappedCiphertextsFailAuthentication() throws Exception {
        create(); FileEntry a = add(new byte[]{1}), b = add(new byte[]{2});
        Files.copy(encrypted(a), encrypted(b), StandardCopyOption.REPLACE_EXISTING);
        assertThrows(GeneralSecurityException.class, () -> files.restore(b, directory.resolve("out"), false));
    }
    @Test void missingSourceDoesNotCreateRecord() throws Exception {
        create(); assertThrows(IOException.class, () -> files.add(directory.resolve("missing")));
        assertTrue(files.list().isEmpty());
    }
    @Test void truncatedHeaderRejected() throws Exception {
        create(); FileEntry entry = add(new byte[]{1}); Files.write(encrypted(entry), new byte[]{1, 2});
        assertThrows(IOException.class, () -> files.restore(entry, directory.resolve("out"), false));
        assertFalse(Files.exists(directory.resolve("out")));
    }
    @Test void unreferencedEncryptedFilesAreNotDeletedAtStartup() throws Exception {
        create(); Path orphan = root.resolve("files").resolve(UUID.randomUUID() + ".enc");
        Files.write(orphan, new byte[32]); vault.lock(); vault.unlock(PASSWORD.toCharArray());
        assertTrue(Files.exists(orphan)); assertTrue(files.health().contains("файлов вне базы: 1"));
    }
    @Test void largeFileUsesStreamingRoundTrip() throws Exception {
        create(); Path source = directory.resolve("large.bin");
        byte[] block = new byte[65536]; new Random(42).nextBytes(block);
        try (var out = Files.newOutputStream(source)) { for (int i = 0; i < 1152; i++) out.write(block); }
        files.add(source); Path restored = directory.resolve("large-restored.bin");
        files.restore(files.list().getFirst(), restored, false);
        assertEquals(-1, Files.mismatch(source, restored));
    }

    @Test void duplicateConfigFieldsRejected() throws Exception {
        create(); vault.lock(); Path config = root.resolve("vault_config.json");
        Files.writeString(config, Files.readString(config).replace("{", "{\"version\":1,"));
        assertThrows(IOException.class, () -> vault.unlock(PASSWORD.toCharArray()));
    }
    @Test void swappedEncryptedNamesFailAuthentication() throws Exception {
        create(); add(new byte[]{1}); add(new byte[]{2});
        try (var connection = DatabaseManager.open(root.resolve("vault.db"));
             var statement = connection.prepareStatement("UPDATE StoredFile SET original_name_enc=(SELECT original_name_enc FROM StoredFile WHERE id=1) WHERE id=2")) {
            statement.executeUpdate();
        }
        assertThrows(GeneralSecurityException.class, () -> files.list());
    }

    @Test void databaseInsertFailurePreservesOriginalAndEncryptedCopy() throws Exception {
        create(); Path source = input(new byte[]{9, 8, 7});
        try (var connection = DatabaseManager.open(root.resolve("vault.db")); var statement = connection.createStatement()) {
            statement.execute("CREATE TRIGGER simulated_failure BEFORE INSERT ON StoredFile BEGIN SELECT RAISE(ABORT, 'simulated failure'); END");
            assertThrows(IOException.class, () -> files.add(source));
            statement.execute("DROP TRIGGER simulated_failure");
        }
        assertArrayEquals(new byte[]{9, 8, 7}, Files.readAllBytes(source));
        assertTrue(files.list().isEmpty());
        try (var paths = Files.list(root.resolve("files"))) {
            var remaining = paths.toList();
            assertEquals(1, remaining.size()); assertTrue(remaining.getFirst().toString().endsWith(".enc"));
        }
        assertTrue(files.health().contains("файлов вне базы: 1"));
    }
}
