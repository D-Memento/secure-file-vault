package ru.vault.crypto;

import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.StringReader;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.util.*;

public final class VaultKeyService {
    private final KeyDerivationService kdf = new KeyDerivationService();
    private final FileEncryptionService crypto = new FileEncryptionService();
    private static final String CONTEXT = "vault-key:1:65536:3:1";
    private static final Gson JSON = new GsonBuilder().setStrictness(Strictness.STRICT).setPrettyPrinting().create();
    private static final Set<String> FIELDS = Set.of("version", "salt", "memoryKiB", "iterations", "parallelism", "wrappedKey");

    public byte[] create(Path config, char[] password) throws Exception {
        if (password.length < 12 || password.length > 1024)
            throw new IllegalArgumentException("Пароль должен содержать от 12 до 1024 символов.");
        byte[] salt = FileEncryptionService.random(16), key = FileEncryptionService.random(32);
        byte[] wrapping = kdf.derive(password, salt);
        boolean success = false;
        try {
            var obj = new JsonObject();
            obj.addProperty("version", 1);
            obj.addProperty("salt", Base64.getEncoder().encodeToString(salt));
            obj.addProperty("memoryKiB", KeyDerivationService.MEMORY_KIB);
            obj.addProperty("iterations", KeyDerivationService.ITERATIONS);
            obj.addProperty("parallelism", KeyDerivationService.PARALLELISM);
            obj.addProperty("wrappedKey", Base64.getEncoder().encodeToString(crypto.encryptBytes(key, wrapping, CONTEXT)));
            Files.writeString(config, JSON.toJson(obj), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
            success = true;
            return key;
        } finally {
            Arrays.fill(wrapping, (byte) 0);
            if (!success) Arrays.fill(key, (byte) 0);
        }
    }

    public byte[] unlock(Path config, char[] password) throws Exception {
        JsonObject obj;
        byte[] salt, wrapped;
        try {
            if (Files.size(config) > 4096) throw new IOException();
            obj = readConfig(Files.readString(config, StandardCharsets.UTF_8));
            if (obj == null || !obj.keySet().equals(FIELDS)
                    || !obj.get("version").getAsString().equals("1")
                    || !obj.get("memoryKiB").getAsString().equals("65536")
                    || !obj.get("iterations").getAsString().equals("3")
                    || !obj.get("parallelism").getAsString().equals("1")) throw new IOException();
            salt = Base64.getDecoder().decode(obj.get("salt").getAsString());
            wrapped = Base64.getDecoder().decode(obj.get("wrappedKey").getAsString());
            if (salt.length != 16 || wrapped.length != 64) throw new IOException();
        } catch (Exception e) {
            throw new IOException("Конфигурация повреждена или её версия не поддерживается.", e);
        }
        byte[] wrapping = kdf.derive(password, salt);
        try {
            byte[] key = crypto.decryptBytes(wrapped, wrapping, CONTEXT);
            if (key.length != 32) throw new IOException("Повреждён ключ хранилища.");
            return key;
        } finally {
            Arrays.fill(wrapping, (byte) 0);
        }
    }

    private static JsonObject readConfig(String text) throws IOException {
        try (var reader = new JsonReader(new StringReader(text))) {
            reader.setStrictness(Strictness.STRICT);
            var result = new JsonObject();
            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName();
                if (result.has(name)) throw new IOException("Повтор поля конфигурации.");
                JsonElement value = JSON.fromJson(reader, JsonElement.class);
                if (!value.isJsonPrimitive()) throw new IOException("Неверный тип поля конфигурации.");
                boolean numeric = Set.of("version", "memoryKiB", "iterations", "parallelism").contains(name);
                if (numeric ? !value.getAsJsonPrimitive().isNumber() : !value.getAsJsonPrimitive().isString())
                    throw new IOException("Неверный тип поля конфигурации.");
                result.add(name, value);
            }
            reader.endObject();
            if (reader.peek() != JsonToken.END_DOCUMENT) throw new IOException("Лишние данные в конфигурации.");
            return result;
        }
    }
}
