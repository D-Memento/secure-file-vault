package ru.vault.crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public final class KeyDerivationService {
    public static final int MEMORY_KIB = 65536, ITERATIONS = 3, PARALLELISM = 1;

    public byte[] derive(char[] password, byte[] salt) {
        if (password == null || password.length > 1024 || salt.length != 16)
            throw new IllegalArgumentException("Некорректные параметры получения ключа.");
        var parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13).withSalt(salt)
                .withMemoryAsKB(MEMORY_KIB).withIterations(ITERATIONS).withParallelism(PARALLELISM).build();
        var generator = new Argon2BytesGenerator();
        try {
            generator.init(parameters);
            byte[] key = new byte[32];
            generator.generateBytes(password, key);
            return key;
        } finally {
            parameters.clear();
        }
    }
}
