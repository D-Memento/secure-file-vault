package ru.vault.crypto;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public final class FileEncryptionService {
    private static final byte[] MAGIC = {'S', 'F', 'V', 1};
    private static final SecureRandom RANDOM = new SecureRandom();
    public static final long MAX_PLAINTEXT = (1L << 36) - 32;

    public static byte[] random(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    public byte[] encryptBytes(byte[] input, byte[] key, String context) throws Exception {
        var out = new ByteArrayOutputStream();
        transform(new ByteArrayInputStream(input), out, key, context, true);
        return out.toByteArray();
    }

    public byte[] decryptBytes(byte[] input, byte[] key, String context) throws Exception {
        if (input.length > 16384) throw new IOException("Слишком большой блок метаданных.");
        var out = new ByteArrayOutputStream();
        transform(new ByteArrayInputStream(input), out, key, context, false);
        return out.toByteArray();
    }

    public byte[] transform(InputStream input, OutputStream output, byte[] key, String context,
                            boolean encrypt) throws Exception {
        if (key.length != 32) throw new IllegalArgumentException("Неверная длина ключа.");
        byte[] header;
        if (encrypt) {
            header = new byte[16];
            System.arraycopy(MAGIC, 0, header, 0, 4);
            System.arraycopy(random(12), 0, header, 4, 12);
            output.write(header);
        } else {
            header = input.readNBytes(16);
            if (header.length != 16 || !Arrays.equals(MAGIC, Arrays.copyOf(header, 4)))
                throw new IOException("Повреждён заголовок зашифрованного файла.");
        }
        var cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        cipher.init(encrypt, new AEADParameters(new KeyParameter(key), 128, Arrays.copyOfRange(header, 4, 16)));
        cipher.processAADBytes(header, 0, header.length);
        byte[] aad = context.getBytes(StandardCharsets.UTF_8);
        cipher.processAADBytes(aad, 0, aad.length);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] in = new byte[65536], out = new byte[65568];
        long total = 0;
        try {
            int n;
            while ((n = input.read(in)) != -1) {
                if (Thread.currentThread().isInterrupted()) throw new InterruptedIOException("Операция прервана.");
                total += n;
                if (total > MAX_PLAINTEXT + (encrypt ? 0 : 16))
                    throw new IOException("Превышен предел размера AES-GCM (около 64 ГиБ).");
                if (encrypt) digest.update(in, 0, n);
                int produced = cipher.processBytes(in, 0, n, out, 0);
                output.write(out, 0, produced);
                if (!encrypt) digest.update(out, 0, produced);
            }
            int produced = cipher.doFinal(out, 0);
            output.write(out, 0, produced);
            if (!encrypt) digest.update(out, 0, produced);
            return digest.digest();
        } catch (InvalidCipherTextException e) {
            throw new GeneralSecurityException("Неверный пароль или нарушена целостность данных.", e);
        } finally {
            Arrays.fill(in, (byte) 0);
            Arrays.fill(out, (byte) 0);
            cipher.reset();
        }
    }
}
