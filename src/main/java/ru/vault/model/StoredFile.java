package ru.vault.model;

public record StoredFile(long id, String storageName, byte[] originalNameEnc) {}
