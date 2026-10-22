package ru.vault.model;

public record FileEntry(long id, String storageName, String originalName) {
    @Override public String toString() { return originalName; }
}
