package ru.vault.ui;

import javafx.animation.*;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import javafx.util.Duration;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import ru.vault.model.FileEntry;
import ru.vault.service.*;

public final class VaultController {
    private final Stage stage;
    private final VBox root = new VBox(16);
    private final Label status = new Label();
    private final ProgressIndicator progress = new ProgressIndicator();
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ListView<FileEntry> list = new ListView<>();
    private final Timeline idle;
    private VaultService vault;
    private FileService files;
    private Pane actions;
    private boolean busy, closing, closeScheduled;
    private long activity = System.nanoTime();
    private static final long IDLE_NANOS = TimeUnit.MINUTES.toNanos(5);
    private record Snapshot(List<FileEntry> entries, String health) {}

    public VaultController(Stage stage) {
        this.stage = stage;
        root.setPadding(new Insets(24));
        status.setWrapText(true);
        progress.setMaxSize(26, 26);
        progress.setVisible(false);
        Scene scene = new Scene(root, 840, 530);
        scene.addEventFilter(MouseEvent.ANY, event -> activity = System.nanoTime());
        scene.addEventFilter(KeyEvent.ANY, event -> activity = System.nanoTime());
        stage.setTitle("Защищённое файловое хранилище");
        stage.setMinWidth(720);
        stage.setMinHeight(450);
        stage.setScene(scene);
        stage.setOnCloseRequest(event -> {
            event.consume();
            closing = true;
            if (busy) status.setText("Закрытие после безопасного завершения текущей операции…");
            else closeNow();
        });
        idle = new Timeline(new KeyFrame(Duration.seconds(5), event -> {
            if (!busy && vault != null && vault.isUnlocked() && System.nanoTime() - activity >= IDLE_NANOS) lock();
        }));
        idle.setCycleCount(Animation.INDEFINITE);
        try {
            vault = new VaultService(Path.of(System.getProperty("user.home"), "SecureFileVault"));
            files = new FileService(vault);
            auth();
            idle.play();
        } catch (Exception e) {
            root.getChildren().setAll(new Label("Не удалось открыть приложение"), status);
            status.setText(message(e));
        }
        stage.show();
    }

    private void auth() {
        list.getItems().clear();
        boolean setup = !vault.exists();
        Label title = new Label(setup ? "Создание защищённого хранилища" : "Разблокировка хранилища");
        title.setStyle("-fx-font-size: 23px; -fx-font-weight: bold;");
        PasswordField password = new PasswordField();
        password.setPromptText(setup ? "Пароль: минимум 12 символов" : "Пароль");
        PasswordField confirmation = new PasswordField();
        confirmation.setPromptText("Повторите пароль");
        Button submit = new Button(setup ? "Создать хранилище" : "Разблокировать");
        submit.setDefaultButton(true);
        VBox form = new VBox(12, password);
        if (setup) form.getChildren().add(confirmation);
        form.getChildren().add(submit);
        form.setMaxWidth(440);
        actions = form;
        status.setText(setup ? "Используйте длинную уникальную парольную фразу. Восстановление забытого пароля невозможно."
                : "Введите пароль. Повреждённые или неполные данные не будут перезаписаны.");
        Label path = new Label("Данные: " + vault.root());
        path.setWrapText(true);
        root.getChildren().setAll(title, path, form, progress, status);
        submit.setOnAction(event -> {
            char[] first = password.getText().toCharArray(), second = confirmation.getText().toCharArray();
            password.clear();
            confirmation.clear();
            run(() -> {
                try {
                    if (setup) vault.create(first, second); else vault.unlock(first);
                    try { return snapshot(); }
                    catch (Exception e) { vault.lock(); throw e; }
                } finally { Arrays.fill(first, '\0'); Arrays.fill(second, '\0'); }
            }, this::main);
        });
        password.requestFocus();
    }

    private Snapshot snapshot() throws Exception { return new Snapshot(files.list(), files.health()); }

    private void main(Snapshot snapshot) {
        Label title = new Label("Защищённое файловое хранилище");
        title.setStyle("-fx-font-size: 23px; -fx-font-weight: bold;");
        list.getItems().setAll(snapshot.entries());
        list.setPlaceholder(new Label("Пока нет файлов. Добавьте первый файл."));
        Button add = new Button("Добавить файл"), restore = new Button("Восстановить файл");
        Button delete = new Button("Удалить из хранилища"), lock = new Button("Заблокировать");
        restore.disableProperty().bind(list.getSelectionModel().selectedItemProperty().isNull());
        delete.disableProperty().bind(list.getSelectionModel().selectedItemProperty().isNull());
        FlowPane buttons = new FlowPane(10, 10, add, restore, delete, lock);
        VBox content = new VBox(12, list, buttons);
        VBox.setVgrow(list, Priority.ALWAYS);
        VBox.setVgrow(content, Priority.ALWAYS);
        actions = content;
        root.getChildren().setAll(title, content, progress, status);
        status.setText(snapshot.health());
        add.setOnAction(event -> {
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Выберите файл для шифрования");
            var source = chooser.showOpenDialog(stage);
            if (source != null) run(() -> { files.add(source.toPath()); return snapshot(); }, result -> {
                main(result); status.setText("Файл добавлен и проверен. Исходный файл сохранён.");
            });
        });
        restore.setOnAction(event -> {
            FileEntry entry = list.getSelectionModel().getSelectedItem();
            if (entry == null) return;
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Восстановить файл");
            chooser.setInitialFileName(entry.originalName());
            var destination = chooser.showSaveDialog(stage);
            if (destination == null) return;
            boolean overwrite = Files.exists(destination.toPath(), LinkOption.NOFOLLOW_LINKS);
            if (overwrite && !confirm("Заменить существующий файл?", "Будет заменён файл: " + destination)) return;
            run(() -> { files.restore(entry, destination.toPath(), overwrite); return "Файл восстановлен. Подлинность и целостность проверены."; }, status::setText);
        });
        delete.setOnAction(event -> {
            FileEntry entry = list.getSelectionModel().getSelectedItem();
            if (entry == null || !confirm("Удалить из хранилища?", "Удалить зашифрованную копию «" + entry.originalName() + "»? Исходный файл останется на месте.")) return;
            run(() -> { files.delete(entry); return snapshot(); }, result -> {
                main(result); status.setText("Файл удалён из хранилища.");
            });
        });
        lock.setOnAction(event -> lock());
    }

    private boolean confirm(String title, String text) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION, text, ButtonType.YES, ButtonType.NO);
        alert.setTitle(title);
        alert.setHeaderText(title);
        alert.initOwner(stage);
        return alert.showAndWait().orElse(ButtonType.NO) == ButtonType.YES;
    }

    private void lock() {
        list.getItems().clear();
        run(() -> { vault.lock(); return true; }, result -> auth());
    }

    private <T> void run(Callable<T> operation, Consumer<T> success) {
        if (busy || closing) return;
        busy = true;
        activity = System.nanoTime();
        actions.setDisable(true);
        progress.setVisible(true);
        status.setText("Выполняется операция…");
        Task<T> task = new Task<>() { @Override protected T call() throws Exception { return operation.call(); } };
        task.setOnSucceeded(event -> {
            finish();
            if (closing) { closeNow(); return; }
            success.accept(task.getValue());
            if (vault.isUnlocked() && System.nanoTime() - activity >= IDLE_NANOS) lock();
        });
        task.setOnFailed(event -> {
            finish();
            if (closing) { closeNow(); return; }
            String error = message(task.getException());
            if (!vault.isUnlocked()) { auth(); status.setText(error); }
            else {
                list.getItems().clear();
                run(() -> { vault.lock(); return true; }, result -> { auth(); status.setText(error); });
            }
        });
        worker.submit(task);
    }

    private void finish() {
        busy = false;
        actions.setDisable(false);
        progress.setVisible(false);
    }

    private static String message(Throwable error) {
        if (error instanceof GeneralSecurityException) return "Неверный пароль или нарушена целостность данных. Данные не изменены.";
        if (error instanceof FileAlreadyExistsException) return "Файл уже существует. Выберите другое имя или подтвердите замену.";
        if (error instanceof AccessDeniedException) return "Нет прав доступа. Проверьте разрешения на файл или каталог.";
        if (error instanceof NoSuchFileException) return "Файл или каталог отсутствует. Возможно, он был удалён или перемещён.";
        if (error instanceof SQLException) return "Ошибка SQLite: база недоступна, повреждена или имеет неподдерживаемую схему. Данные не сброшены.";
        if (error instanceof FileSystemException) return "Ошибка файловой системы. Проверьте свободное место, права доступа и доступность носителя.";
        if (error instanceof java.io.IOException || error instanceof IllegalArgumentException || error instanceof IllegalStateException)
            return error.getMessage() == null ? "Не удалось выполнить операцию." : error.getMessage();
        return "Не удалось выполнить операцию. Закройте приложение и проверьте данные по инструкции README.";
    }

    private void closeNow() {
        if (closeScheduled) return;
        closeScheduled = true;
        idle.stop();
        list.getItems().clear();
        root.setDisable(true);
        worker.submit(() -> {
            try { if (vault != null) vault.close(); }
            catch (Exception ignored) {}
            finally { Platform.runLater(() -> { stage.hide(); Platform.exit(); }); }
        });
        worker.shutdown();
    }

    public void stop() throws Exception {
        idle.stop();
        worker.shutdown();
        if (vault != null) vault.close();
    }
}
