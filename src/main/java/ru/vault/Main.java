package ru.vault;

import javafx.application.Application;
import javafx.stage.Stage;
import ru.vault.ui.VaultController;

public final class Main extends Application {
    private VaultController controller;
    @Override public void start(Stage stage) { controller = new VaultController(stage); }
    @Override public void stop() throws Exception { if (controller != null) controller.stop(); }
    public static void main(String[] args) { launch(args); }
}
