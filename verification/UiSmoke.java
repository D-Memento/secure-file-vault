import javafx.application.Platform;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.control.*;
import javafx.stage.*;
import ru.vault.ui.VaultController;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BooleanSupplier;

public final class UiSmoke {
    private static Stage stage;
    private static VaultController controller;
    private static <T> T fx(Callable<T> action) throws Exception {
        FutureTask<T> task = new FutureTask<>(action);
        Platform.runLater(task);
        return task.get(20, TimeUnit.SECONDS);
    }
    private static List<Node> nodes(Node node) {
        var nodes = new ArrayList<Node>(); nodes.add(node);
        if (node instanceof Parent parent) for (Node child : parent.getChildrenUnmodifiable()) nodes.addAll(nodes(child));
        return nodes;
    }
    private static Button button(String text) {
        return nodes(stage.getScene().getRoot()).stream().filter(n -> n instanceof Button b && b.getText().equals(text))
                .map(n -> (Button)n).findFirst().orElse(null);
    }
    private static void await(BooleanSupplier check) throws Exception {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (System.nanoTime() < until) {
            if (fx(check::getAsBoolean)) return;
            Thread.sleep(50);
        }
        throw new AssertionError("UI timeout");
    }
    private static void enter(String password, String submit) throws Exception {
        fx(() -> {
            for (Node node : nodes(stage.getScene().getRoot())) if (node instanceof PasswordField field) field.setText(password);
            button(submit).fire(); return null;
        });
    }
    public static void main(String[] args) throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        Platform.startup(() -> { Platform.setImplicitExit(false); started.countDown(); });
        if (!started.await(10, TimeUnit.SECONDS)) throw new AssertionError("Toolkit timeout");
        try {
            fx(() -> { stage = new Stage(); controller = new VaultController(stage); return null; });
            await(() -> button("Создать хранилище") != null);
            enter("demonstration password 42", "Создать хранилище");
            await(() -> button("Заблокировать") != null);
            fx(() -> { button("Заблокировать").fire(); return null; });
            await(() -> button("Разблокировать") != null && !button("Разблокировать").isDisabled());
            enter("wrong password", "Разблокировать");
            await(() -> button("Разблокировать") != null && !button("Разблокировать").isDisabled()
                    && nodes(stage.getScene().getRoot()).stream().anyMatch(n -> n instanceof Label l && l.getText().startsWith("Неверный пароль")));
            enter("demonstration password 42", "Разблокировать");
            await(() -> button("Заблокировать") != null);
            fx(() -> { stage.fireEvent(new WindowEvent(stage, WindowEvent.WINDOW_CLOSE_REQUEST)); return null; });
            System.out.println("UI SMOKE PASSED: setup, lock, wrong password, unlock, close");
        } finally {
            if (controller != null) controller.stop();
            Platform.exit();
        }
    }
}
