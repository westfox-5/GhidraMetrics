package it.unive.ghidra.metrics.base;

import javax.swing.JComponent;
import javax.swing.table.DefaultTableModel;

import ghidra.util.Swing;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.interfaces.GMWindowManager;

public abstract class GMBaseWindowManager implements GMWindowManager {

	public static class NonEditableTableModel extends DefaultTableModel {
		private static final long serialVersionUID = 1L;

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return false;
		}
	}

	private final GhidraMetricsPlugin plugin;

	private JComponent component;
	private boolean initialized = false;

	protected GMBaseWindowManager(GhidraMetricsPlugin plugin) {
		this.plugin = plugin;
	}

	protected abstract JComponent createComponent();

	public void init() {
		if (!initialized) {
			component = createComponent();

			onInitializationCompleted();
			initialized = true;
		}
	}

	@Override
	public GhidraMetricsPlugin getPlugin() {
		return plugin;
	}

	@Override
	public JComponent getComponent() {
		init();
		return component;
	}

	@Override
	public void refresh() {
		Swing.runLater(() -> getComponent().repaint());
	}

	@Override
	public void revalidate() {
		Swing.runNow(() -> getComponent().revalidate());
	}

}
