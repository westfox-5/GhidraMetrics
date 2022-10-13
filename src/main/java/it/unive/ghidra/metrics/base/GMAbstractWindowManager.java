package it.unive.ghidra.metrics.base;

import javax.swing.JComponent;
import javax.swing.table.DefaultTableModel;

import ghidra.util.Swing;
import it.unive.ghidra.metrics.base.interfaces.GMiWindowManager;

public abstract class GMAbstractWindowManager implements GMiWindowManager {

	public static class NonEditableTableModel extends DefaultTableModel {
		private static final long serialVersionUID = 1L;

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return false;
		}
	}

	private JComponent component;
	private boolean initialized = false;

	protected GMAbstractWindowManager() {
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
	public JComponent getComponent() {
		init();
		return component;
	}

	@Override
	public void refresh() {
		Swing.runNow(() -> getComponent().repaint());
	}

	@Override
	public void revalidate() {
		Swing.runNow(() -> getComponent().revalidate());
	}

}
