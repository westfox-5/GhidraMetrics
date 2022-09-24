package it.unive.ghidra.metrics.base;

import javax.swing.JComponent;
import javax.swing.table.DefaultTableModel;

import it.unive.ghidra.metrics.base.interfaces.GMiWinManager;

public abstract class GMBaseWinManager implements GMiWinManager {
	
	public static class NonEditableTableModel extends DefaultTableModel {
		private static final long serialVersionUID = 1L;
		
		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return false;
		}		
	}
	
	private final JComponent component;
	private boolean initialized = false;

	protected GMBaseWinManager() {
		this.component = createComponent();
	}

	protected void _init() {
		if (!initialized) {
			init();
			initialized = true;
		}
	}

	protected abstract JComponent createComponent();

	@Override
	public JComponent getComponent() {
		_init();
		return component;
	}

}
