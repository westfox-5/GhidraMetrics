package it.unive.ghidra.metrics.base;

import java.awt.Dimension;
import java.util.function.Function;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import it.unive.ghidra.metrics.base.interfaces.GMMeasure;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMetricWindow;

//@formatter:off
public abstract class GMBaseMetricWindow<
	M extends GMBaseMetric<M, C, W>, 
	C extends GMBaseMetricController<M, C, W>, 
	W extends GMBaseMetricWindow<M, C, W>>
extends GMBaseWindow implements GMMetricWindow {
//@formatter:on
	
	public static class NonEditableTableModel extends DefaultTableModel {
		private static final long serialVersionUID = 1L;

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return false;
		}
		
	}
	
	public static class GMTable extends JTable {
		private static final long serialVersionUID = 1L;

		public GMTable() {
			super();
			setPreferredScrollableViewportSize(new Dimension(0, 0));
		}
	}
	
	private final C controller;

	public GMBaseMetricWindow(C controller) {
		super(controller.getPlugin());
		this.controller = controller;
	}

	@Override
	public C getController() {
		return controller;
	}

	protected void populateMeasureTable(JTable table) {
		populateMeasureTable(table, getMetric());
	}

	protected static void populateMeasureTable(JTable table, GMMetric metric) {
		DefaultTableModel dtm = new NonEditableTableModel();
		
		String[] tableColumns = metric.getTableColumns();
		dtm.setColumnCount(tableColumns.length);
		dtm.setColumnIdentifiers(tableColumns);
		
		Function<GMMeasure<?>, Object[]> tableRowFn = metric.getTableRowFn();
		metric.getMeasures().stream().forEach(measure -> {
			dtm.addRow( tableRowFn.apply(measure) );
		});

		table.setModel(dtm);		
	}
}
