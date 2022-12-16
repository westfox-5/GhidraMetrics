package it.unive.ghidra.metrics.base;

import java.util.function.Function;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import it.unive.ghidra.metrics.base.interfaces.GMiMetricValue;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricWindowManager;

//@formatter:off
public abstract class GMAbstractMetricWindowManager<
	M extends GMAbstractMetric<M, P, W>, 
	P extends GMAbstractMetricManager<M, P, W>, 
	W extends GMAbstractMetricWindowManager<M, P, W>>
extends GMAbstractWindowManager implements GMiMetricWindowManager {
//@formatter:on
	private final P manager;

	public GMAbstractMetricWindowManager(P manager) {
		super();
		this.manager = manager;
	}

	@Override
	public P getManager() {
		return manager;
	}

	@Override
	public M getMetric() {
		return getManager().getMetric();
	}


	@Override
	public void onInitializationCompleted() {
		// default implementation
	}

	@Override
	public void onMetricInitialized() {
		// default implementation
	}

	protected void populateMetricTable(JTable table, String[] columns, Function<GMiMetricValue<?>, Object[]> rowFn) {
		populateMetricTable(table, getMetric(), columns, rowFn);
	}

	protected static <M extends GMAbstractMetric<?, ?, ?>> void populateMetricTable(JTable table, M metric,
			String[] columns, Function<GMiMetricValue<?>, Object[]> rowFn) {
		DefaultTableModel dtm = new NonEditableTableModel();
		dtm.setColumnCount(columns.length);
		dtm.setColumnIdentifiers(columns);

		metric.getMetrics().forEach(val -> {
			dtm.addRow(rowFn.apply(val));
		});

		table.setModel(dtm);
	}
}
