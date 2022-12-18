package it.unive.ghidra.metrics.base;

import java.util.function.Function;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import it.unive.ghidra.metrics.base.interfaces.GMMetricValue;
import it.unive.ghidra.metrics.base.interfaces.GMMetricWindowManager;

//@formatter:off
public abstract class GMBaseMetricWindowManager<
	M extends GMBaseMetric<M, P, W>, 
	P extends GMBaseMetricManager<M, P, W>, 
	W extends GMBaseMetricWindowManager<M, P, W>>
extends GMBaseWindowManager implements GMMetricWindowManager {
//@formatter:on
	private final P manager;

	public GMBaseMetricWindowManager(P manager) {
		super(manager.getPlugin());
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

	protected void populateMetricTable(JTable table, String[] columns, Function<GMMetricValue<?>, Object[]> rowFn) {
		populateMetricTable(table, getMetric(), columns, rowFn);
	}

	protected static <M extends GMBaseMetric<?, ?, ?>> void populateMetricTable(JTable table, M metric,
			String[] columns, Function<GMMetricValue<?>, Object[]> rowFn) {
		DefaultTableModel dtm = new NonEditableTableModel();
		dtm.setColumnCount(columns.length);
		dtm.setColumnIdentifiers(columns);

		metric.getMetrics().forEach(val -> {
			dtm.addRow(rowFn.apply(val));
		});

		table.setModel(dtm);
	}
}
