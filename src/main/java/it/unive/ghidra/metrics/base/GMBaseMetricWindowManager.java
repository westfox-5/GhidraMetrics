package it.unive.ghidra.metrics.base;

import java.util.function.Function;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import it.unive.ghidra.metrics.base.interfaces.GMMeasure;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;
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

	protected void populateMeasureTable(JTable table) {
		populateMeasureTable(table, getMetric());
	}

	protected static void populateMeasureTable(JTable table, GMMetric metric) {
		DefaultTableModel dtm = new NonEditableTableModel();
		
		String[] tableColumns = metric.getTableColumns();
		dtm.setColumnCount(tableColumns.length);
		dtm.setColumnIdentifiers(tableColumns);
		
		Function<GMMeasure<?>, Object[]> tableRowFn = metric.getTableRowFn();
		metric.getMeasures().parallelStream().forEach(measure -> {
			dtm.addRow( tableRowFn.apply(measure) );
		});

		table.setModel(dtm);
	}
}
