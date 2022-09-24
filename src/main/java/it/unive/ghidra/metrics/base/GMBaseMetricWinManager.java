package it.unive.ghidra.metrics.base;

import java.util.function.Function;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import it.unive.ghidra.metrics.base.interfaces.GMiMetricValue;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricWinManager;

public abstract class GMBaseMetricWinManager <
	M extends GMBaseMetric<M, P, W>,
	P extends GMBaseMetricProvider<M, P, W>,
	W extends GMBaseMetricWinManager<M, P, W>>
extends GMBaseWinManager implements GMiMetricWinManager<M, P, W> {
	
	private final P provider;
	
	public GMBaseMetricWinManager(P provider) {
		super();
		this.provider = provider;
	}

	@Override
	public M getMetric() {
		return getProvider().getMetric();
	}

	@Override
	public P getProvider() {
		return provider;
	}
	

	protected void populateMetricTable(JTable table, String[] columns, Function<GMiMetricValue<?>, Object[]> rowFn) {
		populateMetricTable(table, getMetric(), columns, rowFn);
	}
	
	protected static <M extends GMBaseMetric<?,?,?>> void populateMetricTable(JTable table, M metric, String[] columns, Function<GMiMetricValue<?>, Object[]> rowFn) {
		DefaultTableModel dtm = new NonEditableTableModel();
		dtm.setColumnCount(columns.length);
		dtm.setColumnIdentifiers(columns);
		
		metric.getMetrics().forEach(val -> {
			dtm.addRow(rowFn.apply(val));			
		});
		
		table.setModel(dtm);
	}


}
