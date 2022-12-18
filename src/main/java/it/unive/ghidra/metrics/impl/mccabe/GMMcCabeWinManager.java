package it.unive.ghidra.metrics.impl.mccabe;

import java.awt.BorderLayout;
import java.awt.Font;
import java.util.function.Function;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;

import it.unive.ghidra.metrics.base.GMBaseMetricWindowManager;
import it.unive.ghidra.metrics.base.interfaces.GMMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMMetricValue;

public class GMMcCabeWinManager extends GMBaseMetricWindowManager<GMMcCabe, GMMcCabeManager, GMMcCabeWinManager> {
	private static final String[] TABLE_COLUMNS_DEFINITION = { "Name", "Value", "Formula" };
	private static final Function<GMMetricValue<?>, Object[]> TABLE_ROWS_FUNCTION = metric -> new Object[] {
			metric.getKey().getName(), metric.getValue(), metric.getKey().getInfo(GMMetricKey.KEY_INFO_FORMULA) };

	private JTable tableProgramMetrics;
	private JTable tableFunctionMetrics;
	private JTabbedPane tabbedPane;
	private JPanel pnlNoFunctionSelected;
	private JLabel lblNewLabel;


	public GMMcCabeWinManager(GMMcCabeManager manager) {
		super(manager);
	}
	
	@Override
	public void onMetricInitialized() {
		populateProgramMetrics();
		populateFunctionMetrics();
	}

	@Override
	protected JComponent createComponent() {
		JComponent component = new JPanel();
		component.setLayout(new BorderLayout(0, 0));

		tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		component.add(tabbedPane, BorderLayout.CENTER);

		// tab 0 - Program metrics
		{
			JPanel pnlProgramMetrics = new JPanel();
			tabbedPane.addTab("Program metrics", null, new JScrollPane(pnlProgramMetrics), null);
			pnlProgramMetrics.setLayout(new BorderLayout(0, 0));
			
			tableProgramMetrics = new JTable();
			
			JScrollPane scrollPane = new JScrollPane(tableProgramMetrics);  
			scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
			
			pnlProgramMetrics.add(tableProgramMetrics.getTableHeader(), BorderLayout.NORTH);
			pnlProgramMetrics.add(scrollPane, BorderLayout.CENTER);
		}

		// tab 1 - Function metrics
		{
			JPanel pnlFunctionMetrics = new JPanel();
			tabbedPane.addTab("Function metrics", null, new JScrollPane(pnlFunctionMetrics), null);
			pnlFunctionMetrics.setLayout(new BorderLayout(0, 0));

			tableFunctionMetrics = new JTable();
			tableFunctionMetrics.setVisible(false);
			tableFunctionMetrics.setEnabled(false);
			
			JScrollPane scrollPane = new JScrollPane(tableFunctionMetrics);  
			scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
			
			pnlFunctionMetrics.add(tableFunctionMetrics.getTableHeader(), BorderLayout.NORTH);
			pnlFunctionMetrics.add(scrollPane, BorderLayout.CENTER);

			pnlNoFunctionSelected = new JPanel();
			pnlNoFunctionSelected.setVisible(true);
			pnlFunctionMetrics.add(pnlNoFunctionSelected, BorderLayout.SOUTH);
			pnlNoFunctionSelected.setLayout(new BorderLayout(0, 0));

			lblNewLabel = new JLabel("Select a valid function in the listing");
			lblNewLabel.setFont(new Font("Dialog", Font.BOLD | Font.ITALIC, 14));
			lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
			pnlNoFunctionSelected.add(lblNewLabel, BorderLayout.CENTER);
		}
		return component;
	}

	@Override
	public void revalidate() {
		// populateProgramMetrics();
		populateFunctionMetrics();

		super.revalidate();
	}
	

	private void populateProgramMetrics() {
		populateMetricTable(tableProgramMetrics, getMetric());
	}

	private void populateFunctionMetrics() {
		GMMcCabe mcCabeFn = getManager().getMetricFn();
		if (mcCabeFn != null) {
			populateMetricTable(tableFunctionMetrics, mcCabeFn);

			tableFunctionMetrics.setVisible(true);
			pnlNoFunctionSelected.setVisible(false);
		} else {
			tableFunctionMetrics.setVisible(false);
			pnlNoFunctionSelected.setVisible(true);
		}
	}

	public boolean isProgramTabVisible() {
		return tabbedPane.getSelectedIndex() == 0;
	}

	public boolean isFunctionTabVisible() {
		return tabbedPane.getSelectedIndex() == 1;
	}
	
	private void populateMetricTable(JTable table, GMMcCabe metric) {
		populateMetricTable(table, metric, TABLE_COLUMNS_DEFINITION, TABLE_ROWS_FUNCTION);
	}
}
