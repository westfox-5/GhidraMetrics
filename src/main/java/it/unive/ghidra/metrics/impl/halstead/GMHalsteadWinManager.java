package it.unive.ghidra.metrics.impl.halstead;

import java.awt.BorderLayout;
import java.awt.Font;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;

import it.unive.ghidra.metrics.base.GMBaseMetricWinManager;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;

public class GMHalsteadWinManager extends GMBaseMetricWinManager<GMHalstead, GMHalsteadProvider, GMHalsteadWinManager> {
	private static final String[] COLUMNS = { "Name", "Value", "Description", "Formula" };

	private JTable tableProgramMetrics;
	private JTable tableFunctionMetrics;
	private JTabbedPane tabbedPane;
	private JPanel pnlNoFunctionSelected;
	private JLabel lblNewLabel;

	public GMHalsteadWinManager(GMHalsteadProvider provider) {
		super(provider);
	}

	@Override
	public void init() {
		populateProgramMetrics();
		populateFunctionMetrics();
	}

	/**
	 * @wbp.parser.entryPoint
	 */
	@Override
	protected JComponent createComponent() {
		JComponent component = new JPanel();
		component.setLayout(new BorderLayout(0, 0));

		tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		component.add(tabbedPane, BorderLayout.CENTER);

		// tab 0 - Program metrics
		{
			JPanel pnlProgramMetrics = new JPanel();
			tabbedPane.addTab("Program metrics", null, pnlProgramMetrics, null);
			pnlProgramMetrics.setLayout(new BorderLayout(0, 0));

			tableProgramMetrics = new JTable();
			pnlProgramMetrics.add(tableProgramMetrics.getTableHeader(), BorderLayout.NORTH);
			pnlProgramMetrics.add(tableProgramMetrics, BorderLayout.CENTER);
		}

		// tab 1 - Function metrics
		{
			JPanel pnlFunctionMetrics = new JPanel();
			tabbedPane.addTab("Function metrics", null, pnlFunctionMetrics, null);
			pnlFunctionMetrics.setLayout(new BorderLayout(0, 0));

			tableFunctionMetrics = new JTable();
			tableFunctionMetrics.setVisible(false);
			tableFunctionMetrics.setEnabled(false);
			pnlFunctionMetrics.add(tableFunctionMetrics.getTableHeader(), BorderLayout.NORTH);
			pnlFunctionMetrics.add(tableFunctionMetrics, BorderLayout.CENTER);

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

	protected void populateProgramMetrics() {
		populateMetricTable(tableProgramMetrics, getMetric());
	}

	protected void populateFunctionMetrics() {
		GMHalstead fnHalstead = getMetric().getHalsteadFunction();
		if (fnHalstead != null) {
			populateMetricTable(tableFunctionMetrics, fnHalstead);

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

	private void populateMetricTable(JTable table, GMHalstead metric) {
		populateMetricTable(table, metric, COLUMNS, val -> {
			GMiMetricKey key = val.getKey();
			return new Object[] { key.getName(), val.getValue(), key.getInfo(GMiMetricKey.KEY_DESCRIPTION),
					key.getInfo(GMiMetricKey.KEY_FORMULA) };
		});
	}
}
