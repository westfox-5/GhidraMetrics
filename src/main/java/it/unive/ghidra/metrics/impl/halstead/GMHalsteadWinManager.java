package it.unive.ghidra.metrics.impl.halstead;

import java.awt.BorderLayout;
import java.awt.Font;
import java.util.function.Function;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;

import it.unive.ghidra.metrics.base.GMAbstractMetricWindowManager;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricValue;

//@formatter:off
public class GMHalsteadWinManager extends GMAbstractMetricWindowManager<GMHalstead, GMHalsteadProvider, GMHalsteadWinManager> {
//@formatter:on

	private static final String[] TABLE_COLUMNS_DEFINITION = { "Name", "Value", "Description", "Formula" };
	private static final Function<GMiMetricValue<?>, Object[]> TABLE_ROWS_FUNCTION = metric -> new Object[] {
			metric.getKey().getName(), metric.getValue(), metric.getKey().getInfo(GMiMetricKey.KEY_DESCRIPTION),
			metric.getKey().getInfo(GMiMetricKey.KEY_FORMULA) };

	private JTable tableProgramMetrics;
	private JTable tableFunctionMetrics;
	private JTabbedPane tabbedPane;
	private JPanel pnlNoFunctionSelected;
	private JLabel lblNewLabel;

	public GMHalsteadWinManager(GMHalsteadProvider provider) {
		super(provider);
	}

	@Override
	public void onMetricInitialized() {
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

	private void populateProgramMetrics() {
		populateMetricTable(tableProgramMetrics, getMetric());
	}

	private void populateFunctionMetrics() {
		GMHalstead fnHalstead = getProvider().getMetricFn();
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
		populateMetricTable(table, metric, TABLE_COLUMNS_DEFINITION, TABLE_ROWS_FUNCTION);
	}
}
