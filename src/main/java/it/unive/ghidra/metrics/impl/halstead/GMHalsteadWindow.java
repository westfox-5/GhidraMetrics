package it.unive.ghidra.metrics.impl.halstead;

import java.awt.BorderLayout;
import java.awt.Font;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;

import it.unive.ghidra.metrics.base.GMBaseMetricWindow;

//@formatter:off
public class GMHalsteadWindow extends GMBaseMetricWindow<GMHalstead, GMHalsteadController, GMHalsteadWindow> {
//@formatter:on

	private JTable tableProgramMeasure;
	private JTable tableFunctionMeasure;
	private JTabbedPane tabbedPane;
	private JPanel pnlNoFunctionSelected;
	private JLabel lblNewLabel;

	public GMHalsteadWindow(GMHalsteadController controller) {
		super(controller);
	}

	@Override
	public boolean init() {
		populateProgramMeasures();
		populateFunctionMeasures();

		return true;
	}

	@Override
	protected JComponent createComponent() {
		JComponent component = new JPanel();
		component.setLayout(new BorderLayout(0, 0));

		tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		component.add(tabbedPane, BorderLayout.CENTER);

		// tab 0 - Program measures
		{
			JPanel pnlProgramMetrics = new JPanel();
			tabbedPane.addTab("Program measures", null, new JScrollPane(pnlProgramMetrics), null);
			pnlProgramMetrics.setLayout(new BorderLayout(0, 0));

			tableProgramMeasure = new GMTable();

			JScrollPane scrollPane = new JScrollPane(tableProgramMeasure);
			scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

			pnlProgramMetrics.add(tableProgramMeasure.getTableHeader(), BorderLayout.NORTH);
			pnlProgramMetrics.add(scrollPane, BorderLayout.CENTER);
		}

		// tab 1 - Function measures
		{
			JPanel pnlFunctionMetrics = new JPanel();
			tabbedPane.addTab("Function measures", null, new JScrollPane(pnlFunctionMetrics), null);
			pnlFunctionMetrics.setLayout(new BorderLayout(0, 0));

			pnlNoFunctionSelected = new JPanel();
			pnlNoFunctionSelected.setVisible(true);
			pnlFunctionMetrics.add(pnlNoFunctionSelected, BorderLayout.NORTH);
			pnlNoFunctionSelected.setLayout(new BorderLayout(0, 0));

			lblNewLabel = new JLabel("Select a valid function in the listing");
			lblNewLabel.setFont(new Font("Dialog", Font.BOLD | Font.ITALIC, 14));
			lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
			lblNewLabel.setVisible(true);
			pnlNoFunctionSelected.add(lblNewLabel, BorderLayout.CENTER);

			tableFunctionMeasure = new GMTable();

			JScrollPane scrollPane = new JScrollPane(tableFunctionMeasure);
			scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

			// pnlFunctionMetrics.add(tableFunctionMeasure.getTableHeader(),
			// BorderLayout.NORTH);
			pnlFunctionMetrics.add(scrollPane, BorderLayout.CENTER);
		}

		return component;
	}

	@Override
	public void refresh() {
		// populateProgramMeasures();
		populateFunctionMeasures();

		super.refresh();
	}

	private void populateProgramMeasures() {
		populateMeasureTable(tableProgramMeasure, getMetric());
	}

	private void populateFunctionMeasures() {
		GMHalstead fnHalstead = getController().getMetricFn();
		if (fnHalstead != null) {
			populateMeasureTable(tableFunctionMeasure, fnHalstead);

			tableFunctionMeasure.setVisible(true);
			pnlNoFunctionSelected.setVisible(false);
		} else {
			tableFunctionMeasure.setVisible(false);
			pnlNoFunctionSelected.setVisible(true);
		}
	}

	public boolean isProgramTabVisible() {
		return tabbedPane.getSelectedIndex() == 0;
	}

	public boolean isFunctionTabVisible() {
		return tabbedPane.getSelectedIndex() == 1;
	}
}
