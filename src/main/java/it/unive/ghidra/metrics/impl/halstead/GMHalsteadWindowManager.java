package it.unive.ghidra.metrics.impl.halstead;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import it.unive.ghidra.metrics.base.GMBaseMetricWindowManager;
import it.unive.ghidra.metrics.base.GMBaseValue;
import it.unive.ghidra.metrics.base.GMetric;
import javax.swing.JLabel;
import javax.swing.SwingConstants;
import java.awt.Font;

public class GMHalsteadWindowManager extends GMBaseMetricWindowManager<GMHalstead> {

	private JTable tableProgramMetrics;
	private JTable tableFunctionMetrics;
	private JTabbedPane tabbedPane;
	private JPanel pnlNoFunctionSelected;
	private JLabel lblNewLabel;
	
	public GMHalsteadWindowManager(GMHalstead halstead) {
		super(halstead);
	}
	
	/**
	 * @wbp.parser.entryPoint
	 */
	protected JComponent createComponent() {
		JComponent component = new JPanel();
		component.setLayout(new BorderLayout(0, 0));
		
		tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		component.add(tabbedPane, BorderLayout.CENTER);
		
		// Program metrics
		{ 
			JPanel pnlProgramMetrics = new JPanel();
			tabbedPane.addTab("Program metrics", null, pnlProgramMetrics, null);
			pnlProgramMetrics.setLayout(new BorderLayout(0, 0));
			
			tableProgramMetrics = new JTable();
			pnlProgramMetrics.add(tableProgramMetrics.getTableHeader(), BorderLayout.NORTH);
			pnlProgramMetrics.add(tableProgramMetrics, BorderLayout.CENTER);
		}
		
		// Function metrics
		{
			JPanel pnlFunctionMetrics = new JPanel();
			tabbedPane.addTab("Function metrics", null, pnlFunctionMetrics, null);
			pnlFunctionMetrics.setLayout(new BorderLayout(0, 0));
			
			tableFunctionMetrics = new JTable();
			tableFunctionMetrics.setVisible(false);
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
	public void init() {
		populateProgramMetrics();
		populateFunctionMetrics();
		
		refresh();
	}

	@Override
	public void revalidate() {
		//populateProgramMetrics();
		populateFunctionMetrics();
		
		super.revalidate();
	}

	protected void populateProgramMetrics() {
		populateMetricTable(tableProgramMetrics, getMetric());
	}
	
	protected void populateFunctionMetrics() {
		GMHalstead fnHalstead = getMetric().getFnHalstead();
		if (fnHalstead != null) {
			populateMetricTable(tableFunctionMetrics, fnHalstead);
			
			tableFunctionMetrics.setVisible(true);
			pnlNoFunctionSelected.setVisible(false);
		} else {
			tableFunctionMetrics.setVisible(false);
			pnlNoFunctionSelected.setVisible(true);
		}
	}

	private static void populateMetricTable(JTable table, GMetric metric) {
		DefaultTableModel dtm = new DefaultTableModel(0, 4);
		dtm.setColumnIdentifiers(new String[]{"Name", "Value", "Description", "Formula"});
		
		GMHalsteadKey.ALL_KEYS.forEach(k -> {
			GMBaseValue<?> m = metric.getMetric(k);
			dtm.addRow(new Object[] { 
					m.getName(),
					m.getValue(),
					m.getDescription(),
					m.getFormula()});			
		});
		
		table.setModel(dtm);
	}
}
