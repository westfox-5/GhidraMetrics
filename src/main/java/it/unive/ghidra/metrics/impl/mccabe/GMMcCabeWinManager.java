package it.unive.ghidra.metrics.impl.mccabe;

import java.awt.BorderLayout;
import java.awt.Font;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;

import it.unive.ghidra.metrics.base.GMAbstractMetricWindowManager;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;

public class GMMcCabeWinManager extends GMAbstractMetricWindowManager<GMMcCabe, GMMcCabeProvider, GMMcCabeWinManager> {
	private static final String[] COLUMNS = { "Name", "Value" };

	private JPanel pnlSelection;
	private JPanel pnlContainer;
	private JTable tbl;

	public GMMcCabeWinManager(GMMcCabeProvider provider) {
		super(provider);
	}

	@Override
	protected JComponent createComponent() {
		JComponent component = new JPanel();
		component.setLayout(new BorderLayout(0, 0));

		pnlSelection = new JPanel();
		pnlSelection.setBorder(new EmptyBorder(10, 10, 10, 10));
		component.add(pnlSelection, BorderLayout.NORTH);
		pnlSelection.setLayout(new BorderLayout(0, 0));

		JLabel lblNewLabel = new JLabel("Select a valid function in the listing");
		lblNewLabel.setFont(new Font("Dialog", Font.BOLD | Font.ITALIC, 14));
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		pnlSelection.add(lblNewLabel, BorderLayout.WEST);

		pnlContainer = new JPanel();
		pnlContainer.setLayout(new BorderLayout(0, 0));
		component.add(pnlContainer, BorderLayout.CENTER);

		tbl = new JTable();
		pnlContainer.add(tbl.getTableHeader(), BorderLayout.NORTH);
		pnlContainer.add(tbl, BorderLayout.CENTER);

		pnlSelection.setVisible(true);
		pnlContainer.setVisible(false);
		return component;
	}

	@Override
	public void revalidate() {
		// populateProgramMetrics();
		populateFunctionMetrics();

		super.revalidate();
	}

	private void populateFunctionMetrics() {
		GMMcCabe mcCabe = getMetric();
		if (mcCabe != null) {
			populateMetricTable(tbl, mcCabe);

			pnlContainer.setVisible(true);
			pnlSelection.setVisible(false);
		} else {
			pnlContainer.setVisible(false);
			pnlSelection.setVisible(true);
		}
	}

	private void populateMetricTable(JTable table, GMMcCabe metric) {
		populateMetricTable(table, metric, COLUMNS, val -> {
			GMiMetricKey key = val.getKey();
			return new Object[] { key.getName(), val.getValue() };
		});
	}
}
