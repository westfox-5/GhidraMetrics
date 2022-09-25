package it.unive.ghidra.metrics.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.Collection;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseWinManager;
import it.unive.ghidra.metrics.base.interfaces.GMiMetric;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricProvider;

public class GMWindowManager extends GMBaseWinManager {

	private final GhidraMetricsPlugin plugin;

	private JPanel pnlMainContainer;
	private JPanel pnlMetricContainer;

	public GMWindowManager(GhidraMetricsPlugin plugin) {
		this.plugin = plugin;
	}

	@Override
	public void init() {
		populateMetrics(plugin.getAvailableMetrics());
	}

	/**
	 * @wbp.parser.entryPoint
	 */
	@Override
	protected JComponent createComponent() {
		JComponent component = new JPanel();
		component.setBorder(new EmptyBorder(5, 5, 5, 5));

		component.setLayout(new BorderLayout(0, 0));

		pnlMetricContainer = new JPanel();
		pnlMetricContainer.setVisible(false);
		pnlMetricContainer.setMaximumSize(new Dimension(32767, 30));
		component.add(pnlMetricContainer, BorderLayout.NORTH);
		pnlMetricContainer.setLayout(new BorderLayout(0, 0));

		JPanel pnlMetricHeader = new JPanel();
		pnlMetricContainer.add(pnlMetricHeader, BorderLayout.NORTH);
		
		JPanel pnlMetricFooter = new JPanel();
		pnlMetricContainer.add(pnlMetricFooter, BorderLayout.SOUTH);

		pnlMainContainer = new JPanel();
		pnlMainContainer.setVisible(false);
		component.add(pnlMainContainer, BorderLayout.CENTER);
		pnlMainContainer.setLayout(new GridLayout(0, 1, 10, 10));

		return component;
	}

	public final void showView(GMiMetricProvider<?, ?, ?> provider) {
		pnlMetricContainer.removeAll();

		if (provider == null) {
			pnlMetricContainer.setVisible(false);
			pnlMainContainer.setVisible(true);

		} else {
			JComponent component = provider.getWinManager().getComponent();
			pnlMetricContainer.add(component, BorderLayout.CENTER);

			pnlMainContainer.setVisible(false);
			pnlMetricContainer.setVisible(true);
		}

		revalidate();
	}

	private final void populateMetrics(Collection<Class<? extends GMiMetric<?, ?, ?>>> metrics) {
		metrics.forEach(metricClz -> {
			pnlMainContainer.add(new GMMetricButton(plugin, metricClz));
		});
	}
}
