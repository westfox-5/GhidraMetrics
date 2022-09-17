package it.unive.ghidra.metrics.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.Collection;

import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetricProvider;
import it.unive.ghidra.metrics.base.GMBaseWindowManager;
import it.unive.ghidra.metrics.base.GMBaseMetric;

public class GMWindowManager extends GMBaseWindowManager {
	
	private final GhidraMetricsPlugin plugin;
	
	private JPanel 
			pnlMetricList, // Metrics buttons container
			pnlMetricContainer // Metric content
	;
	
	/**
	 * Create the frame.
	 */
	public GMWindowManager(GhidraMetricsPlugin plugin) {
		this.plugin = plugin;
	}
	
	@Override
	protected JComponent createComponent() {
		JComponent container = new JPanel();
		container.setBorder(new EmptyBorder(5, 5, 5, 5));

		container.setLayout(new BorderLayout(0, 0));
		
		pnlMetricContainer = new JPanel();
		pnlMetricContainer.setVisible(false);
		pnlMetricContainer.setMaximumSize(new Dimension(32767, 30));
		container.add(pnlMetricContainer, BorderLayout.NORTH);
		pnlMetricContainer.setLayout(new BorderLayout(0, 0));
		
		JPanel pnlMetricHeader = new JPanel();
		pnlMetricContainer.add(pnlMetricHeader, BorderLayout.NORTH);
		pnlMetricHeader.setMaximumSize(new Dimension(32767, 30));
		pnlMetricHeader.setLayout(new BoxLayout(pnlMetricHeader, BoxLayout.X_AXIS));
		
		JPanel pnlMetricFooter= new JPanel();
		pnlMetricContainer.add(pnlMetricFooter, BorderLayout.SOUTH);
		
		pnlMetricList = new JPanel();
		container.add(pnlMetricList, BorderLayout.CENTER);
		pnlMetricList.setLayout(new GridLayout(0, 1, 0, 0));
		pnlMetricList.setVisible(true);
		
		return container;
	}
	
	public final void addEnabledMetrics(Collection<Class<? extends GMBaseMetric>> metricsClz) {
		for (Class<? extends GMBaseMetric> metricClz: metricsClz) {
			pnlMetricList.add(GMButton.of(plugin, metricClz));
		}
	}
	
	public final void show(GMBaseMetricProvider<?> mProvider) {
		if (mProvider == null) {
			pnlMetricContainer.setVisible(false);
			pnlMetricList.setVisible(true);

		} else {
			JComponent component = mProvider.getComponent();
			pnlMetricContainer.add(component, BorderLayout.CENTER); 

			pnlMetricList.setVisible(false);
			pnlMetricContainer.setVisible(true);			
		}
		
		revalidate();
	}

}
