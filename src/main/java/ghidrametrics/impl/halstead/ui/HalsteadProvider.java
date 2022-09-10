package ghidrametrics.impl.halstead.ui;

import java.awt.BorderLayout;
import java.util.Set;

import javax.swing.JPanel;
import javax.swing.JTextArea;

import ghidrametrics.GhidraMetricsPlugin;
import ghidrametrics.base.BaseMetricProvider;
import ghidrametrics.base.BaseMetricValue;
import ghidrametrics.impl.halstead.HalsteadWrapper;
import ghidrametrics.util.StringUtils;

public class HalsteadProvider extends BaseMetricProvider<HalsteadWrapper> {

	public HalsteadProvider(GhidraMetricsPlugin plugin) {
		super(plugin, HalsteadWrapper.class);
	}

	@Override
	protected void initWrapper(HalsteadWrapper wrapper) {
		return;
	}

	@Override
	protected void buildComponent() {
		panel = new JPanel(new BorderLayout());
		
		JTextArea textArea = new JTextArea();
		textArea.setEditable(false);
			
		StringBuilder sb = new StringBuilder();
		
		Set<BaseMetricValue<?>> metrics = getWrapper().getMetrics();
		for (BaseMetricValue<?> metric: metrics) {			
			String value = StringUtils.quotate(metric.getValue());
			sb.append(metric.getDescription())
				.append("(").append(metric.getName()).append("): ")
				.append(value)
				.append("\n");
		}
		
		textArea.setText(sb.toString());
		panel.add(textArea, BorderLayout.CENTER);
	}
}
