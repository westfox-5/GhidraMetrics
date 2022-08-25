package ghidrametrics.impl.halstead.ui;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import ghidra.program.model.listing.Program;
import ghidrametrics.GhidraMetricsPlugin;
import ghidrametrics.base.BaseMetric;
import ghidrametrics.base.ui.BaseMetricProvider;
import ghidrametrics.impl.halstead.HalsteadMetricKey;
import ghidrametrics.impl.halstead.HalsteadWrapper;
import ghidrametrics.util.StringUtils;

public class HalsteadProvider extends BaseMetricProvider<HalsteadWrapper> {
	
	public HalsteadProvider(GhidraMetricsPlugin plugin) {
		super(plugin, HalsteadWrapper.class);
	}

	@Override
	public HalsteadWrapper initWrapper() {
		if (wrapper == null) {
			Program program = getCurrentProgram();
			wrapper = new HalsteadWrapper.Builder(program)
					.build();
		}
		return wrapper;
	}

	@Override
	public void buildComponent() {
		panel = new JPanel();
		
		JTextArea textArea = new JTextArea();
		textArea.setEditable(false);
			
		StringBuilder sb = new StringBuilder();
		for (HalsteadMetricKey hKey: HalsteadMetricKey.values()) {
			BaseMetric<?> metric = wrapper.getMetric(hKey);
			
			String value = StringUtils.quotate(metric.getValue());
			sb.append(metric.getDescription())
				.append("(").append(metric.getName()).append("): ")
				.append(value)
				.append("\n");
		}
		
		textArea.setText(sb.toString());
		panel.add(new JScrollPane(textArea));
	}
}
