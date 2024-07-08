import matplotlib.pyplot as plt
from matplotlib.ticker import FormatStrFormatter

# Latency values in microseconds
latency_with_ebpf = [7.6]  
latency_without_ebpf = [7.4] 

# Create the plot
fig, ax = plt.subplots()

# Plotting the values
ax.bar(1, latency_with_ebpf, width=0.4, label='With eBPF', align='center')
ax.bar(1, latency_without_ebpf, width=0.4, label='Without eBPF', align='edge')
ax.yaxis.set_major_formatter(FormatStrFormatter('%.2f'))

# Adding labels and title
ax.set_xlabel('Operations - (GET,POST,PUT,PATCH,DELETE,CONNECT,OPTIONS,TRACE)')
ax.set_ylabel('Average Latency (µs)')
ax.set_xticklabels([])
ax.set_title('HTTPS Latency Comparison with and without eBPF')
ax.legend()

# Display the plot
plt.tight_layout()
plt.show()
