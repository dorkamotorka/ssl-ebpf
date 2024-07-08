import matplotlib.pyplot as plt

# Latency values in milliseconds
latency_with_ebpf = [0.0076]  
latency_without_ebpf = [0.0074] 

# Create the plot
fig, ax = plt.subplots()

# Plotting the values
ax.bar(latency_with_ebpf, width=0.4, label='With eBPF', align='center')
ax.bar(latency_without_ebpf, width=0.4, label='Without eBPF', align='edge')

# Adding labels and title
ax.set_xlabel('Operation')
ax.set_ylabel('Latency (ms)')
ax.set_title('HTTPS Latency Comparison with and without eBPF')
ax.legend()

# Display the plot
plt.tight_layout()
plt.show()