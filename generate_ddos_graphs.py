import matplotlib.pyplot as plt
import numpy as np
import re

def read_data(filename, regex_pattern):
    times = []

    with open(filename, 'r') as file:
        for line in file:
            match = re.search(regex_pattern, line)
            if match:
                time = float(match.group(1))
                times.append(time)

    return times

def plot_graph(times, title, xlabel, ylabel, output_filename):
    # Calculate the number of packets/pings for each unique time
    unique_times, counts = np.unique(times, return_counts=True)

    plt.figure(figsize=(10, 6))
    plt.plot(unique_times, counts, marker='o')

    plt.xscale('log')
    plt.yscale('log')

    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)

    plt.grid(True, which="both", ls="--")
    plt.savefig(output_filename)
    plt.show()

    return np.mean(times), np.std(times)

def main():
    # Regular expressions for matching packet times and ping RTTs
    packet_time_pattern = r'\d+\s+([\d\.]+)\s+ms'
    ping_time_pattern = r'time=([\d\.]+)\s+ms'

    # File paths and configuration for the graphs
    input_filenames = {
        'C Program (Packets)': {
            'file': 'syns_results_c.txt',
            'pattern': packet_time_pattern,
            'xlabel': 'Time to Send Packet (ms)',
            'ylabel': 'Number of Packets Sent',
            'output': 'Syn_pkts_c.png'
        },
        'Python Program (Packets)': {
            'file': 'syns_results_p.txt',
            'pattern': packet_time_pattern,
            'xlabel': 'Time to Send Packet (ms)',
            'ylabel': 'Number of Packets Sent',
            'output': 'Syn_pkts_p.png'
        },
        'C Program (Pings)': {
            'file': 'pings_results_c.txt',
            'pattern': ping_time_pattern,
            'xlabel': 'RTT (ms)',
            'ylabel': 'Number of Pings',
            'output': 'Pings_c.png'
        },
        'Python Program (Pings)': {
            'file': 'pings_results_p.txt',
            'pattern': ping_time_pattern,
            'xlabel': 'RTT (ms)',
            'ylabel': 'Number of Pings',
            'output': 'Pings_p.png'
        }
    }

    for label, details in input_filenames.items():
        # Read data from the file
        times = read_data(details['file'], details['pattern'])

        # Plot the graph and save it
        avg, std_dev = plot_graph(
            times,
            title=f'{label} - Time vs Number',
            xlabel=details['xlabel'],
            ylabel=details['ylabel'],
            output_filename=details['output']
        )

        # Print the average and standard deviation for each data set
        print(f'{label} - Average: {avg:.4f} ms, Standard Deviation: {std_dev:.4f} ms')

if __name__ == "__main__":
    main()
