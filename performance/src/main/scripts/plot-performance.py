#!/usr/bin/env python
"""
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This program parses JMH benchmarks and graphs them.
"""

from collections import namedtuple
import json
import locale
from os import mkdir, path

from cycler import cycler
from enum import Enum
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
import scipy.stats as stats

# Make sure the output directory exists
output_directory = path.join('./performance_graphs/')
if not path.exists(output_directory):
    mkdir(output_directory)

# Named tuples and enum
Benchmark = namedtuple('Benchmark', ['filename', 'config_files'])
MeasurementPlot = namedtuple('MeasurementPlot', ['benchmark_name', 'configs', 'params', 'plot_options'])
RunParams = namedtuple('RunParams', ['rows', 'columns', 'keySize', 'valueSize'])
RunKey = namedtuple('RunKey', ['config_file', 'run_params'])
RunValue = namedtuple('RunValue', ['score', 'error'])
class GraphType(Enum):
    total_time = 1
    time_per_op = 2
    ops_per_time = 3

# Available benchmarks
benchmarks = {
    'Encryption (Read)': Benchmark('jmh-encryption-read.json', {
        'Accumulo': '',
        'Field-Level': 'encryption/encrypt-baseline.ini',
        'CEABAC': 'encryption/encrypt-value.ini',
        'CEABAC-Entry': 'encryption/encrypt-entry.ini',
        'Searchable': 'encryption/searchable.ini',
    }),
    'Encryption (Write)': Benchmark('jmh-encryption-write.json', {
        'Accumulo': '',
        'Field-Level': 'encryption/encrypt-baseline.ini',
        'CEABAC': 'encryption/encrypt-value.ini',
        'CEABAC-Entry': 'encryption/encrypt-entry.ini',
        'Searchable': 'encryption/searchable.ini',
    }),
    'Signature (Read)': Benchmark('jmh-signature-read.json', {
        'Accumulo': '',
        'Value': 'signature/read/value.ini',
        'Visibility': 'signature/read/column.ini',
        'Table': 'signature/read/table.ini',
        'RSA-PKCS1': 'signature/rsa-pkcs1.ini',
        'RSA-PSS': 'signature/read/value.ini',
        'DSA': 'signature/dsa.ini',
        'ECDSA': 'signature/ecdsa.ini'
    }),
    'Signature (Write)': Benchmark('jmh-signature-write.json', {
        'Accumulo': '',
        'Value': 'signature/write/value.ini',
        'Visibility': 'signature/write/column.ini',
        'Table': 'signature/write/table.ini',
        'RSA-PKCS1': 'signature/rsa-pkcs1.ini',
        'RSA-PSS': 'signature/rsa-pss.ini',
        'DSA': 'signature/dsa.ini',
        'ECDSA': 'signature/write/value.ini'
    })
}

# Options list and various configurations
default_options = {
    'title': None,                  # graph's (optional) title
    'x_label': '',                  # graph's X label
    'x_tick_labels': '',            # graph's X tick labels
    'y_label': 'Operations / sec',  # graph's Y label
    
    'confidence_interval': .95,     # confidence interval to calculate
    'mode': GraphType.ops_per_time, # mode to graph
    'scale': 1000.0,                # multiply each data point by scale
    'figure_size': [8.0, 3.0],      # size of the figure area in inches

    'number_format': '%.0f',        # number format for data point labels
    'number_rotation': 75,          # rotation of numbers
    'number_y_offset': 0,           # offset of the y value to the bars

    'legend': True,                 # whether to display a legend
    'legend_location': 'best',      # legend location
    'legend_bounding_box': None,    # legend bounding box
    'legend_ncol': 2,               # number of columns in the legend

    'filename': None                # name of the file to save
}

configs_encryption = ['Accumulo', 'Field-Level', 'CEABAC', 'CEABAC-Entry', 'Searchable']
configs_signature = ['Accumulo', 'Value', 'Visibility', 'Table']
configs_signature_modes = ['RSA-PKCS1', 'RSA-PSS', 'DSA', 'ECDSA']

params_set_data_size = [
    RunParams(rows='1000', columns='10',   keySize='10', valueSize='10'),
    RunParams(rows='1000', columns='10',   keySize='100', valueSize='10'),
    RunParams(rows='1000', columns='10',   keySize='10', valueSize='1000'),
    RunParams(rows='1000', columns='10',   keySize='100', valueSize='1000')
]
params_set_operations = [
    RunParams(rows='10',   columns='1',   keySize='100', valueSize='1000'),
    RunParams(rows='100',  columns='1',   keySize='100', valueSize='1000'),
    RunParams(rows='1000', columns='1',   keySize='100', valueSize='1000'),
    RunParams(rows='1000', columns='10',  keySize='100', valueSize='1000')
]

x_label_operations = 'Batch Size'
x_label_data_size = 'Data Size'

x_tick_labels_operations = ('10', '100', '1,000', '10,000')
x_tick_labels_data_size = ('key=10 bytes,\nvalue=10 bytes',
                           'key=10 bytes,\nvalue=1,000 bytes',
                           'key=100 bytes,\nvalue=10 bytes',
                           'key=100 bytes,\nvalue=1,000 bytes')

figure_size_normal = [8.0, 3.0]
figure_size_wide = [16.0, 3.0]

# Load runs
def load_runs(benchmark_name, configs, params, options):
    """Function to load a benchmark."""
    benchmark = benchmarks[benchmark_name]
    with open(benchmark.filename) as file_handle:
        contents = json.load(file_handle)

        included_config_files = [benchmark.config_files[name] for name in configs]
        runs = dict()

        for run in contents:
            config_file = run['params']['configFile']
            run_params = RunParams(
                run['params']['rowCount'],
                run['params']['columnCount'],
                run['params']['keyFieldSize'],
                run['params']['valueFieldSize'])

            # Only save runs to be plotted
            if not config_file in included_config_files:
                continue
            if not run_params in params:
                continue

            # Generate the metric appropriately
            ops = float(run_params.rows) * float(run_params.columns)
            data = np.array([score for scores in run['primaryMetric']['rawData'] for score in scores])
            
            mode = options['mode']
            if mode is GraphType.total_time:
                pass
            elif mode is GraphType.time_per_op:
                data = data / ops
            elif mode is GraphType.ops_per_time:
                data = ops / data
            else:
                raise 'invalid graph type'

            data = data * options['scale']

            mean = np.mean(data)
            standard_error = stats.sem(data)
            interval = standard_error * stats.t.ppf((1 + options['confidence_interval']) / 2, len(data) - 1)
            runs[RunKey(config_file, run_params)] = RunValue(mean, interval)
    
        return runs

# Create graphs
plt.style.use('ggplot')

locale.setlocale(locale.LC_ALL, 'en_US')

colors = []
for item in plt.rcParams['axes.prop_cycle']:
    colors.append(item['color'])
colors.pop(3)
colors.append('purple')
colors.append('orange')
plt.rc('axes', prop_cycle=cycler('color', colors))

def plot_measurements(benchmark_name, configs, params, plot_options, show_figure=False):
    """ Plot measurements. """
    options = default_options.copy()
    options.update(plot_options)
    runs = load_runs(benchmark_name, configs, params, options)
    
    # Create the bar chart
    fig, ax = plt.subplots(figsize=options['figure_size'])
    extra_artists = []    

    bar_locs = np.arange(len(params)) * (len(configs) + 1) + 1
    bar_graphs = []

    for index, config in enumerate(configs):
        config_file = benchmarks[benchmark_name].config_files[config]
        means = []
        stds = []

        for run_params in params:
            run = runs[RunKey(config_file, run_params)]
            means.append(run.score)
            stds.append(run.error)

        bar_graph = ax.bar(bar_locs + index,
                        means,
                        color=colors[index % len(colors)],
                        yerr=stds,
                        error_kw=dict(ecolor='black', lw=.5, capsize=4, capthick=.5))
        bar_graphs.append(bar_graph)

    # Add some text for labels, title and axes ticks
    if options['title'] is not None:
        extra_artists.append(ax.set_title(options['title']))
    ax.set_xlabel(options['x_label'])
    ax.set_xticks(bar_locs + len(configs) / 2.)
    ax.set_xticklabels(options['x_tick_labels'])
    ax.set_ylabel(options['y_label'])

    if options['legend']:
        extra_artists.append(ax.legend(
            tuple([bar_graph[0] for bar_graph in bar_graphs]),
            tuple(configs),
            loc=options['legend_location'],
            bbox_to_anchor=options['legend_bounding_box'],
            ncol=options['legend_ncol']))

    for bar_graph in bar_graphs:
        for bar in bar_graph:
            height = bar.get_height()
            extra_artists.append(ax.text(
                bar.get_x() + bar.get_width() * 2./3.,
                height + options['number_y_offset'],
                locale.format(options['number_format'], height, grouping=True),
                ha='center',
                va='bottom',
                rotation=options['number_rotation']))

    # Show the plot
    if show_figure:
        plt.show()
    fig.savefig(path.join(output_directory, options['filename']),
                bbox_extra_artists=tuple(extra_artists),
                bbox_inches='tight')

def plot_legend(configs, filename, ncol=None):
    """Draw a legend by itself."""
    fig = plt.figure(figsize=(0.1, 0.1))
    patches = [mpatches.Patch(color=color, label=config) for config, color in zip(configs, colors)]
    legend = fig.legend(patches, configs, loc='center', ncol=ncol if ncol is not None else len(configs))
    fig.savefig(filename, bbox_extra_artists=(legend,), bbox_inches='tight')

# Plot legends.

# List all measurement plots and create them
plots = [
    MeasurementPlot('Encryption (Write)', configs_encryption, params_set_data_size, {
        'x_label': x_label_data_size,
        'x_tick_labels': x_tick_labels_data_size,
        'number_y_offset': 2500,
        'filename': 'encryption_write_data_size.pdf'
    }),
    MeasurementPlot('Encryption (Read)', configs_encryption, params_set_data_size, {
        'x_label': x_label_data_size,
        'x_tick_labels': x_tick_labels_data_size,
        'number_y_offset': 1000,
        'filename': 'encryption_read_data_size.pdf'
    }),
    MeasurementPlot('Encryption (Write)', configs_encryption, params_set_operations, {
        'x_label': x_label_operations,
        'x_tick_labels': x_tick_labels_operations,
        'number_y_offset': 250,
        'filename': 'encryption_write_operations.pdf'
    }),
    MeasurementPlot('Encryption (Read)', configs_encryption, params_set_operations, {
        'x_label': x_label_operations,
        'x_tick_labels': x_tick_labels_operations,
        'number_y_offset': 250,
        'filename': 'encryption_read_operations.pdf'
    }),
    MeasurementPlot('Signature (Write)', configs_signature, params_set_data_size, {
        'x_label': x_label_data_size,
        'x_tick_labels': x_tick_labels_data_size,
        'number_y_offset': 2500,
        'filename': 'signature_write_data_size.pdf'
    }),
    MeasurementPlot('Signature (Read)', configs_signature, params_set_data_size, {
        'x_label': x_label_data_size,
        'x_tick_labels': x_tick_labels_data_size,
        'number_y_offset': 1250,
        'filename': 'signature_read_data_size.pdf'
    }),
    MeasurementPlot('Signature (Write)', configs_signature, params_set_operations, {
        'x_label': x_label_operations,
        'x_tick_labels': x_tick_labels_operations,
        'number_y_offset': 125,
        'filename': 'signature_write_operations.pdf'
    }),
    MeasurementPlot('Signature (Read)', configs_signature, params_set_operations, {
        'x_label': x_label_operations,
        'x_tick_labels': x_tick_labels_operations,
        'number_y_offset': 125,
        'filename': 'signature_read_operations.pdf'
    }),
    MeasurementPlot('Signature (Write)', configs_signature_modes, params_set_data_size, {
        'x_label': x_label_data_size,
        'x_tick_labels': x_tick_labels_data_size,
        'number_y_offset': 250,
        'filename': 'signature_write_data_size_modes.pdf'
    }),
    MeasurementPlot('Signature (Read)', configs_signature_modes, params_set_data_size, {
        'x_label': x_label_data_size,
        'x_tick_labels': x_tick_labels_data_size,
        'number_y_offset': 250,
        'filename': 'signature_read_data_size_modes.pdf'
    }),
    MeasurementPlot('Signature (Write)', configs_signature_modes, params_set_operations, {
        'x_label': x_label_operations,
        'x_tick_labels': x_tick_labels_operations,
        'number_y_offset': 125,
        'filename': 'signature_write_operations_modes.pdf'
    }),
    MeasurementPlot('Signature (Read)', configs_signature_modes, params_set_operations, {
        'x_label': x_label_operations,
        'x_tick_labels': x_tick_labels_operations,
        'number_y_offset': 125,
        'filename': 'signature_read_operations_modes.pdf'
    })
]

for plot in plots:
    plot_measurements(plot.benchmark_name, plot.configs, plot.params, plot.plot_options)
