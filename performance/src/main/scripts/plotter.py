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
from cycler import cycler
import json
import matplotlib.pyplot as plt
import numpy as np

# Named tuples
Benchmark = namedtuple('Benchmark', ['filename', 'configs', 'runs'])
RunParams = namedtuple('RunParams',
                       ['config', 'rows', 'columns', 'keySize', 'valueSize'])
Run = namedtuple('Run', ['score', 'error'])

# Available benchmarks
benchmarks = {
    'Encryption (Read)': Benchmark('./jmh-encryption-read.json', {
        'Accumulo': '',
        'Value': 'encryption/encrypt-value.ini',
        'Entry': 'encryption/encrypt-entry.ini',
        'Searchable': 'encryption/searchable.ini'
    }, dict()),
    'Encryption (Write)': Benchmark('./jmh-encryption-write.json', {
        'Accumulo': '',
        'Value': 'encryption/encrypt-value.ini',
        'Entry': 'encryption/encrypt-entry.ini',
        'Searchable': 'encryption/searchable.ini'
    }, dict()),
    'Signature (Read)': Benchmark('./jmh-signature-read.json', {
        'Accumulo': '',
        'Value': 'signature/read/value.ini',
        'Column': 'signature/read/column.ini',
        'Table': 'signature/read/table.ini',
        'RSA-PKCS1': 'signature/rsa-pkcs1.ini',
        'RSA-PSS': 'signature/read/value.ini',
        'DSA': 'signature/dsa.ini',
        'ECDSA': 'signature/ecdsa.ini'
    }, dict()),
    'Signature (Write)': Benchmark('./jmh-signature-write.json', {
        'Accumulo': '',
        'Value': 'signature/write/value.ini',
        'Column': 'signature/write/column.ini',
        'Table': 'signature/write/table.ini',
        'RSA-PKCS1': 'signature/rsa-pkcs1.ini',
        'RSA-PSS': 'signature/rsa-pss.ini',
        'DSA': 'signature/dsa.ini',
        'ECDSA': 'signature/write/value.ini'
    }, dict())
}

# Set what to graph
benchmark_name = 'Encryption (Read)'
configs = ['Accumulo', 'Value', 'Entry', 'Searchable']
params = [
    RunParams(None, rows='1',    columns='1',   keySize='100', valueSize='1000'),
    RunParams(None, rows='10',   columns='1',   keySize='100', valueSize='1000'),
    RunParams(None, rows='100',  columns='1',   keySize='100', valueSize='1000'),
    RunParams(None, rows='1000', columns='1',   keySize='100', valueSize='1000'),
    RunParams(None, rows='1000', columns='10',  keySize='100', valueSize='1000')
]

x_label = 'Inserts'
x_tick_labels = ('1', '10', '100', '1000', '10000')

time_per_operation = True

# Parse the benchmark
benchmark = benchmarks[benchmark_name]
with open(benchmark.filename) as file_handle:
    contents = json.load(file_handle)

    included_configs = [benchmark.configs[name] for name in configs]

    for run in contents:
        runParams = RunParams(
            run['params']['configFile'],
            run['params']['rowCount'],
            run['params']['columnCount'],
            run['params']['keyFieldSize'],
            run['params']['valueFieldSize'])

        # Only save runs to be plotted
        if not runParams.config in included_configs:
            continue
        if not runParams._replace(config=None) in params:
            continue

        # As needed scale results to individual iterations
        if time_per_operation:
            scale = float(runParams.rows) * float(runParams.columns)
        else :
            scale = 1

        benchmark.runs[runParams] = Run(
            run['primaryMetric']['score'] / scale,
            0#run['primaryMetric']['scoreError'] / scale
        )

    # Create the graphing environment
plt.style.use('ggplot')

colors = []
for item in plt.rcParams['axes.prop_cycle']:
    colors.append(item['color'])
colors.append('purple')
plt.rc('axes', prop_cycle=cycler('color', colors))

fig, ax = plt.subplots()

# Create the bar chart
bar_locs = np.arange(len(params)) * (len(configs) + 1) + 1
bar_graphs = []

for index, config in enumerate(configs):
    means = []
    stds = []

    for runParams in [rp._replace(config=benchmark.configs[config]) for rp in params]:
        run = benchmark.runs[runParams]
        means.append(run.score)
        stds.append(run.error)

    bar_graph = ax.bar(bar_locs + index,
                       means,
                       color=colors[index % len(colors)],
                       yerr=stds)
    bar_graphs.append(bar_graph)

# Add some text for labels, title and axes ticks
ax.set_ylabel('Time (ms)')
ax.set_xlabel(x_label)
ax.set_title(benchmark_name)
ax.set_xticks(bar_locs + len(configs) / 2.)
ax.set_xticklabels(x_tick_labels)

ax.legend(
    tuple([bar_graph[0] for bar_graph in bar_graphs]),
    tuple(configs),
    loc='upper right',
    ncol=2)

for bar_graph in bar_graphs:
    for bar in bar_graph:
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2.,
            1.05 * height,
            '%.2f' % height,
            ha='center',
            va='bottom')

# Show the plot
plt.show()
