import json
from functools import total_ordering

@total_ordering
class TaintTrace:
    def __init__(self, trace):
        self.trace = trace
        self.start = trace["start"]
        self.end = trace["end"]
        self.offset = trace["start"]["offset"]
        self._context = trace["context"]
        self.next_traces = set()

    @property
    def context(self):
        return self._context.replace('"', '#quot;').replace("'", '#apos;').replace("<", "&lt;").replace(">", "&gt;").replace("\n", '<br>')

    def set_next_traces(self, next_traces):
        self.next_traces = set(next_traces)

    def update_traces(self, other):
        self.next_traces.update(other)

    def mermaid_node_name(self):
        return f"{hash(self)}[\"{self.context}\"] "

    def to_mermaid_node(self):
        for trace in self.next_traces:
            yield f"{hash(self)} --> {hash(trace)}"

    def __hash__(self):
        return hash((self.offset, self.context))

    def __eq__(self, other):
        return self.offset == other.offset and self.context == other.context

    def __lt__(self, other):
        return self.offset < other.offset

    def __repr__(self):
        return str(self)

    def __str__(self):
        return str({
            "start": self.start,
            "end": self.end,
            "offset": self.offset,
            "context": self.context,
            "next_traces": self.next_traces
        })

class TaintTraceGraph:

    def __init__(self, sources, intermediates, sinks):
        sources = sorted(sources)
        intermediates = sorted(intermediates)
        sinks = sorted(sinks)
        for source in range(len(sources) - 1):
            sources[source].set_next_traces([sources[source + 1]])
        sources[-1].set_next_traces([intermediates[0] if len(intermediates) > 0 else sinks[0]])
        for i in range(len(intermediates) - 1):
            intermediates[i].set_next_traces([intermediates[i + 1]])
        if len(intermediates) > 0:
            intermediates[-1].set_next_traces([sinks[0]])
        self.sources = sources
        self.intermediates = intermediates
        self.sinks = sinks

    def intersects(self, other):
        return bool(
            set(self.sources).intersection(other.sources) or
            set(self.intermediates).intersection(other.intermediates) or
            set(self.sinks).intersection(other.sinks)
        )

    def update(self, other):
        self.sources.extend(other.sources)
        self.intermediates.extend(other.intermediates)
        self.sinks.extend(other.sinks)

    def to_graph(self):
        nodes = set()
        styles = set()
        links = set()
        for source in self.sources:
            nodes.update(list(source.to_mermaid_node()))
        for intermediate in self.intermediates:
            nodes.update(list(intermediate.to_mermaid_node()))
        for sink in self.sinks:
            nodes.update(list(sink.to_mermaid_node()))

        nodes_str = '\n'.join(nodes)
        source_names = '\n'.join(set([source.mermaid_node_name() for source in self.sources]))
        intermediate_names = '\n'.join(set([intermediate.mermaid_node_name() for intermediate in self.intermediates]))
        sink_names = '\n'.join(set([sink.mermaid_node_name() for sink in self.sinks]))

        return f"""
```mermaid
graph LR;
    subgraph sources
        {source_names}
    end
    {intermediate_names}
    subgraph sinks
        {sink_names}
    end
    {nodes_str}
```
        """


    def __repr__(self):
        return str(self)

    def __str__(self):
        return str({
            "sources": list(self.sources),
            "intermediates": list(self.intermediates),
            "sinks": list(self.sinks)
        })


header = """
User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorization information sent with this request. They could also probe internal servers or other resources that the server runnig this code can access. (This is called server-side request forgery, or SSRF.) Do not allow arbitrary hosts. Instead, create an allowlist for approved hosts hardcode the correct host.

"""
footer = """
<a href='https://semgrep.dev/api/agent/deployments/1/issues/2768289/sentiment?hash=b6f1aea1d8e80b03d06c147424b182bc35ecc0b0ee87971eeb859180dd1c9140&sentiment=bad&utm_campaign=finding_notification&utm_medium=review_comment&utm_source=github&utm_content=logo'>
<img align='right' src='https://img.shields.io/badge/-Not%20helpful%20%F0%9F%91%8E-%235F36D9' height=24px alt='' />
</a>
<sub>⚪️ This finding does not block your pull request.
</sub><br/><sub>
🙈 From <a href='https://semgrep.dev/r/python.flask.security.injection.tainted-url-host.tainted-url-host'>python.flask.security.injection.tainted-url-host.tainted-url-host</a>.
</sub>
"""
def text_ranges_overlap(range1, range2) -> bool:
    return bool(
        range1["start"]["line"] <= range2["end"]["line"]
        and range1["end"]["line"] >= range2["start"]["line"]
        and range1["start"]["col"] < range2["end"]["col"]
        and range1["end"]["col"] > range2["start"]["col"]
    )

def associate_info(ranges, file_contents):
    for range in ranges:
        range['context'] = file_contents[range['start']['offset']:range['end']['offset']]
    ranges = list(map(lambda x: TaintTrace(x), ranges))
    ranges = list(filter(lambda x: x.context != ".", ranges))
    return ranges

def format_source(dataflow,contents):
    sink = [dataflow]
    source = dataflow['extra']['dataflow_trace']['taint_source']
    intermediate = dataflow['extra']['dataflow_trace']['intermediate_vars']
    sources = associate_info(source,contents)
    intermediates = associate_info(intermediate,contents)
    sinks = associate_info(sink,contents)
    return (sources,intermediates,sinks)

def build_base():
    nodes = ""
    links = ""
    classes = ""
    GRAPH_BASE = f"""
<sub>
<details>
<summary>View Taint Trace</summary>
```mermaid
flowchart LR;
    {nodes}

    {links}

    classDef source fill:#ebf2fc,stroke:#193c47
    classDef im fill:#ebf2fc,stroke:#193c47,stroke-dasharray: 5 5
    classDef sink fill:#ebf2fc,stroke:#193c47,stroke-width: 2px
    {classes}
```

<br>
</details>
</sub>
"""

with open("out.json") as f:
    with open("code.py") as f2:
        data = json.load(f)
        contents = f2.read()
        results = {}
        for r in data["results"]:
            if "dataflow_trace" in r["extra"]:
                if not r["check_id"] in results:
                    results[r["check_id"]] = []
                b,i,e = format_source(r,contents)
                results[r["check_id"]].append(TaintTraceGraph(b,i,e))

for res in results:
    final = []
    seen = []
    for g in results[res]:
        if g in seen:
            continue
        for h in results[res]:
            if h in seen:
                continue
            if g == h:
                continue
            if g.intersects(h):
                g.update(h)
                seen.append(h)
        final.append(g)
    print(final, len(final))


    for f in final:
        print(f.to_graph())
