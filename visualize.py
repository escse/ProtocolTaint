import pydot

with open("info.txt", "r") as f:
    lines = f.readlines()


def fold(s, n, maxline=3):
    ret = []
    size = len(s)
    line = (size - 1)// n + 1
    if line >= maxline:
        n = (size - 1) // maxline + 1
        line = maxline
    for i in range(line):
        ret.append(s[n * i : n * (i+1)])
        ret.append("\n")
    ret.pop()
    return "".join(ret)
    

class Node(object):
    _id = 0

    def __init__(self):
        self._id = Node._id
        Node._id += 1
        self.parent = None
        self.children = []
    
    def name(self):
        return ""

    def id(self):
        return "{}-{}".format(self.name(), self._id)

    def __getitem__(self, s):
        return self.children[s]

    def __len__(self):
        return len(self.children)

    def add(self, c):
        c.parent = self
        self.children.append(c)
    
    def construct(self, graph):    
        for child in self.children:
            graph.add_node(pydot.Node(child.id(), label=child.name()))
            edge = pydot.Edge(self.id(), child.id())
            graph.add_edge(edge)
            child.construct(graph)


class FuncNode(Node):

    def __init__(self, name):
        super(FuncNode, self).__init__()
        self.name_ = name
    
    def name(self):
        return fold(self.name_, 12)

    def trim(self):
        self.children = [c for c in self.children if c.trim()]
        return len(self.children) > 0


class DataNode(Node):

    def __init__(self):
        super(DataNode, self).__init__()
        self.data = []

    def name(self):
        return fold(str(self.data).replace('\'', '')[1:-1], 12)

    def empty(self):
        return not self.data

    def trim(self):
        return len(self.data) > 0

    def add(self, c):
        size = len(c)
        if not size: return
        if size == 1:
            if not self.data or self.data[-1] != c[0]:
                self.data.append(c[0])
        else:
            while self.data and (self.data[-1] in c or self.data[-1] == c):
                self.data.pop()
            self.data.append(c)
    

root = FuncNode("")
cur_f = root
cur_d = DataNode()
for line in lines:
    content = line.strip().split('\t')
    tag = content[0]
    data = content[1]
    if tag == "enter":
        node = FuncNode(data)
        if not cur_d.empty():
            cur_f.add(cur_d)
            cur_d = DataNode()
        cur_f.add(node)
        cur_f = node
    elif tag == "exit":
        if not cur_d.empty():
            cur_f.add(cur_d)
            cur_d = DataNode()
        cur_f = cur_f.parent

    elif tag.startswith("Instruction"):
        cur_d.add(data.split(","))

# root.cont()
graph = pydot.Dot(graph_type='graph')
root.trim()
root = root[0]
graph.add_node(pydot.Node(root.id(), label=root.name()))
root.construct(graph)
graph.write_png('graph.png')