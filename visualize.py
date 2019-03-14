import pydot
from collections import OrderedDict


with open("info.txt", "r") as f:
    lines = f.readlines()


def fold(s, n, maxline=3):
    ret = []
    size = len(s)
    if size <= n: return s
    line = min(maxline, (size - 1)// n + 1)
    n = (size - 1) // line + 1
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

    def add(self, c):
        c.parent = self
        self.children.append(c)

    def trim(self):
        self.children = [c for c in self.children if c.trim()]
        return len(self.children) > 0
    
    def collect(self, container):
        for c in self.children:
            c.collect(container)


class DataNode(Node):

    def __init__(self):
        super(DataNode, self).__init__()
        self.data = []

    def name(self):
        return fold(str(self.data)[1:-1], 12)

    def empty(self):
        return not self.data

    def trim(self):
        return len(self.data) > 0

    def add(self, c):
        size = len(c)
        if not size: return
        if size == 1: c = c[0]
        if c not in self.data:
            self.data.append(c)

    def collect(self, container):
        container.append(self.data)


class MemoryBlock:

    def __init__(self):
        self.container = OrderedDict()
        self.max = None
        self.min = None
        self.thres = 0x40
    
    def valid(self, addr):
        return addr >= self.min - self.thres and addr <= self.max + self.thres
    
    def add(self, addr, offset, size):
        if not self.max or addr + size - 1 > self.max:
            self.max = addr + size -1
        if not self.min or addr < self.min:
            self.min = addr        
        while size > 0:
            self.container[addr] = offset
            addr += 1
            offset += 1
            size -= 1
    
    def remove(self, addr, size):
        while size > 0:
            del self.container[addr]
            addr += 1
            size -= 1
    
    def snapshot(self):
        for k, v in self.container.items():
            print(k, v)


class Memory:

    def __init__(self):
        self.container = []

    def index(self, addr):
        for c in self.container:
            if c.valid(addr): return c
        self.container.append(MemoryBlock())
        return self.container[-1]

    def add(self, addr, offset, size):
        self.index(addr).add(addr, offset, size)

    def remove(self, addr, size):
        self.index(addr).remove(addr, size)

    def snapshot(self):
        for c in self.container:
            c.snapshot()


root = FuncNode("")
cur_f = root
cur_d = DataNode()
memory = Memory()

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
        cur_d.add([int(c) for c in data.split(",")])
    elif tag.startswith("Memory"):
        addr = int(content[2].split(":")[1], 16)
        src = int(content[3].split(":")[1], 16)
        offset = int(content[4].split(":")[1], 16)
        size = int(content[5].split(":")[1], 16)
        bigendian = int(content[6].split(":")[1])
        if data == "Taint":
            memory.add(addr, offset, size)
        elif data == "Untaint":
            memory.remove(addr, size)


graph = pydot.Dot(graph_type='graph')
root.trim()
root = root[0]
graph.add_node(pydot.Node(root.id(), label=root.name()))
root.construct(graph)
graph.write_png('graph.png')
memory.snapshot()
container = []
root.collect(container)
print(container)