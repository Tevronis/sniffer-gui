import random

from defines import *
from graph import Graph
from utils import log_report, matrix_to_str


def generate_allow_edges(n):
    result = []
    for idx in range(n-1):
        for idy in range(1, n):
            if idx != idy:
                result.append((idx, idy))
    return result


class GraphGenerator:
    def __init__(self, params):
        self.file = params.file if not (params.file is None) else None
        self.n = random.randint(2, 20) if params.n is None else params.n
        self.m = random.randint(self.n - 1, (self.n * (self.n - 1)) // 2) if params.m is None else params.m
        if self.m > (self.n * (self.n - 1)) // 2:
            self.m = (self.n * (self.n - 1)) // 2
        self.const_cup_mod, self.const_cup_value = (False, 0) if params.cup is None else (True, params.cup)
        self.max_cup = 20 if params.max_cup is None else params.max_cup
        self.duo_mod = False
        self.allowable_edges = []

    def gen_matrix(self):
        def get_indexes():
            if len(self.allowable_edges) == 0:
                return None, None
            x, y = random.choice(self.allowable_edges)
            self.allowable_edges.remove((x, y))
            try:
                self.allowable_edges.remove((y, x))
            except: pass
            return x, y

        result = [[0 for x in range(self.n)] for y in range(self.n)]
        for x in range(self.m):
            idx, idy = get_indexes()
            if idx is None:
                break
            result[idx][idy] = self.generate_cup()
        return result

    def check_way(self, M):
        if M is None:
            return False
        result = False

        def duo():
            part = [-1 for i in range(self.n)]
            ok = True
            q = [0 for i in range(self.n)]
            for st in range(self.n):
                if part[st] == -1:
                    h, t = 0, 0
                    q[t] = st
                    t += 1
                    part[st] = 0
                    while h < t:
                        v = q[h]
                        h += 1
                        for i in range(len(M)):
                            if not M[v][i]:
                                continue
                            to = i
                            if part[to] == -1:
                                part[to] = not part[v]
                                q[t] = to
                                t += 1
                            else:
                                ok &= part[to] != part[v]

            return ok

        def dfs(u):
            used[u] = True
            if u == len(M) - 1:
                return
            for to in range(self.n):
                if not used[to] and M[u][to]:
                    dfs(to)

        used = [False for i in range(self.n)]
        dfs(0)
        if used[len(M) - 1]:
            result = True
        if self.duo_mod:
            result *= duo()

        return result

    def gen(self):
        result = None
        if not (self.file is None):
            return Graph.readMatrixFromFile(self.file)

        while not self.check_way(result):
            self.allowable_edges = generate_allow_edges(self.n)
            result = self.gen_matrix()
        log_report('Generate graph:\n', matrix_to_str(result))
        return result

    def generate_cup(self):
        if self.const_cup_mod:
            return self.const_cup_value
        return random.randint(1, self.max_cup)

    def __next__(self):
        return self.gen()
