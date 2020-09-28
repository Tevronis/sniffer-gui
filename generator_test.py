import argparse
import random
import sys

from utils import log_report, matrix_to_str


def generate_allow_edges(n):
    result = []
    for idx in range(n):
        for idy in range(n):
            if idx != idy:
                result.append((idx, idy))
    return result


class GraphGenerator:
    def __init__(self, params):
        self.n = random.randint(2, 10) if params.n is None else params.n
        self.m = random.randint(2, 10) if params.m is None else params.m
        if self.m > self.n * (self.n - 1):
            self.m = self.n * (self.n - 1)
        self.const_cup_mod, self.const_cup_value = (False, 0) if params.max_cup is None else (True, params.cup)
        self.max_cup = 20 if params.max_cup is None else params.max_cup
        self.duo_mod = False # False if params.duo is None else True
        self.allowable_edges = []

    def gen_matrix(self):
        def get_indexes():
            x, y = random.choice(self.allowable_edges)
            self.allowable_edges.remove((x, y))
            return x, y

        result = [[0 for x in range(self.n)] for y in range(self.n)]
        for x in range(self.m):
            idx, idy = get_indexes()
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
        while not self.check_way(result):
            self.allowable_edges = generate_allow_edges(self.n)
            result = self.gen_matrix()
        # log_report('Generate graph:\n', matrix_to_str(result))
        return result

    def generate_cup(self):
        if self.const_cup_mod:
            return self.const_cup_value
        return random.randint(1, self.max_cup)

    def __next__(self):
        return self.gen()


def parseargs(args):
    parser = argparse.ArgumentParser()
    #parser.add_argument('duo')
    parser.add_argument('--n', type=int)
    parser.add_argument('--m', type=int)
    parser.add_argument('--cup', type=int)
    parser.add_argument('--max_cup', type=int)
    parser.add_argument('--fromfile', type=str)
    return parser.parse_args(args)


def main():
    args = sys.argv[1:]
    # args = ['--n', '8', '--m', '20']
    params = parseargs(args)
    generator = GraphGenerator(params)
    g = next(generator)
    e = 0
    for i in range(len(g)):
        for j in range(len(g)):
            if g[i][j] > 0:
                e += 1
            print(g[i][j], end=' ')
        print()
    print(e)


if __name__ == '__main__':
    main()
