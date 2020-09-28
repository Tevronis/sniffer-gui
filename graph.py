import utils


class Graph:
    def __init__(self):
        pass

    def updateVisual(self):
        pass

    @staticmethod
    def readMatrixFromTerminal():
        n = int(input())
        M = [[0 for y in range(n)] for x in range(n)]
        for i in range(n):
            M[i] = list(map(int, input().split()))
        return M

    @staticmethod
    def readMatrixFromFile(file_name):
        with open(file_name) as f:
            n = int(f.readline().strip())
            M = [[0 for y in range(n)] for x in range(n)]
            for i in range(n):
                line = f.readline()
                M[i] = list(map(int, line.split()))
        return M

    @staticmethod
    def readAdjacencyListToMatrix():
        n, m = map(int, input().split())
        M = [[0 for y in range(n)] for x in range(n)]
        for i in range(m):
            x, y, c = map(int, input().split())
            M[x - 1][y - 1] = c
        return M

    @staticmethod
    def initGraphFromMatrix(M):
        n = len(M)
        G = [[utils.edge(cup=M[x][y]) for y in range(n)] for x in range(n)]
        return G

    @staticmethod
    def default(n):
        G = [[utils.edge() for y in range(n)] for x in range(n)]
        G[0][1].cup = 3
        G[1][3].cup = 1
        G[0][2].cup = 1
        G[2][3].cup = 2
        G[1][2].cup = 1
        return G