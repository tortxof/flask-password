import string
from collections import defaultdict
import random
import itertools
import bisect

def pairwise(iterable):
    """
    Yield pairs of consecutive elements in iterable.

    >>> list(pairwise('abcd'))
    [('a', 'b'), ('b', 'c'), ('c', 'd')]
    """
    iterator = iter(iterable)
    try:
        a = iterator.__next__()
    except StopIteration:
        return
    for b in iterator:
        yield a, b
        a = b

with open('corpus.txt') as f:
    corpus = f.read()

corpus = ''.join(c.lower() if c in string.ascii_letters else ' ' for c in corpus).split()
corpus = [word for word in corpus if len(word) > 1]
counts = defaultdict(lambda: defaultdict(int))
for word in corpus:
    for a, b in pairwise(word):
        counts[a][b] += 1

sys_rand = random.SystemRandom()

def gen_password(l=12):
    password = []
    state = sys_rand.choice(string.ascii_lowercase)
    password.append(state)
    while len(password) < l:
        choices, weights = zip(*counts[state].items())
        cumdist = list(itertools.accumulate(weights))
        x = sys_rand.random() * cumdist[-1]
        state = choices[bisect.bisect(cumdist, x)]
        password.append(state)
    return ''.join(password)

print(gen_password())
