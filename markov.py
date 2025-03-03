import json
import random
import string
from collections import defaultdict


def pairwise(iterable):
    """
    Yield pairs of consecutive elements in iterable.

    >>> list(pairwise('abcd'))
    [('a', 'b'), ('b', 'c'), ('c', 'd')]
    """
    iterator = iter(iterable)
    try:
        a = next(iterator)
    except StopIteration:
        return
    for b in iterator:
        yield a, b
        a = b


def generate_counts(corpus_file="corpus.txt", counts_file="counts.json"):
    with open(corpus_file) as f:
        corpus = f.read()
    corpus = "".join(
        c.lower() if c in string.ascii_letters else " " for c in corpus
    ).split()
    corpus = [word for word in corpus if len(word) > 1]
    counts = defaultdict(lambda: defaultdict(int))
    for word in corpus:
        for a, b in pairwise(word):
            counts[a][b] += 1
    with open(counts_file, "w") as f:
        json.dump(counts, f)


class Markov(object):
    def __init__(self, counts_file="counts.json"):
        self.sys_rand = random.SystemRandom()
        with open(counts_file) as f:
            self.counts = json.load(f)

    def gen_password(self, l=16):
        password = []
        password.append(self.sys_rand.choice(string.ascii_lowercase))
        while len(password) < l:
            choices, weights = zip(*self.counts[password[-1]].items())
            password.append(self.sys_rand.choices(choices, weights=weights)[0])
        cap, num = self.sys_rand.sample(range(len(password)), 2)
        password[num] = str(self.sys_rand.randrange(10))
        password[cap] = password[cap].upper()
        return "".join(password)
