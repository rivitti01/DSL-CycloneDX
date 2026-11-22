#!/usr/bin/env python3
"""LL(1) checker for the syntactic grammar in docs/grammar.md.

It extracts the ```ebnf blocks of section "2. Syntactic Grammar", rewrites the EBNF operators
into plain BNF, computes FIRST/FOLLOW sets and reports every LL(1) conflict:

  FIRST/FIRST   two alternatives of a non-terminal can start with the same token
  FIRST/FOLLOW  an alternative derives the empty string and a token in FOLLOW could also
                start another alternative

Usage:  python3 tools/check_ll1.py [docs/grammar.md] [--verbose]
Exit status: 0 if the grammar is LL(1), 1 if there are conflicts or undefined symbols.

Supported EBNF:  A ::= ...   |   [ X ]   ( X )   ( X )*   ( X )+   "terminal"   'terminal'
                 (* comment *)    an alternative with no symbols is the empty string
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

# Token classes produced by the lexer (terminals that are not written in quotes).
TOKEN_CLASSES = {"Identifier", "StringLiteral", "IntegerLiteral", "FloatLiteral",
                 "BooleanLiteral", "EOF"}
START_SYMBOL = "Program"
EPS = "ε"
END = "$"


def extract_syntactic_ebnf(markdown: str) -> str:
    """Return the ebnf code blocks between '## 2.' and '## 3.'."""
    m = re.search(r"^## 2\..*?(?=^## 3\.)", markdown, re.S | re.M)
    if not m:
        sys.exit("error: section '## 2. ...' not found")
    blocks = re.findall(r"^```ebnf\n(.*?)^```", m.group(0), re.S | re.M)
    if not blocks:
        sys.exit("error: no ```ebnf blocks found in section 2")
    return "\n".join(blocks)


def split_rules(text: str) -> list[tuple[str, str]]:
    text = re.sub(r"\(\*.*?\*\)", " ", text, flags=re.S)  # (* comments *)
    rules: list[tuple[str, str]] = []
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z_]\w*)\s*::=(.*)", line)
        if m:
            rules.append((m.group(1), m.group(2)))
        elif line.strip():
            if not rules:
                sys.exit(f"error: continuation line before the first rule: {line!r}")
            name, body = rules[-1]
            rules[-1] = (name, body + " " + line)
    return rules


def tokenize(body: str) -> list[str]:
    toks = re.findall(r'"[^"]*"|\'[^\']*\'|[\[\]()|*+]|[A-Za-z_]\w*|\S', body)
    bad = [t for t in toks if len(t) == 1 and t not in "[]()|*+" and not t.isalnum()]
    if bad:
        sys.exit(f"error: unexpected characters in EBNF: {bad}")
    return toks


class Grammar:
    """BNF grammar obtained from EBNF; synthetic non-terminals are named Owner#n."""

    def __init__(self) -> None:
        self.prods: dict[str, list[list[str]]] = {}
        self.origin: dict[str, str] = {}
        self.order: list[str] = []
        self._n = 0

    def _fresh(self, owner: str, desc: str) -> str:
        self._n += 1
        name = f"{owner}#{self._n}"
        self.origin[name] = desc
        return name

    def add_rule(self, name: str, body: str) -> None:
        if name in self.prods:
            sys.exit(f"error: non-terminal {name} defined twice")
        toks = tokenize(body)
        alts, i = self._alts(toks, 0, name)
        if i != len(toks):
            sys.exit(f"error: cannot parse rule {name} near {' '.join(toks[i:i + 5])!r}")
        self.prods[name] = alts
        self.order.append(name)

    def _alts(self, toks, i, owner):
        seq, i = self._seq(toks, i, owner)
        alts = [seq]
        while i < len(toks) and toks[i] == "|":
            seq, i = self._seq(toks, i + 1, owner)
            alts.append(seq)
        return alts, i

    def _group(self, toks, i, owner, close):
        start = i
        inner, i = self._alts(toks, i + 1, owner)
        if i >= len(toks) or toks[i] != close:
            sys.exit(f"error: missing '{close}' in rule {owner}")
        return inner, i + 1, " ".join(toks[start + 1:i])

    def _seq(self, toks, i, owner):
        out: list[str] = []
        while i < len(toks) and toks[i] not in ("|", ")", "]"):
            t = toks[i]
            if t == "[":
                inner, i, text = self._group(toks, i, owner, "]")
                nt = self._fresh(owner, f"[ {text} ]")
                self.prods[nt] = inner + [[]]
                out.append(nt)
            elif t == "(":
                inner, i, text = self._group(toks, i, owner, ")")
                rep = toks[i] if i < len(toks) and toks[i] in ("*", "+") else ""
                i += bool(rep)
                if rep == "*":
                    nt = self._fresh(owner, f"( {text} )*")
                    self.prods[nt] = [alt + [nt] for alt in inner] + [[]]
                    out.append(nt)
                elif rep == "+":
                    body = self._fresh(owner, f"( {text} )")
                    self.prods[body] = inner
                    tail = self._fresh(owner, f"( {text} )+")
                    self.prods[tail] = [[body, tail], []]
                    out += [body, tail]
                else:
                    nt = self._fresh(owner, f"( {text} )")
                    self.prods[nt] = inner
                    out.append(nt)
            else:
                out.append(t[1:-1] if t[0] in "\"'" else t)
                i += 1
        return out, i


def analyse(g: Grammar):
    nts = set(g.prods)
    terminals_used = {s for alts in g.prods.values() for a in alts for s in a if s not in nts}
    # A bare (unquoted) symbol that is not a token class must be a non-terminal.
    undefined = sorted(s for s in terminals_used
                       if re.fullmatch(r"[A-Za-z_]\w*", s) and not s.isupper()
                       and s not in TOKEN_CLASSES)

    first: dict[str, set[str]] = {nt: set() for nt in nts}

    def first_of(seq):
        out = set()
        for sym in seq:
            if sym not in nts:
                out.add(sym)
                return out
            out |= first[sym] - {EPS}
            if EPS not in first[sym]:
                return out
        out.add(EPS)
        return out

    changed = True
    while changed:
        changed = False
        for nt, alts in g.prods.items():
            for alt in alts:
                f = first_of(alt)
                if not f <= first[nt]:
                    first[nt] |= f
                    changed = True

    follow: dict[str, set[str]] = {nt: set() for nt in nts}
    if START_SYMBOL not in nts:
        sys.exit(f"error: start symbol {START_SYMBOL} not defined")
    follow[START_SYMBOL].add(END)
    changed = True
    while changed:
        changed = False
        for nt, alts in g.prods.items():
            for alt in alts:
                for k, sym in enumerate(alt):
                    if sym in nts:
                        f = first_of(alt[k + 1:])
                        add = (f - {EPS}) | (follow[nt] if EPS in f else set())
                        if not add <= follow[sym]:
                            follow[sym] |= add
                            changed = True

    conflicts = []
    for nt, alts in g.prods.items():
        predict = []
        for alt in alts:
            f = first_of(alt)
            predict.append((f - {EPS}, (f - {EPS}) | (follow[nt] if EPS in f else set())))
        for x in range(len(predict)):
            for y in range(x + 1, len(predict)):
                common = predict[x][1] & predict[y][1]
                if common:
                    both_first = common & predict[x][0] & predict[y][0]
                    kind = "FIRST/FIRST" if both_first else "FIRST/FOLLOW"
                    conflicts.append((nt.split("#")[0], g.origin.get(nt, nt), kind, sorted(common)))

    reachable, todo = {START_SYMBOL}, [START_SYMBOL]
    while todo:
        for alt in g.prods[todo.pop()]:
            for sym in alt:
                if sym in nts and sym not in reachable:
                    reachable.add(sym)
                    todo.append(sym)
    unreachable = [nt for nt in g.order if nt not in reachable]
    return undefined, unreachable, conflicts, first, follow


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("-")]
    verbose = "--verbose" in argv
    path = Path(args[0]) if args else Path(__file__).resolve().parent.parent / "docs" / "grammar.md"

    g = Grammar()
    for name, body in split_rules(extract_syntactic_ebnf(path.read_text(encoding="utf-8"))):
        g.add_rule(name, body)

    undefined, unreachable, conflicts, first, follow = analyse(g)

    if verbose:
        for nt in g.order:
            print(f"{nt:20} FIRST  = {{ {', '.join(sorted(first[nt]))} }}")
            print(f"{'':20} FOLLOW = {{ {', '.join(sorted(follow[nt]))} }}")
    for nt in unreachable:
        print(f"warning: {nt} is not reachable from {START_SYMBOL}")
    for sym in undefined:
        print(f"error: undefined non-terminal {sym}")
    for owner, where, kind, tokens in conflicts:
        print(f"CONFLICT {kind:12} in {owner} at {where}\n         lookahead: {', '.join(tokens)}")

    if undefined or conflicts:
        print(f"{path}: grammar is NOT LL(1)")
        return 1
    print(f"{path}: grammar is LL(1) ({len(g.order)} rules, {len(g.prods)} BNF non-terminals)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
