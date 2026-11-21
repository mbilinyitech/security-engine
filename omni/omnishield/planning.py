"""Planning that returns a plan, not a promise.

Forward search over STRIPS actions, hierarchical task decomposition, temporal
list scheduling with precedence and workers, and multi-agent task assignment.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from typing import Any


class PlanningError(Exception):
    pass


def plan(
    initial: Iterable[str],
    actions: Sequence[Mapping[str, Any]],
    goal: Iterable[str],
    *,
    limit: int = 20_000,
) -> dict[str, Any]:
    """Breadth-first STRIPS search. Each action needs name, pre, add and del."""
    start = frozenset(initial)
    target = frozenset(goal)
    if target <= start:
        return {"plan": [], "cost": 0, "explored": 0}
    queue = deque([(start, [])])
    seen = {start}
    explored = 0
    while queue and explored < limit:
        state, path = queue.popleft()
        explored += 1
        for action in actions:
            preconditions = set(action.get("pre", ()))
            if not preconditions <= state:
                continue
            following = frozenset(
                (set(state) | set(action.get("add", ()))) - set(action.get("del", ()))
            )
            if following in seen:
                continue
            extended = [*path, action["name"]]
            if target <= following:
                return {"plan": extended, "cost": len(extended), "explored": explored}
            seen.add(following)
            queue.append((following, extended))
    return {"plan": None, "reason": "no plan within the limit", "explored": explored}


def decompose(goal: str, methods: Mapping[str, Sequence[str]]) -> dict[str, Any]:
    """Expand a compound task into primitives; refuse cycles."""
    primitives: list[str] = []
    deepest = 0
    active: set[str] = set()

    def expand(task: str, depth: int) -> None:
        nonlocal deepest
        deepest = max(deepest, depth)
        if task not in methods:
            primitives.append(task)
            return
        if task in active:
            raise PlanningError(f"decomposition cycle at {task!r}")
        active.add(task)
        for sub in methods[task]:
            expand(sub, depth + 1)
        active.discard(task)

    expand(goal, 0)
    return {"primitives": primitives, "steps": len(primitives), "depth": deepest}


def schedule(
    tasks: Mapping[str, Mapping[str, Any]], *, workers: int = 1
) -> dict[str, Any]:
    """List scheduling with precedence, earliest start and a worker pool."""
    if workers < 1:
        raise PlanningError("at least one worker is needed")
    durations = {name: float(config.get("duration", 1.0)) for name, config in tasks.items()}
    precedence = {name: list(config.get("after", ())) for name, config in tasks.items()}
    for name, dependencies in precedence.items():
        for dependency in dependencies:
            if dependency not in tasks:
                raise PlanningError(f"{name!r} waits for unknown task {dependency!r}")

    order: list[str] = []
    remaining = {name: list(deps) for name, deps in precedence.items()}
    while remaining:
        ready = sorted(name for name, deps in remaining.items() if not deps)
        if not ready:
            raise PlanningError("the precedence graph has a cycle")
        for name in ready:
            order.append(name)
            del remaining[name]
        for deps in remaining.values():
            deps[:] = [dep for dep in deps if dep not in ready]

    free_at = [0.0] * workers
    starts: dict[str, float] = {}
    ends: dict[str, float] = {}
    for name in order:
        earliest = max((ends[dep] for dep in precedence[name]), default=0.0)
        worker = min(range(workers), key=lambda index: free_at[index])
        begin = max(earliest, free_at[worker])
        starts[name] = round(begin, 3)
        ends[name] = round(begin + durations[name], 3)
        free_at[worker] = ends[name]
    return {
        "order": order,
        "start": starts,
        "end": ends,
        "makespan": round(max(ends.values()), 3) if ends else 0.0,
        "workers": workers,
    }


def coordinate(
    agents: Mapping[str, Iterable[str]],
    tasks: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Assign tasks to agents by skill, balancing load, reporting what is left."""
    skills = {agent: set(abilities) for agent, abilities in agents.items()}
    load = {agent: 0 for agent in skills}
    assignment: dict[str, list[str]] = {}
    unassigned: list[str] = []
    for task in sorted(tasks, key=lambda name: (-int(tasks[name].get("needed", 1)), name)):
        config = tasks[task]
        needed = int(config.get("needed", 1))
        skill = config.get("skill")
        eligible = [
            agent
            for agent, abilities in skills.items()
            if skill is None or skill in abilities
        ]
        if len(eligible) < needed:
            unassigned.append(task)
            continue
        chosen = sorted(eligible, key=lambda agent: (load[agent], agent))[:needed]
        assignment[task] = chosen
        for agent in chosen:
            load[agent] += 1
    return {"assignment": assignment, "unassigned": unassigned, "load": load}
