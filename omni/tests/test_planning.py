import pytest

from omnishield.planning import PlanningError, coordinate, decompose, plan, schedule

ACTIONS = [
    {"name": "go_shop", "pre": ["home"], "add": ["shop"], "del": ["home"]},
    {"name": "buy_milk", "pre": ["shop"], "add": ["milk"]},
    {"name": "go_home", "pre": ["shop"], "add": ["home"], "del": ["shop"]},
]


def test_strips_planner_finds_a_short_plan():
    result = plan(["home"], ACTIONS, ["milk", "home"])
    assert result["plan"] == ["go_shop", "buy_milk", "go_home"]
    assert result["cost"] == 3
    assert plan(["home"], ACTIONS, ["home"])["plan"] == []


def test_strips_planner_reports_an_unsolvable_goal():
    result = plan(["home"], ACTIONS, ["gold"])
    assert result["plan"] is None
    assert "limit" in result["reason"]


def test_hierarchical_decomposition_expands_to_primitives():
    methods = {"build_house": ["foundation", "walls"], "walls": ["bricks", "mortar"]}
    result = decompose("build_house", methods)
    assert result["primitives"] == ["foundation", "bricks", "mortar"]
    assert result["depth"] == 2
    with pytest.raises(PlanningError, match="cycle"):
        decompose("a", {"a": ["b"], "b": ["a"]})


def test_temporal_schedule_respects_precedence_and_workers():
    tasks = {
        "design": {"duration": 2},
        "build": {"duration": 3, "after": ["design"]},
        "test": {"duration": 1, "after": ["build"]},
    }
    result = schedule(tasks, workers=2)
    assert result["order"] == ["design", "build", "test"]
    assert result["start"]["build"] == 2.0
    assert result["makespan"] == 6.0
    with pytest.raises(PlanningError, match="cycle"):
        schedule({"a": {"after": ["b"]}, "b": {"after": ["a"]}})


def test_multi_agent_coordination_assigns_by_skill():
    agents = {"amina": {"python", "wifi"}, "juma": {"python"}}
    tasks = {
        "audit_wifi": {"needed": 1, "skill": "wifi"},
        "write_code": {"needed": 2, "skill": "python"},
        "paint": {"needed": 1, "skill": "painting"},
    }
    result = coordinate(agents, tasks)
    assert result["assignment"]["audit_wifi"] == ["amina"]
    assert result["assignment"]["write_code"] == ["amina", "juma"]
    assert result["unassigned"] == ["paint"]
    assert result["load"] == {"amina": 2, "juma": 1}
