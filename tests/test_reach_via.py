"""pip-compile `# via` annotations in both layouts feed the transitive reachability tier."""
from pathlib import Path

from tracegate.reach import static_reachability, via_graph

OLD = """pymlconf==0.3.17          # via tzf.pyramid-yml
pyyaml==3.11              # via pymlconf
six==1.9.0                # via bcrypt, cffi
tzf.pyramid-yml==1.0.1
"""
NEW = """pyyaml==6.0.1
    # via
    #   pymlconf
    #   -r requirements.in
"""


def test_inline_and_multiline_via():
    assert via_graph(OLD) == {"pymlconf": {"tzf-pyramid-yml"}, "pyyaml": {"pymlconf"}, "six": {"bcrypt", "cffi"},
                              "tzf-pyramid-yml": set()}
    assert via_graph(NEW) == {"pyyaml": {"pymlconf"}}


def test_inline_via_makes_dependencies_transitive(tmp_path: Path):
    src = tmp_path / "app"
    src.mkdir()
    (src / "config.py").write_text("from tzf.pyramid_yml import config_defaults\n")
    pins = {"tzf-pyramid-yml": "1.0.1", "pymlconf": "0.3.17", "pyyaml": "3.11"}
    rep = static_reachability(pins, [src], tmp_path, OLD)
    assert rep.status["tzf-pyramid-yml"] == "imported"
    assert rep.status["pymlconf"] == rep.status["pyyaml"] == "transitive"
