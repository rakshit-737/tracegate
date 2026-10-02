from tracegate.baselines import PypiScan, Typomania, levenshtein


def test_typomania_checks():
    t = Typomania(["requests", "django-rest", "numpy"])
    assert t.flag("reqeusts")          # swapped characters
    assert t.flag("requestss")         # repeated character
    assert t.flag("rest-django")       # swapped words
    assert t.flag("reqests")           # omitted character
    assert not t.flag("requests")      # exact corpus name is not a squat
    assert not t.flag("flask")


def test_pypi_scan_min_len_and_distance():
    p = PypiScan(["requests", "six"])
    assert p.flag("requets")
    assert not p.flag("sx")            # 'six' is shorter than MIN_LEN 5
    assert not p.flag("requests")
    assert levenshtein("kitten", "sitten", 2) == 1
