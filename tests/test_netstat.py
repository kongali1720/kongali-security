from kongali_security.network import analyze_netstat


def test_netstat_engine():

    result = analyze_netstat()

    assert result is not None
    assert hasattr(
        result,
        "to_dict"
    )
