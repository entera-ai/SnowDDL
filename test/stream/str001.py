def test_step1(helper):
    stream_show = helper.show_stream("db1", "sc1", "str001_str1")

    assert stream_show["source_type"] == "Table"
    assert stream_show["table_name"].endswith(".STR001_TB1")
    assert stream_show["mode"] == "DEFAULT"
    assert stream_show["comment"] == "abc"


def test_step2(helper):
    stream_show = helper.show_stream("db1", "sc1", "str001_str1")

    assert stream_show["source_type"] == "Table"
    assert stream_show["table_name"].endswith(".STR001_TB1")
    assert stream_show["mode"] == "APPEND_ONLY"
    assert stream_show["comment"] == "abc"


def test_step3(helper):
    stream_show = helper.show_stream("db1", "sc1", "str001_str1")

    assert stream_show["source_type"] == "Table"
    assert stream_show["table_name"].endswith(".STR001_TB1")
    assert stream_show["mode"] == "APPEND_ONLY"
    assert stream_show["comment"] == "cde"
