def test_step1(helper):
    alert_show = helper.show_alert("db1", "sc1", "al002_al1")

    assert alert_show["warehouse"] is None
    assert alert_show["schedule"] == "1 hour"
    assert alert_show["condition"] == f"SELECT * FROM {helper.env_prefix}db1.sc1.al002_tb1"
    assert alert_show["action"] == "SELECT CURRENT_TIMESTAMP()"


def test_step2(helper):
    alert_show = helper.show_alert("db1", "sc1", "al002_al1")

    assert str(alert_show["warehouse"]).endswith("__AL002_WH1")
    assert alert_show["schedule"] == "USING CRON * * * * * UTC"

    assert alert_show["condition"] == f"SELECT 1\nFROM {helper.env_prefix}db1.sc1.al002_tb1"
    assert alert_show["action"] == "SELECT\nCURRENT_TIMESTAMP() AS abc"


def test_step3(helper):
    alert_show = helper.show_alert("db1", "sc1", "al002_al1")

    assert alert_show["warehouse"] is None
    assert alert_show["schedule"] == "USING CRON * * * * * UTC"

    assert alert_show["condition"] == f"SELECT 1\nFROM {helper.env_prefix}db1.sc1.al002_tb1"
    assert alert_show["action"] == "SELECT\nCURRENT_TIMESTAMP() AS abc"
