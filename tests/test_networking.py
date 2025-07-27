from pathlib import Path
import sys
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import networking  # noqa: E402


def test_send_email_no_send(monkeypatch):
    mock_smtp = MagicMock()
    monkeypatch.setattr(networking, "smtplib", MagicMock(SMTP=mock_smtp))
    networking.send_email("sub", "body", {"send_email": False})
    assert not mock_smtp.called


def test_send_email_via_smtp(monkeypatch):
    mock_server = MagicMock()
    smtp_instance = MagicMock(
        __enter__=MagicMock(return_value=mock_server),
        __exit__=MagicMock(return_value=None),
    )
    smtp_cls = MagicMock(return_value=smtp_instance)
    monkeypatch.setattr(networking, "smtplib", MagicMock(SMTP=smtp_cls))
    config = {
        "send_email": True,
        "use_smtp": True,
        "email_sender": "a@b.com",
        "email_recipient": "c@d.com",
        "smtp_server": "srv",
        "smtp_port": 25,
        "smtp_user": "u",
        "smtp_password": "p",
    }
    networking.send_email("sub", "body", config)
    smtp_cls.assert_called_with("srv", 25)
    mock_server.starttls.assert_called()
    mock_server.login.assert_called_with("u", "p")
    mock_server.send_message.assert_called()
