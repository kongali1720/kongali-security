"""Tests for the Kongali Security command-line interface."""

from kongali_security.cli import main


class TestCLI:
    """Test Kongali Security CLI behavior."""

    def test_version(self, monkeypatch, capsys) -> None:
        """Test --version output."""
        monkeypatch.setattr(
            "sys.argv",
            ["kongali-security", "--version"],
        )

        try:
            main()
        except SystemExit as exc:
            assert exc.code == 0

        captured = capsys.readouterr()

        assert "kongali-security 0.1.0" in captured.out

    def test_help(self, monkeypatch, capsys) -> None:
        """Test --help output."""
        monkeypatch.setattr(
            "sys.argv",
            ["kongali-security", "--help"],
        )

        try:
            main()
        except SystemExit as exc:
            assert exc.code == 0

        captured = capsys.readouterr()

        assert "Kongali Security" in captured.out
        assert "ioc" in captured.out
        assert "hash" in captured.out
        assert "dns" in captured.out

    def test_no_command(self, monkeypatch, capsys) -> None:
        """Test CLI without a command."""
        monkeypatch.setattr(
            "sys.argv",
            ["kongali-security"],
        )

        result = main()

        captured = capsys.readouterr()

        assert result == 0
        assert "Kongali Security" in captured.out

    def test_ioc_command(self, monkeypatch, capsys) -> None:
        """Test IOC analysis command."""
        monkeypatch.setattr(
            "sys.argv",
            [
                "kongali-security",
                "ioc",
                "8.8.8.8",
            ],
        )

        result = main()

        captured = capsys.readouterr()

        assert result == 0
        assert "Kongali Security IOC Analyzer" in captured.out
        assert "8.8.8.8" in captured.out
        assert "ipv4" in captured.out

    def test_ioc_json_output(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test IOC JSON output."""
        monkeypatch.setattr(
            "sys.argv",
            [
                "kongali-security",
                "ioc",
                "kongali1720.com",
                "--format",
                "json",
            ],
        )

        result = main()

        captured = capsys.readouterr()

        assert result == 0
        assert '"value": "kongali1720.com"' in captured.out
        assert '"type": "domain"' in captured.out
        assert '"valid": true' in captured.out

    def test_hash_command(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test hash analysis command."""
        monkeypatch.setattr(
            "sys.argv",
            [
                "kongali-security",
                "hash",
                "d41d8cd98f00b204e9800998ecf8427e",
            ],
        )

        result = main()

        captured = capsys.readouterr()

        assert result == 0
        assert "Kongali Security Hash Analyzer" in captured.out
        assert "md5" in captured.out
        assert "True" in captured.out

    def test_hash_json_output(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test hash JSON output."""
        monkeypatch.setattr(
            "sys.argv",
            [
                "kongali-security",
                "hash",
                "d41d8cd98f00b204e9800998ecf8427e",
                "--format",
                "json",
            ],
        )

        result = main()

        captured = capsys.readouterr()

        assert result == 0
        assert '"type": "md5"' in captured.out
        assert '"length": 32' in captured.out
        assert '"valid": true' in captured.out

    def test_dns_not_implemented(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test DNS command placeholder."""
        monkeypatch.setattr(
            "sys.argv",
            [
                "kongali-security",
                "dns",
            ],
        )

        result = main()

        captured = capsys.readouterr()

        assert result == 2
        assert "DNS analysis is not yet implemented." in captured.err
