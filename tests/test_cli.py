from __future__ import annotations

import json
import sys

from kongali_security.cli import main


class TestCLI:
    """Test Kongali Security command-line interface."""

    def test_help_without_command(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test CLI help output when no command is provided."""
        monkeypatch.setattr(
            sys,
            "argv",
            ["kongali-security"],
        )

        result = main()

        captured = capsys.readouterr()

        assert result == 0
        assert "Kongali Security" in captured.out
        assert "ioc" in captured.out
        assert "hash" in captured.out
        assert "dns" in captured.out

    def test_version(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test CLI version output."""
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "kongali-security",
                "--version",
            ],
        )

        try:
            main()
        except SystemExit as exc:
            assert exc.code == 0

        captured = capsys.readouterr()

        assert "kongali-security 0.1.0" in captured.out

    def test_ioc_domain(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test IOC domain analysis."""
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "kongali-security",
                "ioc",
                "example.com",
            ],
        )

        result = main()

        captured = capsys.readouterr()

        assert result == 0
        assert "Kongali Security IOC Analyzer" in captured.out
        assert "example.com" in captured.out
        assert "domain" in captured.out
        assert "True" in captured.out

    def test_ioc_json(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test IOC JSON output."""
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "kongali-security",
                "ioc",
                "8.8.8.8",
                "--format",
                "json",
            ],
        )

        result = main()

        captured = capsys.readouterr()

        data = json.loads(captured.out)

        assert result == 0
        assert data["value"] == "8.8.8.8"
        assert data["type"] == "ipv4"
        assert data["valid"] is True

    def test_hash_md5(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test MD5 hash analysis."""
        monkeypatch.setattr(
            sys,
            "argv",
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
        assert "d41d8cd98f00b204e9800998ecf8427e" in captured.out
        assert "md5" in captured.out
        assert "True" in captured.out

    def test_hash_json(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test hash JSON output."""
        monkeypatch.setattr(
            sys,
            "argv",
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

        data = json.loads(captured.out)

        assert result == 0
        assert data["value"] == (
            "d41d8cd98f00b204e9800998ecf8427e"
        )
        assert data["type"] == "md5"
        assert data["length"] == 32
        assert data["valid"] is True
        assert data["algorithm"] == "md5"

    def test_dns_domain(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test DNS domain analysis."""
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "kongali-security",
                "dns",
                "example.com",
            ],
        )

        result = main()

        captured = capsys.readouterr()

        assert result == 0
        assert "DNS" in captured.out
        assert "example.com" in captured.out

    def test_dns_json(
        self,
        monkeypatch,
        capsys,
    ) -> None:
        """Test DNS JSON output."""
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "kongali-security",
                "dns",
                "example.com",
                "--format",
                "json",
            ],
        )

        result = main()

        captured = capsys.readouterr()

        data = json.loads(captured.out)

        assert result == 0
        assert isinstance(data, dict)
        assert data["domain"] == "example.com"

    def test_invalid_command(
        self,
        monkeypatch,
    ) -> None:
        """Test invalid command handling."""
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "kongali-security",
                "invalid-command",
            ],
        )

        try:
            main()
        except SystemExit as exc:
            assert exc.code == 2
