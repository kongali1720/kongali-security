from pathlib import Path

path = Path("kongali_security/cli.py")

content = path.read_text()


# Tambah import
if "from kongali_security.network import analyze_netstat" not in content:
    marker = "from kongali_security.analysis.ip import analyze_ip"

    content = content.replace(
        marker,
        marker + "\nfrom kongali_security.network import analyze_netstat"
    )


# Tambah parser setelah ip_parser block sebelum scan_parser
if '"netstat"' not in content:

    marker = "    scan_parser = subparsers.add_parser("

    insert = '''
    netstat_parser = subparsers.add_parser(
        "netstat",
        help="Analyze local network connections.",
    )

'''

    content = content.replace(
        marker,
        insert + marker
    )


# Tambah handler sebelum scan handler
if 'args.command == "netstat"' not in content:

    marker = '    elif args.command == "scan":'

    insert = '''
    elif args.command == "netstat":

        result = analyze_netstat()

        print(
            "Kongali Security Network Intelligence"
        )

        print("=" * 40)

        data = result.to_dict()

        for conn in data["connections"]:

            print(
                f"{conn['local']} -> "
                f"{conn['remote']} "
                f"{conn['state']}"
            )

        if data["findings"]:

            print("\\nFindings:")

            for finding in data["findings"]:

                print(
                    f"[{finding['severity']}] "
                    f"{finding['title']}"
                )

'''

    content = content.replace(
        marker,
        insert + marker
    )


path.write_text(content)

print("Netstat CLI integration complete")
