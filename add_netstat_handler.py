from pathlib import Path

path = Path("kongali_security/cli.py")

content = path.read_text()

if 'if args.command == "netstat":' in content:
    print("Netstat handler already exists")
    exit()


marker = '    if args.command == "scan":'

handler = '''
    if args.command == "netstat":

        result = analyze_netstat()

        print(
            "Kongali Security Network Intelligence"
        )

        print("=" * 40)

        data = result.to_dict()

        print(
            f"Active Connections: {len(data['connections'])}"
        )

        print()

        for conn in data["connections"]:

            print(
                f"{conn['local']} -> "
                f"{conn['remote']} "
                f"{conn['state']}"
            )


        if data["findings"]:

            print()
            print("Findings")
            print("--------")

            for finding in data["findings"]:

                print(
                    f"[{finding['severity']}] "
                    f"{finding['title']}"
                )

        return


'''

content = content.replace(
    marker,
    handler + marker
)

path.write_text(content)

print("Netstat handler added")
