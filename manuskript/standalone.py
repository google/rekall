import argparse

from manuskript import server


PARSER = argparse.ArgumentParser()
PARSER.add_argument("--host", type=str,
                    help="Web server host address.")
PARSER.add_argument("--port", type=int,
                    help="Web server port.")
PARSER.add_argument("--debug", type=bool,
                    help="If true, reload files on change.")


def main():
    args = PARSER.parse_args()
    server.RunServer(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()
