def register(sub):
    p = sub.add_parser("doctor", help="Check credentials and permissions")
    p.set_defaults(func=run)

def run(args) -> int:
    from dva.errors import DvaError
    raise DvaError("doctor not implemented yet")
