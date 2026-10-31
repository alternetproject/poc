
import argparse
import contextlib
import datetime

from .config import Address, Config


class AlternetResolver():

    def __init__(self, config):
        self.config = config


    def serve():


def start(config):
    server = AlternetResolver(config)
    server.serve()


def demo_config(name:str, port:int, known_peers:dict):


@contextlib.contextmanager
def launch_demo_network():
    """spawns a number of alternet resolver servers

    network peer topology looks like:

    +--------------+    +--------------+                        +--------------+
    | A            |    | B            |                        | F            |
    +--------------+    +--------------+                        +--------------+
    | peers: {B,}  |----| peers: {A,C} |                        | peers: {E,}  |
    +--------------+    +--------------+                        +--------------+
                               |                                        |
                        +--------------+    +--------------+    +--------------+
                        | C            |    | D            |    | E            |
                        +--------------+    +--------------+    +--------------+
                        | peers: {B,D} |----| peers: {C,E} |----| peers: {D,F} |
                        +--------------+    +--------------+    +--------------+

    By default binds to localhost:1024 thru :1029, export ALTERNET_DEMO_PORT_A thru _F to change
    """
    port_a = os.environ.get('ALTERNET_DEMO_PORT_A', 1024)
    port_b = os.environ.get('ALTERNET_DEMO_PORT_B', 1025)
    port_c = os.environ.get('ALTERNET_DEMO_PORT_C', 1026)
    port_d = os.environ.get('ALTERNET_DEMO_PORT_D', 1027)
    port_e = os.environ.get('ALTERNET_DEMO_PORT_E', 1028)
    port_f = os.environ.get('ALTERNET_DEMO_PORT_F', 1029)

    a = AlternetResolver(demo_config('A', port_a, {'B': f'localhost:{port_b}'}))
    b = AlternetResolver(demo_config('B', port_b, {'A': f'localhost:{port_a}', 'C': f'localhost:{port_c}'}))
    c = AlternetResolver(demo_config('C', port_c, {'B': f'localhost:{port_b}', 'D': f'localhost:{port_d}'}))
    d = AlternetResolver(demo_config('D', port_d, {'C': f'localhost:{port_c}', 'E': f'localhost:{port_e}'}))
    e = AlternetResolver(demo_config('E', port_e, {'D': f'localhost:{port_d}', 'F': f'localhost:{port_f}'}))
    f = AlternetResolver(demo_config('F', port_f, {'E': f'localhost:{port_e}'}))

    try:
        for server in a, b, c, d, e, f:
            server.serve()
            yield
    finally:
        for server in a, b, c, d, e, f:
            server.stop()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args()


def demo():
    args = parse_args()
    print(f'\ndemo Alternet Server and Discovery\n')
    with launch_demo_network():
        start = time.time()
        # create a new instance with peer A, request F
        end = time.time()
        elapsed = datetime.timedelta(end - start)
    print(f'elapsed time: {elapsed}\n')
    # return success
    return(0)

