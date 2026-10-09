
# NOTES, TODOs, etc...

## dependencies
I moved around some dependencies in `pyproject.yaml` so `cryptography` &
`curl-cffi` are outright dependencies, but then I noticed they are defensively
imported in the code only when about to be used -- are there use-cases for
alternet w/out those packages?

Since making those changes, the install method may have changed slightly

To install in "dev mode":
```
kenneth@fado ~/git/alternet-poc (kld) $ python3.12 -m venv ./venv3.12
kenneth@fado ~/git/alternet-poc (kld) $ . ./venv3.12/bin/activate
((venv3.12) ) kenneth@fado ~/git/alternet-poc (kld) $ pip install -U pip .[test]
((venv3.12) ) kenneth@fado ~/git/alternet-poc (kld) $ pip install -e .
```

I've been working primarily with `3.12` but find so far that `3.11` works as
well.  There was an issue with `3.14` around tightening of cert validation
practices which may have happened in `3.13`

## pytest-related
A default set of pytest arguments have been added to `pyproject.yaml`

To run:
```sh
kenneth@fado ~/git/alternet-poc (kld) $ . ./venv3.11/bin/activate
(venv3.11) kenneth@fado ~/git/alternet-poc (kld) $ pytest
```

You can still pass preferred args to `pytest` to override defaults & specify tests to run
```sh
(venv3.12) kenneth@fado ~/git/alternet-poc (kld) $ pytest -q --no-cov tests/test_routing.py
==================================================================== test session starts ====================================================================
platform linux -- Python 3.12.15, pytest-9.1.1, pluggy-1.6.0
rootdir: /home/kenneth/git/alternet-poc
configfile: pyproject.toml
plugins: cov-7.1.0
collected 1 item

tests/test_routing.py .                                                                                                                               [100%]

===================================================================== 1 passed in 0.03s =====================================================================
```

### TODO: investigate 13 Warnings
```
tests/test_entry_resilience.py: 1 warning
tests/test_http_carrier.py: 11 warnings
tests/test_recovery_race.py: 1 warning
  /home/kenneth/git/alternet-poc/venv3.11/lib/python3.11/site-packages/curl_cffi/curl.py:588:
  CurlCffiWarning: Wrote bytes != received bytes.
      ret = lib.curl_easy_perform(self._curl)

      -- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
```


## alternet.cli
Starting @ UI

I moved the `argparse.ArgumentParser` def out of `main()` & created it as a
top-level object, able to be tested independently & simplifying `main()`

I see there are some basic tests that particular arguments result in
particular calls to the nested imports.

I didn't want to mess with this straight out of the gate, nested imports are a
red flag for problem code to me, and I think related to my initial problems with
`coverage`.  There are a lot of nested imports elsewhere too, I think this can
be cleaned up to not test for side-effects, and instead test results of
`parser.parse_args()`


## alternet.config
I chose a simple class to refactor & test to provide an example for discussion

### Address.parse
I separated `Address.parse` into two functions, delegating the address validation
to a helper class function, `Address.valid_address`, which returns the same
struct from `urllib.parse.urlsplit` on success, or raises a new error, `InvalidAddressError`,
a subclass of `ValueError` which is what `parse()` had raised previously.

There's more that could be done to flesh out `valid_address`, it wasn't my
intention to complete it, I documented links to the relevant specs in docstring

### tests/test_config.py
The `test_address` assertions just begin with me verifying that I am calling
it correctly, and just run through a few obvious expected errors


## alternet.peer_discovery

### PeerBook
Here, I just couldn't resist immediately separating creation of sqlite db into
separate `create_peerdb` function.

I'm not sure I understand why `PeerBook` accepts `None` as `Path` arg, I
imagine it will become clear as I learn more about various use cases

Also, one thing I noticed (maybe not here), there is a tendency in the code to
include a catchall `*` in method parameter lists.  This seems like a dangerous
error-swallowing practice.

In beginning to try to understand `PeerBook.hint()` I found myself moving on
to the `alternet.routing` module.


## alternet.routing


### RouteError subclass of OSError?
At a superficial glance, it looks like `RouteError` is raised by `connect_tcp`
when a connection cannot be made, perhaps due to a DNS lookup or network
issues (or route going down, being blocked), and in several other parts of the
codebase for a number of reasons, none of which look like an `OSError`

Perhaps it was declared an `OSError` because it is raised in the same function
`connect_tcp` whose primary job is to create a socket?

I tried changing the parent to `RuntimeError` and 10 tests failed, 11 more
threw errors.


### Blocking FIFO maxsize=1
Possibly this is a common pattern, I'm not sure I get it

`queue.Queue(maxsize=1)` is blocking FIFO for single thread

being used here as basically a kind of lock?


### NOTE: Daemonic Threads introduced in 3.3
Something to be aware of

https://docs.python.org/3/library/threading.html#module-threading

    A thread can be flagged as a “daemon thread”. The significance of this flag is
    that the entire Python program exits when only daemon threads are left. The
    initial value is inherited from the creating thread. The flag can be set
    through the daemon property or the daemon constructor argument.

    Note Daemon threads are abruptly stopped at shutdown. Their resources (such as
    open files, database transactions, etc.) may not be released properly. If you
    want your threads to stop gracefully, make them non-daemonic and use a
    suitable signalling mechanism such as an Event.

    There is a “main thread” object; this corresponds to the initial thread of
    control in the Python program. It is not a daemon thread.


