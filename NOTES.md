# NOTES, TODOs, etc...
Welcome to Alternet!

## Getting Started
### minimum Python
Python `3.11` & `3.12` seemed to work, but tests threw a lot of warnings 
around TLS certs.  I think tightening of cert validation happened in `3.13`,
this project is developed so far with `3.14`

### install method
To install in "dev mode":
```sh
kenneth@fado ~/git/alternet-poc (kld) $ python3.14 -m venv ./venv3.14
kenneth@fado ~/git/alternet-poc (kld) $ . ./venv3.14/bin/activate
(venv3.14) kenneth@fado ~/git/alternet-poc (kld) $ pip install -U pip .[test]
(venv3.14) kenneth@fado ~/git/alternet-poc (kld) $ pip install -e .
```

### pytest-related
A default set of pytest arguments have been added to `pyproject.yaml`

To run:
```sh
kenneth@fado ~/git/alternet-poc (kld) $ . ./venv3.14/bin/activate
(venv3.14) kenneth@fado ~/git/alternet-poc (kld) $ pytest
```
You can still pass preferred args to `pytest` to override defaults & specify tests to run
```sh
(venv3.14) kenneth@fado ~/git/alternet-poc (kld) $ pytest -q --no-cov tests/test_routing.py
==================================================================== test session starts ====================================================================
platform linux -- Python 3.14.8, pytest-9.1.1, pluggy-1.6.0
rootdir: /home/kenneth/git/alternet-poc
configfile: pyproject.toml
plugins: cov-7.1.0
collected 1 item

tests/test_routing.py .                                                                                                                               [100%]

===================================================================== 1 passed in 0.03s =====================================================================
```

## process
 * Weeklyish conversations about direction
 * May include code review when appropriate, feasible
 * Communication via Vulture, email
 * Continued presence @ discord?

## Codebase Intro
### alternet.config
I chose a simple class to refactor & test to provide an example for discussion
about code layout & style, testing organization, etc
#### tests/test_config.py
Initial `test_address` assertions just begin with me verifying that I am calling
it correctly, and just run through a few obvious expected errors

### alternet.peer_discovery
I'm not sure I understand why `PeerBook` accepts `None` as `Path` arg, I
imagine it will become clear as I learn more about various use cases

Also, one thing I noticed (maybe not here), there is a tendency in the code to
include a catchall `*` in method parameter lists.  This seems like a dangerous
error-swallowing practice.

In beginning to try to understand `PeerBook.hint()` I found myself moving on
to the `alternet.routing` module.

### alternet.routing

### Proof of Work
Thinking of Alternet PoC as one project separate from its eventual deployment
style is a little tenuous for me.

There are several processes that will rely heavily on threading, but there are
also processes that should be separate processes, will deployment eventually
be as a Docker swarm?

I am beginning to think of this already because I believe PoW stuff should be
implemented, in terms of SOA, as a proxy, inserting itself into the routing of
particular requests -- though I'm unclear how to do this in a way that
supports Tor-style prioritization of requests based on the amount of work (if
we are intending to do that)


## NOTES
Aspects of alternet-poc design & implementation worth taking a moment to review,
including comments, clarifications, current thinking

### Proof of Work

#### Non Application-Specific IC friendly
What exactly does [this](https://onionservices.torproject.org/technology/security/pow/#how-is-this-different-or-the-same-from-pow-in-the-cryptocurrency-space) mean for us?

    While PoW algorithms for cryptocurrencies are optimizable for special-purpose
    hardware such as ASICs, PoW for Onion Services was designed to not be
    optimizable that way, in order to disincentive attackers to build special
    hardware in order to attack Onion Services.

Also, in terms of understanding our goals with PoW vis-a-vis Tor, I find their analagy of a 
[sold-out concert](https://onionservices.torproject.org/technology/security/pow/#could-you-explain-a-bit-more-how-pow-for-onion-services-works)
to be more confusing than helpful (partly because, after spending years
implementing SOA systems in the hospitality industry, I find it difficult to
believe that is how StubHub works & the abstraction gets in the way for me)

I think notes about understanding linked-to docs are important to create discussion about too


### Daemonic Threads introduced in 3.3
Just something to be aware of

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


### Blocking FIFO maxsize=1
Possibly this is a common pattern, I'm not sure I get it

`queue.Queue(maxsize=1)` is blocking FIFO for single thread

being used here as basically a kind of lock?

This is something worth returning to when code refactoring circles back this way


## TODOs
Mostly unprioritized

### Tests for alternet.cli rely on side-effects
I moved the `argparse.ArgumentParser` def out of `main()` & created it as a
top-level object, able to be tested independently & simplifying `main()`

I see there are some basic tests that particular arguments result in
particular calls to the nested imports.

I didn't want to mess with this straight out of the gate, nested imports are a
red flag for problem code to me, and I think related to my initial problems with
`coverage`.  There are a lot of nested imports elsewhere too, I think this can
be cleaned up to not test for side-effects, and instead test results of
`parser.parse_args()`

### expand on Address.parse validations
I separated `Address.parse` into two functions, delegating the address validation
to a helper class function, `Address.valid_address`, which returns the same
struct from `urllib.parse.urlsplit` on success, or raises a new error, `InvalidAddressError`,
a subclass of `ValueError` which is what `parse()` had raised previously.

There's more that could be done to flesh out `valid_address`, it wasn't my
intention to complete it, I documented links to the relevant specs in docstring

### Fix TLS-Related warnings in 3.12
```
tests/test_entry_resilience.py: 1 warning
tests/test_http_carrier.py: 11 warnings
tests/test_recovery_race.py: 1 warning
  /home/kenneth/git/alternet-poc/venv3.12/lib/python3.12/site-packages/curl_cffi/curl.py:588:
  CurlCffiWarning: Wrote bytes != received bytes.
      ret = lib.curl_easy_perform(self._curl)

      -- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
```
#### RouteError subclass of OSError?
At a superficial glance, it looks like `RouteError` is raised by `connect_tcp`
when a connection cannot be made, perhaps due to a DNS lookup or network
issues (or route going down, being blocked), and in several other parts of the
codebase for a number of reasons, none of which look like an `OSError`

Perhaps it was declared an `OSError` because it is raised in the same function
`connect_tcp` whose primary job is to create a socket?

I tried changing the parent to `RuntimeError` and 10 tests failed, 11 more
threw errors.


## References

  * https://onionservices.torproject.org/technology/security/pow/
