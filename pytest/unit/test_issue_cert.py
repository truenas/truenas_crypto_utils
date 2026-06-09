import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from acme import errors, messages

import truenas_acme_utils.issue_cert as ic
from truenas_acme_utils.exceptions import CallError


def make_order(uri='https://acme.test/order/1', identifiers=('example.com',)):
    body = SimpleNamespace(identifiers=[SimpleNamespace(value=v) for v in identifiers])
    return SimpleNamespace(uri=uri, body=body)


def make_failed_authzr(identifier='example.com'):
    challenge = SimpleNamespace(
        chall=SimpleNamespace(typ='dns-01'),
        error=SimpleNamespace(typ='urn:ietf:params:acme:error:dns', detail='no TXT record found'),
    )
    return SimpleNamespace(body=SimpleNamespace(identifier=identifier, challenges=[challenge]))


@pytest.fixture
def env(monkeypatch):
    """Patch issue_cert module globals so issue_certificate runs against a fake ACME client."""
    order = make_order()
    client = MagicMock()
    client.poll_authorizations.return_value = order
    client.finalize_order.return_value = order
    cleanup = MagicMock()

    monkeypatch.setattr(ic, 'get_acme_client_and_key', lambda payload: (client, object()))
    monkeypatch.setattr(ic, 'acme_order', lambda *a, **k: order)
    monkeypatch.setattr(ic, 'handle_authorizations', lambda *a, **k: None)
    monkeypatch.setattr(ic, 'cleanup_authorizations', cleanup)
    monkeypatch.setattr(ic, 'send_event', lambda *a, **k: None)

    return SimpleNamespace(order=order, client=client, cleanup=cleanup)


def call():
    return ic.issue_certificate({}, 'csr-pem', {'DNS:example.com': object()})


def test_happy_path(env):
    assert call() is env.order
    env.client.poll_authorizations.assert_called_once()
    env.client.finalize_order.assert_called_once()
    env.cleanup.assert_called_once()


def test_authz_timeout(env):
    env.client.poll_authorizations.side_effect = errors.TimeoutError()
    with pytest.raises(CallError) as exc:
        call()
    assert 'authorization phase' in exc.value.errmsg
    env.client.finalize_order.assert_not_called()
    env.cleanup.assert_called_once()
    assert exc.value.extra == {'order_uri': env.order.uri}


def test_finalize_timeout(env):
    env.client.finalize_order.side_effect = errors.TimeoutError()
    with pytest.raises(CallError) as exc:
        call()
    assert 'finalize phase' in exc.value.errmsg
    env.cleanup.assert_called_once()
    assert exc.value.extra == {'order_uri': env.order.uri}


def test_validation_error(env):
    env.client.poll_authorizations.side_effect = errors.ValidationError([make_failed_authzr()])
    with pytest.raises(CallError) as exc:
        call()
    assert 'final order failed' in exc.value.errmsg
    assert 'example.com' in exc.value.errmsg
    assert 'no TXT record found' in exc.value.errmsg
    env.cleanup.assert_called_once()


def test_finalize_invalid(env):
    env.client.finalize_order.side_effect = errors.IssuanceError(messages.Error.with_code('serverInternal'))
    with pytest.raises(CallError) as exc:
        call()
    assert 'final order failed' in exc.value.errmsg
    env.cleanup.assert_called_once()


def test_finalize_rate_limited(env):
    env.client.finalize_order.side_effect = messages.Error.with_code('rateLimited', detail='slow down')
    with pytest.raises(CallError) as exc:
        call()
    assert 'rate limited' in exc.value.errmsg
    assert 'will not help' in exc.value.errmsg
    env.cleanup.assert_called_once()


def test_order_placement_error(env, monkeypatch):
    def boom(*a, **k):
        raise messages.Error(detail='nope')

    monkeypatch.setattr(ic, 'acme_order', boom)
    with pytest.raises(CallError) as exc:
        call()
    assert 'Failed to issue a new order' in exc.value.errmsg
    env.cleanup.assert_not_called()


def test_order_placement_rate_limited(env, monkeypatch):
    def boom(*a, **k):
        raise messages.Error.with_code('rateLimited', detail='slow down')

    monkeypatch.setattr(ic, 'acme_order', boom)
    with pytest.raises(CallError) as exc:
        call()
    assert 'rate limited' in exc.value.errmsg
    env.cleanup.assert_not_called()


def test_deadlines_independent(env):
    before = datetime.datetime.now()
    call()
    after = datetime.datetime.now()

    authz_deadline = env.client.poll_authorizations.call_args.args[1]
    finalize_deadline = env.client.finalize_order.call_args.args[1]

    # Each phase gets its own ~5 minute window computed at call time.
    assert before + ic.ACME_AUTHZ_TIMEOUT <= authz_deadline <= after + ic.ACME_AUTHZ_TIMEOUT
    assert before + ic.ACME_FINALIZE_TIMEOUT <= finalize_deadline <= after + ic.ACME_FINALIZE_TIMEOUT
    # finalize deadline is computed after authorizations finish, so it is a fresh, later window.
    assert finalize_deadline > authz_deadline
