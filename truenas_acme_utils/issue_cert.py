import datetime
import errno
import json
import logging

import josepy as jose
from acme import errors, messages

from .client_utils import ACMEClientAndKeyData, acme_order, get_acme_client_and_key
from .event import send_event
from .exceptions import CallError


logger = logging.getLogger('acme')

# Each phase gets its own independently-computed deadline so finalize receives a fresh window
# after authorizations complete (acme.client.poll_and_finalize shares a single deadline between
# the two). ZeroSSL/Boulder validate and issue in ~2 minutes, so 5 minutes per phase is ~2.5x
# normal: fail-fast with margin. Tune here if a CA proves slower.
ACME_AUTHZ_TIMEOUT = datetime.timedelta(minutes=5)
ACME_FINALIZE_TIMEOUT = datetime.timedelta(minutes=5)


def issue_certificate(
    acme_client_key_payload: ACMEClientAndKeyData, csr: str, authenticator_mapping_copy: dict, progress_base: int = 25,
    cert_renewal_id: str | None = None,
) -> messages.OrderResource:
    # cert_id is the ID of the certificate being replaced if any
    # Authenticator mapping should be a valid mapping of domain to authenticator object
    acme_client, key = get_acme_client_and_key(acme_client_key_payload)
    try:
        # perform operations and have a cert issued
        order = acme_order(acme_client, csr.encode(), cert_renewal_id)
    except messages.Error as e:
        if messages.is_acme_error(e) and e.code == 'rateLimited':
            raise CallError(
                f'ACME server rate limited the new order request: {e}. Retrying immediately will not help; '
                'please wait for the rate limit window to reset before requesting this certificate again.'
            )
        raise CallError(f'Failed to issue a new order for Certificate : {e}')
    else:
        identifiers = [i.value for i in order.body.identifiers]
        logger.info('ACME order placed (uri=%r) for identifiers: %s', order.uri, ', '.join(identifiers))
        send_event(progress_base, 'New order for certificate issuance placed')

        authenticator_mapping = {}
        for d, v in map(lambda v: (v[0].split(':', 1)[-1], v[1]), authenticator_mapping_copy.items()):
            authenticator_mapping[d] = v
            if '*' in d:
                # Boulder returns us domain name stripped of wildcard character,
                # hence we account for that in the mapping we keep
                authenticator_mapping[d.replace('*.', '')] = v

        try:
            handle_authorizations(progress_base, order, authenticator_mapping, acme_client, key)

            # poll_and_finalize of acme lib bundles authorization polling and order finalization under a single
            # deadline and raises an indistinguishable timeout for either. We split them so each phase
            # has its own deadline and a failure names the phase that actually hung.
            logger.info('Entering authorization polling phase for order %r', order.uri)
            try:
                order = acme_client.poll_authorizations(order, datetime.datetime.now() + ACME_AUTHZ_TIMEOUT)
            except errors.TimeoutError:
                raise CallError(
                    'Certificate request timed out during the authorization phase '
                    f'(no response within {int(ACME_AUTHZ_TIMEOUT.total_seconds() // 60)} minutes)'
                )
            except errors.ValidationError as e:
                msg = ''
                for authzr in e.failed_authzrs:
                    msg += f'\nAuthorization for identifier {authzr.body.identifier} failed.'
                    msg += '\nHere are the challenges that were not fulfilled:'
                    for challenge in authzr.body.challenges:
                        msg += \
                            f'\nChallenge Type: {challenge.chall.typ}' \
                            f'\n\nError information:' \
                            f'\n- Type: {challenge.error.typ if challenge.error else "No error type found"}' \
                            '\n- Details: ' \
                            f'{challenge.error.detail if challenge.error else "No error details were found"}\n\n'
                raise CallError(f'Certificate request for final order failed: {msg}')

            logger.info('Entering finalize phase for order %r', order.uri)
            try:
                order = acme_client.finalize_order(order, datetime.datetime.now() + ACME_FINALIZE_TIMEOUT)
            except errors.TimeoutError:
                raise CallError(
                    'Certificate request timed out during the finalize phase '
                    f'(no certificate issued within {int(ACME_FINALIZE_TIMEOUT.total_seconds() // 60)} minutes)'
                )
            except errors.IssuanceError as e:
                logger.info('Finalize failed (order invalid) for order %r: %s', order.uri, e)
                raise CallError(f'Certificate request for final order failed: {e}')
            except messages.Error as e:
                if messages.is_acme_error(e) and e.code == 'rateLimited':
                    raise CallError(
                        f'ACME server rate limited the finalize request: {e}. Retrying immediately will not '
                        'help; please wait for the rate limit window to reset before requesting this '
                        'certificate again.'
                    )
                detail = getattr(e, 'detail', None) or str(e)
                logger.info('Finalize failed for order %r: %s', order.uri, detail)
                raise CallError(f'Certificate request for final order failed: {detail}')

            logger.info('Certificate issued successfully for order %r', order.uri)
            return order
        except Exception as e:
            if hasattr(e, 'extra') and e.extra is None:
                e.extra = {'order_uri': order.uri}
            raise
        finally:
            cleanup_authorizations(order, authenticator_mapping, key)


def handle_authorizations(progress, order, authenticator_mapping, acme_client, key):
    # When this is called, it should be ensured by the function calling this function that for all authorization
    # resource, a domain name dns mapping is available
    # For multiple domain providers in domain names, I think we should ask the end user to specify which domain
    # provider is used for which domain so authorizations can be handled gracefully

    max_progress = (progress * 4) - progress - (progress * 4 / 5)

    for authorization_resource in order.authorizations:
        status = False
        domain = authorization_resource.body.identifier.value
        try:
            progress += (max_progress / len(order.authorizations))
            challenge = get_challenge(authorization_resource.body.challenges)

            if not challenge:
                raise CallError(f'DNS Challenge not found for domain {domain}', errno=errno.ENOENT)

            perform_challenge(get_acme_payload(authenticator_mapping, challenge, domain, key))

            try:
                status = acme_client.answer_challenge(challenge, challenge.response(key))
            except errors.UnexpectedUpdate as e:
                raise CallError(f'Error answering challenge for {domain} : {e}')
        finally:
            send_event(progress, f'DNS challenge {"completed" if status else "failed"} for {domain}')


def get_challenge(challenges):
    challenge = None
    for chg in challenges:
        if chg.typ == 'dns-01':
            challenge = chg
    return challenge


def get_acme_payload(authenticator_mapping: dict, challenge, domain, key) -> dict:
    return {
        'authenticator': authenticator_mapping[domain],
        'challenge': challenge.json_dumps(),
        'domain': domain,
        'key': key.json_dumps()
    }


def perform_challenge(data: dict):
    authenticator = data['authenticator']
    authenticator.perform(*get_validation_parameters(data['challenge'], data['domain'], data['key']))


def get_validation_parameters(challenge, domain, key):
    challenge = messages.ChallengeBody.from_json(json.loads(challenge))
    return (
        domain,
        challenge.validation_domain_name(domain),
        challenge.validation(jose.JWKRSA.fields_from_json(json.loads(key))),
    )


def cleanup_authorizations(order, authenticator_mapping, key):
    for authorization_resource in order.authorizations:
        domain = authorization_resource.body.identifier.value
        challenge = get_challenge(authorization_resource.body.challenges)
        if not challenge:
            continue
        try:
            cleanup_challenge(get_acme_payload(authenticator_mapping, challenge, domain, key))
        except Exception:
            logger.error('Failed to cleanup challenge for %r domain', domain, exc_info=True)


def cleanup_challenge(data: dict):
    authenticator = data['authenticator']
    authenticator.cleanup(*get_validation_parameters(data['challenge'], data['domain'], data['key']))
