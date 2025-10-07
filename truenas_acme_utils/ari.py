import json
import time
from datetime import datetime

from .exceptions import CallError


# ARI retry configuration per RFC 9773 Section 4.3.3
DEFAULT_RETRY_AFTER = 21600  # 6 hours default
MIN_RETRY_AFTER = 60  # 1 minute minimum
MAX_RETRY_AFTER = 86400  # 1 day maximum
MAX_RETRIES = 3  # Max temporary error retries


def fetch_renewal_info(acme_client, ari_endpoint: str, cert_id: str, retries: int = MAX_RETRIES) -> dict:
    """
    Fetch renewal information from ACME server per RFC 9773 Section 4

    Implements exponential backoff for temporary errors per RFC 9773 Section 4.3.3

    :param acme_client: ACME ClientV2 instance
    :param ari_endpoint: RenewalInfo endpoint URL
    :param cert_id: Unique certificate identifier from get_cert_id()
    :param retries: Number of retries remaining for temporary errors
    :return: Dict with suggestedWindow (start/end datetimes), optional explanationURL, retry_after
    """
    url = f'{ari_endpoint}/{cert_id}'
    backoff_delay = 1
    start_time = time.time()

    for attempt in range(retries + 1):
        try:
            response = acme_client.net.get(url)

            # Check for HTTP 409 alreadyReplaced error (RFC 9773 Section 7.4)
            if response.status_code == 409:
                raise CallError('Certificate has already been marked as replaced')

            # Handle 5xx server errors as temporary (RFC 9773 Section 4.3.3)
            if 500 <= response.status_code < 600:
                if attempt < retries:
                    time.sleep(backoff_delay)
                    backoff_delay *= 2
                    continue
                raise CallError(f'ARI server error after {retries + 1} attempts: HTTP {response.status_code}')

            if response.status_code not in (200, 201, 204):
                raise CallError(f'ARI request failed: HTTP {response.status_code}')

            data = json.loads(response.text)
            break
        except (ConnectionError, TimeoutError) as e:
            if attempt < retries:
                time.sleep(backoff_delay)
                backoff_delay *= 2
                continue
            raise CallError(f'ARI request failed after {retries + 1} attempts: {e}')
        except Exception as e:
            raise CallError(f'ARI request failed: {e}')

    elapsed_time = time.time() - start_time

    if 'suggestedWindow' not in data:
        raise CallError('Invalid ARI response: missing suggestedWindow')

    window = data['suggestedWindow']
    if 'start' not in window or 'end' not in window:
        raise CallError('Invalid suggestedWindow: missing start or end')

    start = datetime.fromisoformat(window['start'].replace('Z', '+00:00'))
    end = datetime.fromisoformat(window['end'].replace('Z', '+00:00'))

    result = {
        'suggestedWindow': {'start': start, 'end': end},
        'retry_after': None,
        'metrics': {
            'attempts': attempt + 1,
            'elapsed_seconds': elapsed_time,
        }
    }

    if 'explanationURL' in data:
        result['explanationURL'] = data['explanationURL']

    # Parse Retry-After header per RFC 9773 Section 4.3
    if 'Retry-After' in response.headers:
        try:
            retry_after = int(response.headers['Retry-After'])
            # Clamp to reasonable limits per RFC 9773 Section 4.3.2
            retry_after = max(MIN_RETRY_AFTER, min(retry_after, MAX_RETRY_AFTER))
            result['retry_after'] = retry_after
        except ValueError:
            result['retry_after'] = DEFAULT_RETRY_AFTER
    else:
        # Use default if not provided per RFC 9773 Section 4.3.3
        result['retry_after'] = DEFAULT_RETRY_AFTER

    return result
