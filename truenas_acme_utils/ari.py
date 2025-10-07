import json
import time
from datetime import datetime

import requests


# ARI retry configuration per RFC 9773 Section 4.3.3
DEFAULT_RETRY_AFTER = 21600  # 6 hours default
MIN_RETRY_AFTER = 60  # 1 minute minimum
MAX_RETRY_AFTER = 86400  # 1 day maximum
MAX_RETRIES = 3  # Max temporary error retries


def fetch_renewal_info(ari_endpoint: str, cert_id: str, retries: int = MAX_RETRIES, timeout: int = 30) -> dict:
    """
    Fetch renewal information from ACME server per RFC 9773 Section 4

    Implements exponential backoff for temporary errors per RFC 9773 Section 4.3.3

    :param ari_endpoint: RenewalInfo endpoint URL
    :param cert_id: Unique certificate identifier from get_cert_id()
    :param retries: Number of retries remaining for temporary errors
    :param timeout: Request timeout in seconds
    :return: Dict with error field (None if success), suggestedWindow (start/end datetimes), optional explanationURL, retry_after
    """
    url = f'{ari_endpoint}/{cert_id}'
    backoff_delay = 1
    response = None

    for attempt in range(retries + 1):
        try:
            response = requests.get(url, timeout=timeout)

            # Check for HTTP 409 alreadyReplaced error (RFC 9773 Section 7.4)
            if response.status_code == 409:
                return {'error': 'Certificate has already been marked as replaced'}

            # Handle 5xx server errors as temporary (RFC 9773 Section 4.3.3)
            if 500 <= response.status_code < 600:
                if attempt < retries:
                    time.sleep(backoff_delay)
                    backoff_delay *= 2
                    continue
                return {'error': f'ARI server error after {retries + 1} attempts: HTTP {response.status_code}'}

            if response.status_code not in (200, 201, 204):
                return {'error': f'ARI request failed: HTTP {response.status_code}'}

            data = response.json()
            break

        except (ConnectionError, TimeoutError, requests.exceptions.RequestException) as e:
            if attempt < retries:
                time.sleep(backoff_delay)
                backoff_delay *= 2
                continue

            return {'error': f'ARI request failed after {retries + 1} attempts: {e}'}
        except json.JSONDecodeError as e:
            return {'error': f'Invalid JSON response: {e}'}
        except Exception as e:
            return {'error': f'ARI request failed: {e}'}

    if 'suggestedWindow' not in data:
        return {'error': 'Invalid ARI response: missing suggestedWindow'}

    window = data['suggestedWindow']
    if 'start' not in window or 'end' not in window:
        return {'error': 'Invalid suggestedWindow: missing start or end'}

    try:
        start = datetime.fromisoformat(window['start'].replace('Z', '+00:00'))
        end = datetime.fromisoformat(window['end'].replace('Z', '+00:00'))
    except (ValueError, TypeError) as e:
        return {'error': f'Invalid date format in suggestedWindow: {e}'}

    result = {
        'error': None,
        'suggested_window': {'start': start, 'end': end},
        'retry_after': None,
        'explanation_url': data.get('explanationURL'),
    }

    # Parse Retry-After header per RFC 9773 Section 4.3
    if response and 'Retry-After' in response.headers:
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
