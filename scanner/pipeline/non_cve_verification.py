"""Exact HTTP inputs for non-CVE remediation verification.

Raw paths/queries stay in restricted inputs, never public evidence previews.
A subject digest is compared independently of run and template revision.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .finding_evidence import subject


def metadata(row: dict[str, Any]) -> dict[str, Any]:
    target = row.get('matched_at')
    result = {'template_id': row.get('template_id'), 'subject': subject(row),
              'verification_target': None}
    try:
        expected = target_subject(target)
        if expected == result['subject']:
            result['verification_target'] = target
    except (ValueError, TypeError, AttributeError):
        pass
    return result


def target_subject(url: Any) -> dict[str, Any]:
    if not isinstance(url, str) or not url or len(url) > 4096:
        raise ValueError('an exact bounded HTTP URL is required')
    if any(ord(char) < 33 for char in url):
        raise ValueError('unsafe verification URL')
    parsed = urlsplit(url)
    if (parsed.scheme.lower() not in {'http', 'https'} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment):
        raise ValueError('unsupported verification URL')
    return subject({'host': parsed.hostname, 'matched_at': url, 'protocol': 'tcp'})


def validate_target(value: Any) -> dict[str, Any]:
    """Refuse a URL whose canonical subject differs from the recorded finding."""
    from .config_schema import NUCLEI_TEMPLATE_ID_RE
    if not isinstance(value, dict) or set(value) != {'url', 'subject', 'template_id'}:
        raise ValueError('invalid exact verification target')
    if (not isinstance(value['template_id'], str)
            or NUCLEI_TEMPLATE_ID_RE.fullmatch(value['template_id']) is None):
        raise ValueError('invalid verification template')
    if target_subject(value['url']) != value['subject']:
        raise ValueError('verification target does not match the finding subject')
    return value


def exact_template(content: bytes) -> bool:
    """Admit only a single request to the exact BaseURL input.

    A match URL cannot be replayed into ``{{BaseURL}}/backup.zip``: that
    would probe ``/backup.zip/backup.zip``. More complex templates require
    actual request-level coverage evidence, not an input-list receipt.
    """
    import yaml
    try:
        document = yaml.safe_load(content)
        if (not isinstance(document, dict) or set(document) - {'id', 'info', 'http'}
                or not isinstance(document.get('http'), list) or len(document['http']) != 1):
            return False
        request = document['http'][0]
        if (not isinstance(request, dict)
                or set(request) - {'method', 'path', 'matchers', 'matchers-condition'}
                or request.get('method', 'GET') not in {'GET', 'HEAD'}
                or request.get('path') != ['{{BaseURL}}']):
            return False
        matchers = request.get('matchers')
        if not isinstance(matchers, list) or not matchers:
            return False
        for matcher in matchers:
            if (not isinstance(matcher, dict)
                    or matcher.get('type') not in {'word', 'status', 'regex', 'binary'}
                    or set(matcher) - {'type', 'part', 'words', 'status', 'regex', 'binary',
                                       'condition', 'negative', 'case-insensitive', 'name', 'encoding'}
                    or matcher.get('part', 'body') not in {'body', 'header', 'all', 'status_code'}):
                return False
        return True
    except (ValueError, TypeError, yaml.YAMLError):
        return False
